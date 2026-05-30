"""E2E tests for the M11 lite-mode container backend.

Covers the design § "E2E tests" lite-specific assertions: feature
rejection, hardening posture, resource defaults, gateway parity,
git-remote-sandbox parity, and the β home-volume lifecycle. These
assertions exercise the *container* backend end-to-end through the
public CLI surface (``sandbox create --lite ...``); the matching
backend-agnostic parametrisation of the existing test files is
deferred to a follow-up.

These tests boot real Docker containers (no QEMU/Lima); each create +
stop/start cycle takes ~5-10s plus assertion overhead, so individual
tests run in ~30-90s. Run with the standard E2E timeout::

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_lite.py -v --timeout=600
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time

import pytest

from conftest import (
    CONTAINER_HOME,
    SandboxBinaries,
    cleanup_policy_file,
    parse_session_id,
    restart_test_daemon,
    wait_for_state,
    write_policy_file,
)
from helpers import HostResources, LiteBackendHarness

# Whole-file container-only: lets `-m container` select this file
# explicitly and documents the backend coverage at the file's edge
# rather than implicitly via the absence of the ``backend`` fixture.
pytestmark = pytest.mark.container

# Two-line advisory that `sandbox create --lite` always emits to stderr
# before any rejection or success output.  Tests that assert on the
# *rejection* message content must strip this notice first so the
# advisory does not mask or accidentally satisfy rejection-specific
# assertions.
_LITE_ADVISORY_LINES = frozenset([
    "lite: container-backed session — container-level isolation only (not VM-grade)",
    "      see guides/lite-mode for the trade-off details",
])


def _strip_lite_advisory(stderr: str) -> str:
    """Return ``stderr`` with the known lite advisory lines removed.

    The advisory is emitted unconditionally by ``sandbox create --lite``
    before rejection/success output; tests that inspect the rejection
    message should call this helper so their assertions target only the
    product-specific error text.
    """
    return "\n".join(
        line for line in stderr.splitlines()
        if line not in _LITE_ADVISORY_LINES
    )


# ---------------------------------------------------------------------------
# File-level skip if Docker is not accessible
# ---------------------------------------------------------------------------
#
# The session-scoped `_preflight_checks` fixture in conftest.py already
# skips the entire suite when Docker is unavailable, but we duplicate a
# narrow check here as a defense-in-depth signal: lite mode is a pure
# Docker workflow, so a Docker outage during a single-file rerun must
# fail loud rather than silently producing 9 cascading failures.

_DOCKER_AVAILABLE = shutil.which("docker") is not None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def lite_harness(sandbox_cli):
    """Per-test ``LiteBackendHarness`` with automatic teardown.

    Force-removes every session created via the harness on exit, so
    tests cannot leak Docker containers or named volumes even on
    assertion failure or timeout.
    """
    harness = LiteBackendHarness(sandbox_cli)
    yield harness
    harness.cleanup()


# ---------------------------------------------------------------------------
# Daemon /sessions/<id> JSON probe
# ---------------------------------------------------------------------------


def _get_session_json(socket_path: str, session_id: str, timeout: float = 5.0) -> dict:
    """Issue ``GET /sessions/<id>`` against the daemon's Unix socket
    and return the parsed JSON body.

    Mirrors the minimal HTTP-over-Unix-socket client pattern in
    ``conftest.py::_query_base_image_status`` (no extra dependency on
    ``httpx`` / ``aiohttp``); used by the resource-defaults assertion
    so the test can read the daemon's authoritative wire shape rather
    than the CLI describe/inspect surface (which currently shows the
    persisted ``0`` sentinel — todo #69 tracks the cosmetic fix).
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(socket_path)
        s.sendall(
            f"GET /sessions/{session_id} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n\r\n".encode("utf-8")
        )
        chunks: list[bytes] = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0] if head else b""
    assert b"200" in status_line, (
        f"GET /sessions/{session_id} did not return 200; head: {head!r}"
    )
    text = body.decode("utf-8", errors="replace")
    start = text.find("{")
    end = text.rfind("}")
    assert start != -1 and end > start, (
        f"GET /sessions/{session_id} body did not contain a JSON object: {text!r}"
    )
    return json.loads(text[start : end + 1])


# ---------------------------------------------------------------------------
# 3.1 — `--hardened` is rejected for `--lite`
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_hardened_rejected_for_lite(sandbox_cli):
    """"CLI & UX → Feature-mismatch errors": ``--hardened`` ↔
    ``--lite`` is a CLI-side rejection (exit 2) with the design-shaped
    error wording. The daemon is never contacted; the rejection lives
    in ``render_feature_mismatch`` (sandbox-cli/src/backend.rs).
    """
    result = sandbox_cli(
        "create", "--lite", "--hardened", "--name", "lite-rej-hardened",
        timeout=60,
    )
    assert result.returncode == 2, (
        f"sandbox create --lite --hardened should exit 2, got "
        f"{result.returncode}.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    rejection_stderr = _strip_lite_advisory(result.stderr)
    assert "--hardened" in rejection_stderr, (
        f"stderr must mention --hardened.\nstderr: {result.stderr}"
    )
    assert "container backend" in rejection_stderr or "lite" in rejection_stderr, (
        f"stderr must reference the container backend or --lite.\n"
        f"stderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# 3.2 — `--no-cache` is rejected for `--lite`
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_no_cache_rejected_for_lite(sandbox_cli):
    """"`sandbox create --no-cache` is forbidden on container":
    ``--lite --no-cache`` exits 2 with the design error wording. The
    rejection is the CLI-side gate in ``main.rs`` (runs before the
    daemon is contacted); the daemon-side mirror lives in
    ``SessionSpec::validate``.
    """
    result = sandbox_cli(
        "create", "--lite", "--no-cache", "--name", "lite-rej-nocache",
        timeout=60,
    )
    assert result.returncode == 2, (
        f"sandbox create --lite --no-cache should exit 2, got "
        f"{result.returncode}.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    rejection_stderr = _strip_lite_advisory(result.stderr)
    assert "--no-cache" in rejection_stderr, (
        f"stderr must mention --no-cache.\nstderr: {result.stderr}"
    )
    # the documented designwording: "`--no-cache` is not supported with `--lite` /
    # container backend"
    assert "not supported" in rejection_stderr, (
        f"stderr must say 'not supported'.\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# 3.3 — rootfs is read-only inside the lite container
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_lite_rootfs_is_readonly(lite_harness):
    """
    writes to ``/`` fail with EROFS. ``LiteBackendHarness`` captures
    the probe so this test can stay focused on the create + assert
    shape.
    """
    sid = lite_harness.create("--name", "lite-rootfs-ro")
    lite_harness.assert_rootfs_readonly(sid)


# ---------------------------------------------------------------------------
# 3.4 — Docker-in-Docker is blocked
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_lite_blocks_docker_in_docker(lite_harness):
    """

    Probe: ``ls /var/run/docker.sock`` returns non-zero (the path is
    absent inside the namespace).
    """
    sid = lite_harness.create("--name", "lite-no-dind")
    lite_harness.assert_no_dind(sid)


# ---------------------------------------------------------------------------
# 3.5 — `unshare --user` is blocked
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_lite_blocks_user_namespace(lite_harness):
    """
    new user namespaces cannot be created. Probe via ``unshare --user
    true``.
    """
    sid = lite_harness.create("--name", "lite-no-userns")
    lite_harness.assert_no_userns(sid)


# ---------------------------------------------------------------------------
# 3.6 — resource defaults match host's 80% ceiling
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_lite_resource_defaults_match_host_80pct(lite_harness, sandbox_daemon):
    """"Resource defaults — container only": creating a lite
    session without ``--cpus`` / ``--memory`` applies the daemon's
    host-80% defaults at the runtime layer.

    The assertion path: read the resolved values from the daemon's
    ``GET /sessions/<id>`` JSON (not from ``sandbox describe -v``,
    which currently surfaces the persisted ``0`` sentinel as
    ``CPUs: 0, Memory: 0 MB`` — todo #69 tracks the cosmetic fix).
    Compare against ``HostResources.from_host()``, which mirrors the
    daemon's ``compute_default_resource_limits`` formula.
    """
    sid = lite_harness.create("--name", "lite-resource-defaults")
    expected = HostResources.from_host()
    body = _get_session_json(sandbox_daemon["socket"], sid)
    config = body["config"]

    resolved_cpus = config["resolved_cpus"]
    resolved_memory_mb = config["resolved_memory_mb"]

    # Memory is integer MB on both sides; equality should hold exactly.
    assert resolved_memory_mb == expected.expected_lite_memory_mb, (
        f"resolved_memory_mb on the wire ({resolved_memory_mb}) does not "
        f"match the host-80% ceiling ({expected.expected_lite_memory_mb}); "
        f"host total = {expected.memory_mb_total} MB."
    )
    # CPUs is f64 with one decimal; allow a tiny tolerance for floating
    # point representation noise.
    assert abs(resolved_cpus - expected.expected_lite_cpus) < 0.05, (
        f"resolved_cpus on the wire ({resolved_cpus}) does not match the "
        f"host-80% ceiling ({expected.expected_lite_cpus}); host total = "
        f"{expected.cpus_total} CPUs."
    )

    # Persisted values stay at the `0` sentinel — that is the Phase
    # 4D-pre Task 4 design choice (the runtime applies the default).
    # Keep this assertion paired with the resolved-* check so a
    # future "always store the resolved value" refactor would trip
    # both fields and force a deliberate decision.
    assert config["cpus"] == 0, (
        f"persisted cpus should remain at the 0 sentinel; got {config['cpus']}"
    )
    assert config["memory_mb"] == 0, (
        f"persisted memory_mb should remain at the 0 sentinel; got "
        f"{config['memory_mb']}"
    )


# ---------------------------------------------------------------------------
# 3.7 — git-remote-sandbox parity for lite sessions
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_lite_git_remote_sandbox(
    lite_harness,
    sandbox_cli,
    sandbox_binaries: SandboxBinaries,
    sandbox_daemon,
):
    """``git-remote-sandbox`` (the symlink to the ``sandbox`` binary
    that powers ``sandbox::`` URLs) must work against a lite session
    the same way it does against a Lima VM. Mirrors
    ``test_git_remote.py::test_git_push_to_vm`` but uses
    ``--lite``.
    """
    socket_path = sandbox_daemon["socket"]
    helper_dir = tempfile.mkdtemp(prefix="sandbox-git-helper-lite-")
    local_repo = None
    try:
        symlink_path = os.path.join(helper_dir, "git-remote-sandbox")
        os.symlink(str(sandbox_binaries.sandbox), symlink_path)
        git_env = os.environ.copy()
        git_env["PATH"] = helper_dir + ":" + git_env.get("PATH", "")
        git_env["SANDBOX_SOCKET"] = socket_path

        # Create the lite session via the harness (auto-cleanup).
        sid = lite_harness.create("--name", "lite-git-remote")

        # Initialise a bare repo inside the lite container so the
        # remote helper has a destination. CONTAINER_HOME/workspace/ is
        # writable inside the lite image (rootfs is read-only but
        # CONTAINER_HOME is the named home volume).
        exec_result = sandbox_cli(
            "exec", "lite-git-remote", "--",
            "git", "init", "--bare", f"{CONTAINER_HOME}/workspace/repo.git",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"git init --bare inside lite session failed.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )

        # Build a local repo with one commit.
        local_repo = tempfile.mkdtemp(prefix="sandbox-git-push-lite-")
        subprocess.run(
            ["git", "init", local_repo],
            check=True, capture_output=True, timeout=30,
        )
        subprocess.run(
            ["git", "-C", local_repo, "config", "user.email", "test@test.com"],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["git", "-C", local_repo, "config", "user.name", "Test"],
            check=True, capture_output=True, timeout=10,
        )
        readme_path = os.path.join(local_repo, "README.md")
        with open(readme_path, "w") as f:
            f.write("# Lite Push Test\n")
        subprocess.run(
            ["git", "-C", local_repo, "add", "README.md"],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["git", "-C", local_repo, "commit", "-m", "lite host commit"],
            check=True, capture_output=True, timeout=10,
        )
        branch_result = subprocess.run(
            ["git", "-C", local_repo, "branch", "--show-current"],
            capture_output=True, text=True, timeout=10,
        )
        branch = branch_result.stdout.strip()
        assert branch, "could not determine local branch name"

        # Add the sandbox:: remote and push through the helper.
        remote_url = f"sandbox::lite-git-remote{CONTAINER_HOME}/workspace/repo.git"
        subprocess.run(
            ["git", "-C", local_repo, "remote", "add", "sandbox", remote_url],
            check=True, capture_output=True, timeout=10,
        )
        push_result = subprocess.run(
            ["git", "-C", local_repo, "push", "sandbox", branch],
            capture_output=True, text=True, timeout=180,
            env=git_env,
        )
        assert push_result.returncode == 0, (
            f"git push via sandbox:: against lite session failed "
            f"(rc={push_result.returncode}).\n"
            f"stdout: {push_result.stdout}\nstderr: {push_result.stderr}"
        )

        # Verify the commit landed inside the lite container.
        log_result = sandbox_cli(
            "exec", "lite-git-remote", "--",
            "git", "-C", f"{CONTAINER_HOME}/workspace/repo.git",
            "log", "--oneline", "-1",
            timeout=120,
        )
        assert log_result.returncode == 0, (
            f"git log inside lite session failed.\n"
            f"stdout: {log_result.stdout}\nstderr: {log_result.stderr}"
        )
        assert "lite host commit" in log_result.stdout, (
            f"expected 'lite host commit' in lite-side git log.\n"
            f"got: {log_result.stdout}"
        )
    finally:
        if local_repo is not None:
            shutil.rmtree(local_repo, ignore_errors=True)
        shutil.rmtree(helper_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 3.8 — gateway parity (mitmproxy/Envoy/CoreDNS) for lite sessions
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_lite_gateway_parity(lite_harness, sandbox_cli):
    """"Gateway integration": the gateway container (Envoy +
    mitmproxy + CoreDNS) is attached to lite sessions exactly the same
    way it is attached to Lima sessions. Apply a policy that allows
    only ``example.com`` and verify the allow path succeeds while a
    denied destination is blocked.

    The shape matches ``test_policy.py::test_level1_transport_tcp``
    plus a deny probe — kept narrow because the full M4 matrix is
    parametrised separately; this test is the lite-specific smoke gate.
    The gateway is wired into the container backend so
    ``create_session`` performs the same 8-step gateway sequence
    as ``setup_session_networking`` for lite sessions.
    """
    policy_path = None
    try:
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                },
                {
                    "host": "example.com",
                    "port": 53,
                    "protocol": "udp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        sid = lite_harness.create(
            "--name", "lite-gateway",
            "--policy", policy_path,
        )
        wait_for_state(sandbox_cli, "lite-gateway", "Running", timeout=10)

        # Warm DNS so the daemon's propagation loop materialises the
        # per-rule Envoy filter chain (prefix_ranges = resolved IPs)
        # and the sandbox_policy nftables concat-set entry. Mirrors
        # the warmup pattern used by every L1+ policy test in
        # test_policy.py — without it, the first request races the
        # 2-second poll and fails closed at the empty-cache state.
        lite_harness.ssh(sid, "nslookup", "example.com", timeout=120)
        time.sleep(5)

        # Allow path: example.com:80 over TCP should succeed.
        allow_result = lite_harness.ssh(
            sid,
            "curl", "-s", "--connect-timeout", "15", "--max-time", "30",
            "http://example.com",
            timeout=120,
        )
        assert allow_result.returncode == 0, (
            f"curl http://example.com failed at L1 transport in a lite "
            f"session.\nstdout: {allow_result.stdout}\n"
            f"stderr: {allow_result.stderr}"
        )
        assert "Example Domain" in allow_result.stdout, (
            f"response from example.com missing 'Example Domain' marker.\n"
            f"stdout: {allow_result.stdout}"
        )

        # Deny path: a domain not in the policy must fail closed at
        # CoreDNS (NXDOMAIN) or be denied at the gateway. Use a wrapper
        # that always exits 0 so we can introspect the inner exit code
        # explicitly.
        deny_result = lite_harness.ssh(
            sid, "sh", "-c",
            shlex.quote(
                "curl -s --connect-timeout 10 --max-time 15 "
                "http://denied.example.org/ 2>&1; echo EXIT:$?"
            ),
            timeout=120,
        )
        assert "EXIT:0" not in deny_result.stdout, (
            f"curl to denied.example.org should have failed under the "
            f"example.com-only policy.\nstdout: {deny_result.stdout}"
        )
    finally:
        if policy_path is not None:
            cleanup_policy_file(policy_path)


# ---------------------------------------------------------------------------
# 3.9 — workspace UID alignment
# ---------------------------------------------------------------------------


def _grant_traverse_to_sandbox(path: os.PathLike) -> None:
    """Add the execute (traverse) bit for group and others on ``path``
    and every ancestor up to ``/tmp`` (exclusive).

    pytest creates its per-test tmp directories under
    ``/tmp/pytest-of-<user>/pytest-<N>/test_<name>/`` with mode 0700,
    owner=operator.  When the daemon runs as user ``sandbox`` (uid 999) it
    must traverse these directories to reach a shared-workspace host path,
    but mode 0700 gives EACCES to any non-owner.

    In real usage an operator's home directory is 0755, so this situation
    never occurs in production.  It is purely a pytest-tmp artifact.

    We grant *traverse-only* (``g+x,o+x``, not ``g+r,o+r``) to the chain:
    ``/tmp/pytest-of-<user>/``, each ``pytest-<N>/`` dir, each
    ``test_<name>/`` dir, and the workspace directory itself.
    We do NOT chmod the workspace *contents* — the daemon only needs to
    reach the specific bind-mount path, not list it.

    Both ``g+x`` and ``o+x`` are required because pytest's tmp dirs are
    group-owned by ``sandbox`` (the operator's supplementary group) and
    Linux kernel access checks apply group bits before other bits for
    group members — so ``o+x`` alone does not help a process whose
    effective group matches the directory's group.

    Stops at ``/tmp`` (world-writable already) and ``/`` to avoid
    inadvertently widening permissions outside the pytest tree.
    """
    import stat as _stat

    p = os.path.abspath(path)
    stop_at = {"/tmp", "/"}
    visited: list[str] = []

    # Walk upward collecting dirs that need g+x,o+x, stop at /tmp or root.
    current = p
    while True:
        visited.append(current)
        if current in stop_at:
            break
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    _traverse_bits = _stat.S_IXGRP | _stat.S_IXOTH
    for d in visited:
        try:
            st = os.stat(d)
            if not (st.st_mode & _traverse_bits == _traverse_bits):
                os.chmod(d, st.st_mode | _traverse_bits)
        except OSError:
            pass  # best-effort; failure will surface as EACCES on create


@pytest.mark.timeout(300)
def test_lite_workspace_uid_alignment(lite_harness, tmp_path):
    """"Workspace bind": mounting a host directory as
    ``--workspace shared:<path>`` makes it available at
    ``CONTAINER_HOME/workspace/`` inside the lite container, and files
    written from inside the session land on the host with the *host*
    user's uid (not a stale container uid).
    ``ContainerNetwork.workspace_host_path`` is set to
    ``Some(<path>)`` when the request supplies ``WorkspaceMode::Shared``,
    and the container runtime renders it as ``--mount
    type=bind,src=<path>,dst=CONTAINER_HOME/workspace/`` (the bind target
    matches Lima's workspace mount; the legacy target ``/workspace``
    has been retired).

    UID alignment is enforced by ``map_container_uid_gid`` (the
    container runs as the daemon's host uid:gid), so any file
    written inside the bind mount must show up on the host with that
    same uid. We probe both directions:

    1. host -> container: drop a fixture file and ``cat`` it from
       inside the session, confirming the bind mount is live and
       readable.
    2. container -> host: ``touch`` a file inside the session, stat
       it on the host, and assert ``st_uid == os.getuid()``.
    """
    host_dir = tmp_path / "lite-workspace"
    host_dir.mkdir()
    host_uid = os.getuid()

    # The daemon (user `sandbox`, uid 999) must traverse the pytest tmp
    # ancestor directories to reach host_dir.  Pytest creates those dirs
    # mode 0700, which blocks any non-owner.  Grant o+x up the chain so
    # the daemon can reach the bind-mount path.  See _grant_traverse_to_sandbox.
    _grant_traverse_to_sandbox(host_dir)

    sid = lite_harness.create(
        "--name", "lite-ws-uid",
        "--workspace", f"shared:{host_dir}:{CONTAINER_HOME}/workspace",
    )
    assert sid is not None

    # 1. host -> container: write a file on the host, read it from inside.
    host_fixture = host_dir / "from-host.txt"
    host_fixture.write_text("hello from host\n")
    cat_result = lite_harness.ssh(sid, "cat", f"{CONTAINER_HOME}/workspace/from-host.txt")
    assert cat_result.returncode == 0, (
        f"cat {CONTAINER_HOME}/workspace/from-host.txt failed inside lite session.\n"
        f"stdout: {cat_result.stdout}\nstderr: {cat_result.stderr}"
    )
    assert "hello from host" in cat_result.stdout, (
        f"workspace bind mount did not surface host fixture.\n"
        f"stdout: {cat_result.stdout!r}"
    )

    # 2. container -> host: touch a file from inside, verify host uid.
    touch_result = lite_harness.ssh(
        sid, "sh", "-c",
        shlex.quote(f"echo from-container > {CONTAINER_HOME}/workspace/from-container.txt"),
    )
    assert touch_result.returncode == 0, (
        f"writing {CONTAINER_HOME}/workspace/from-container.txt failed inside lite session.\n"
        f"stdout: {touch_result.stdout}\nstderr: {touch_result.stderr}"
    )

    written = host_dir / "from-container.txt"
    assert written.exists(), (
        f"file written inside lite session did not appear on host at {written}"
    )
    st = written.stat()
    assert st.st_uid == host_uid, (
        f"file written inside the lite session must be owned by the host uid "
        f"({host_uid}); got st_uid={st.st_uid}. UID alignment broke; check "
        f"map_container_uid_gid + the container's --user flag."
    )


# ---------------------------------------------------------------------------
# 3.10 — β home-volume lifecycle (stop/start preserves, rm clears)
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_lite_home_volume_lifecycle_beta(lite_harness, sandbox_cli):
    """"Home directory persistence (beta)": the named volume
    ``sandbox-home-<id>`` is mounted at ``CONTAINER_HOME`` and survives
    ``stop`` + ``start``; ``rm`` removes the volume.

    Three steps:

    1. Create the lite session and write a marker into ``CONTAINER_HOME``.
    2. Stop and restart; the marker must survive.
    3. Remove the session; ``docker volume ls`` must not list the
       ``sandbox-home-<id>`` volume.
    """
    sid = lite_harness.create("--name", "lite-home-volume")
    volume_name = f"sandbox-home-{sid}"

    # 1. Write a marker. CONTAINER_HOME is the named-volume mount, so
    # writes here persist independently of the read-only rootfs.
    marker_content = "lite-home-volume-survived"
    write_result = lite_harness.ssh(
        sid, "sh", "-c",
        shlex.quote(f"echo {marker_content} > {CONTAINER_HOME}/marker && cat {CONTAINER_HOME}/marker"),
        timeout=60,
    )
    assert write_result.returncode == 0, (
        f"failed to write marker into {CONTAINER_HOME}.\n"
        f"stdout: {write_result.stdout}\nstderr: {write_result.stderr}"
    )
    assert marker_content in write_result.stdout, (
        f"marker not echoed back from {CONTAINER_HOME}/marker.\n"
        f"stdout: {write_result.stdout}"
    )

    # 2. Stop + start; the marker must survive because CONTAINER_HOME
    # is on the named volume, not the container's writable layer.
    lite_harness.stop(sid)
    lite_harness.start(sid)
    # Wait briefly for the container to be exec-ready after start.
    wait_for_state(sandbox_cli, "lite-home-volume", "Running", timeout=30)

    read_result = lite_harness.ssh(
        sid, "cat", f"{CONTAINER_HOME}/marker", timeout=60,
    )
    assert read_result.returncode == 0, (
        f"failed to read {CONTAINER_HOME}/marker after stop+start.\n"
        f"stdout: {read_result.stdout}\nstderr: {read_result.stderr}"
    )
    assert marker_content in read_result.stdout, (
        f"marker did not survive stop+start.\n"
        f"got: {read_result.stdout}"
    )

    # 3. Remove the session; the named volume must be gone.
    lite_harness.rm(sid)
    volumes = subprocess.run(
        ["docker", "volume", "ls", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=30,
    )
    assert volumes.returncode == 0, (
        f"docker volume ls failed.\nstderr: {volumes.stderr}"
    )
    listed = volumes.stdout.splitlines()
    assert volume_name not in listed, (
        f"named home volume {volume_name!r} still exists after rm; "
        f"docker volume ls listed: {listed}"
    )


# ---------------------------------------------------------------------------
# 3.11 — orphan reaper cleans stranded container + home volume on daemon
# restart (todo #71 — pytest equivalent of the Phase 5B Rust integration test
# `integration_orphan_reaper_removes_orphans_and_preserves_live_resources`)
# ---------------------------------------------------------------------------


@pytest.mark.timeout(600)
def test_lite_orphan_cleanup_on_daemon_restart(
    lite_harness, sandbox_binaries, sandbox_daemon
):
    """"Orphan cleanup on daemon start" / 
    "kill the daemon mid-create, restart, assert orphan container and
    volume are reaped".

    We approximate "kill mid-create" with the simpler, deterministic
    variant the design authorises: create the lite session normally,
    SIGKILL the daemon (so it has no chance to clean anything up),
    then mutate ``sessions.db`` to delete the session row — that
    leaves the ``sandbox-<id>`` container and ``sandbox-home-<id>``
    volume on the host with no owning row, which is exactly the
    invariant the boot-time reaper exists to fix. Restart the daemon
    and assert both Docker artifacts are gone.

    Restart mechanics mirror
    ``test_networking::test_daemon_restart_recovery``: SIGKILL the
    process, append to the existing log files so the session-scoped
    fixture can adopt the restarted daemon, and hand the new ``Popen``
    back via ``sandbox_daemon["process"]`` so subsequent tests (and
    fixture teardown) operate on the live process. Without that
    handoff every test after this one cascade-fails on a dead socket.
    """
    sid = lite_harness.create("--name", "lite-orphan-reap")
    container_name = f"sandbox-{sid}"
    volume_name = f"sandbox-home-{sid}"

    # Sanity precondition: both Docker artifacts exist before we kick
    # the legs out from under the daemon.
    pre_containers = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=30,
    )
    assert pre_containers.returncode == 0, (
        f"docker ps -a failed.\nstderr: {pre_containers.stderr}"
    )
    assert container_name in pre_containers.stdout.splitlines(), (
        f"precondition: container {container_name!r} should exist before "
        f"the daemon is killed; docker ps -a listed:\n{pre_containers.stdout}"
    )
    pre_volumes = subprocess.run(
        ["docker", "volume", "ls", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=30,
    )
    assert pre_volumes.returncode == 0, (
        f"docker volume ls failed.\nstderr: {pre_volumes.stderr}"
    )
    assert volume_name in pre_volumes.stdout.splitlines(), (
        f"precondition: volume {volume_name!r} should exist before the "
        f"daemon is killed; docker volume ls listed:\n{pre_volumes.stdout}"
    )

    daemon_proc = sandbox_daemon["process"]
    base_dir = sandbox_daemon["base_dir"]
    db_path = os.path.join(base_dir, "sessions.db")

    restarted_handle = None
    handed_off = False
    try:
        # 1. SIGKILL the daemon. Abrupt — no graceful shutdown, so the
        #    daemon has no chance to remove the container/volume on the
        #    way out. This is the regime the orphan reaper exists for.
        #    ``send_signal``/``wait``/``poll`` work uniformly across
        #    Popen and _SystemdDaemonHandle.
        daemon_proc.send_signal(signal.SIGKILL)
        daemon_proc.wait(timeout=10)
        assert daemon_proc.poll() is not None, (
            "Daemon did not die after SIGKILL"
        )
        # Give the kernel a beat to release the abstract socket file so
        # the restarted daemon can rebind on the same path without
        # racing the EADDRINUSE window.
        time.sleep(1)

        # 2. Mutate `sessions.db` directly: drop the session row, which
        #    leaves the docker container + sandbox-home-<id> volume
        #    orphaned (no owning row). `foreign_keys = ON` cascades the
        #    delete through `session_policies` / `policy_rules` /
        #    `policy_rule_http_filters` (V003+V004 schema).
        #
        #    Under the production-shaped harnesses (sandbox-systemd /
        #    sandbox-sudo) the DB is owned by user `sandbox` (uid 999)
        #    inside a mode-0700 directory — the test-runner process
        #    (operator uid) gets EACCES on a direct sqlite3.connect().
        #    Route the mutation through `sudo -n -u sandbox sqlite3` so
        #    the correct user performs the write.  Under the legacy
        #    test-user harness the daemon and operator share a uid, so
        #    a direct connection is fine.
        from conftest import SANDBOX_HARNESS  # local import to avoid circularity
        assert os.path.exists(db_path), (
            f"sessions.db not found at {db_path}; can't synthesise an orphan."
        )
        if SANDBOX_HARNESS in ("sandbox-systemd", "sandbox-sudo"):
            # Pass the SQL via stdin so the session id doesn't need shell quoting.
            sql = (
                "PRAGMA foreign_keys = ON; "
                f"DELETE FROM sessions WHERE id = '{sid}';"
            )
            db_result = subprocess.run(
                ["sudo", "-n", "-u", "sandbox", "sqlite3", db_path],
                input=sql,
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert db_result.returncode == 0, (
                f"sudo sqlite3 DELETE failed (rc={db_result.returncode}).\n"
                f"stdout: {db_result.stdout}\nstderr: {db_result.stderr}"
            )
            # Verify the row is gone by querying count.
            count_result = subprocess.run(
                ["sudo", "-n", "-u", "sandbox", "sqlite3", db_path,
                 f"SELECT COUNT(*) FROM sessions WHERE id = '{sid}';"],
                capture_output=True, text=True, timeout=15,
            )
            remaining = count_result.stdout.strip()
            assert remaining == "0", (
                f"expected session row for {sid} to be deleted; "
                f"SELECT COUNT(*) returned {remaining!r}."
            )
        else:
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("PRAGMA foreign_keys = ON")
                cur = conn.execute(
                    "DELETE FROM sessions WHERE id = ?", (sid,)
                )
                assert cur.rowcount == 1, (
                    f"expected to delete exactly 1 session row for {sid}; "
                    f"DELETE matched {cur.rowcount} rows."
                )
                conn.commit()
            finally:
                conn.close()

        # 3. Restart the daemon with the same socket and base-dir.
        #    Harness-aware: ``systemctl start`` under sandbox-systemd,
        #    ``Popen`` swap under test-user / sandbox-sudo.
        restarted_handle = restart_test_daemon(sandbox_daemon, sandbox_binaries)

        # 4. Allow the boot-time orphan reaper to run. The reaper is
        #    invoked once during startup before `serve` starts handling
        #    requests, but `docker rm -f` against the still-running
        #    container takes a moment; poll instead of a fixed sleep so
        #    the test fails loudly with a clear "still present" message
        #    rather than racing flakily.
        post_containers_listed: list[str] = []
        post_volumes_listed: list[str] = []
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ps = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=30,
            )
            vs = subprocess.run(
                ["docker", "volume", "ls", "--format", "{{.Name}}"],
                capture_output=True, text=True, timeout=30,
            )
            post_containers_listed = ps.stdout.splitlines()
            post_volumes_listed = vs.stdout.splitlines()
            if (
                container_name not in post_containers_listed
                and volume_name not in post_volumes_listed
            ):
                break
            time.sleep(1)

        # 5. Assertions: the orphan container AND the orphan home
        #    volume must both be gone.
        assert container_name not in post_containers_listed, (
            f"orphan container {container_name!r} should have been reaped "
            f"by the boot-time orphan reaper; docker ps -a still lists:\n"
            f"{post_containers_listed}"
        )
        assert volume_name not in post_volumes_listed, (
            f"orphan home volume {volume_name!r} should have been reaped "
            f"by the boot-time orphan reaper; docker volume ls still "
            f"lists:\n{post_volumes_listed}"
        )

        # 6. Hand the restarted daemon back to the session-scoped
        #    fixture so subsequent tests (and fixture teardown) run
        #    against the live process. Without this handoff the rest
        #    of the suite cascade-fails on a dead socket.
        sandbox_daemon["process"] = restarted_handle
        if hasattr(restarted_handle, "_sandbox_stdout_fh"):
            sandbox_daemon["_stdout_fh"] = restarted_handle._sandbox_stdout_fh
            sandbox_daemon["_stderr_fh"] = restarted_handle._sandbox_stderr_fh
        handed_off = True

    finally:
        # The lite_harness still tracks `sid` in its session list; the
        # cleanup hook will issue `sandbox rm -y <sid>` against the
        # restarted daemon, which returns "not found" (the row is
        # gone), and the harness tolerates that branch — see
        # `LiteBackendHarness.rm`.

        # Recovery path: the session-scoped sandbox_daemon fixture MUST
        # end the test with a live daemon process. If our restart never
        # made it that far (e.g. an assertion fired between SIGKILL and
        # the handoff), spin up a fresh daemon so subsequent tests don't
        # cascade-fail.
        if not handed_off and restarted_handle is not None:
            if restarted_handle.poll() is None:
                sandbox_daemon["process"] = restarted_handle
                if hasattr(restarted_handle, "_sandbox_stdout_fh"):
                    sandbox_daemon["_stdout_fh"] = (
                        restarted_handle._sandbox_stdout_fh
                    )
                    sandbox_daemon["_stderr_fh"] = (
                        restarted_handle._sandbox_stderr_fh
                    )
                handed_off = True

        if sandbox_daemon["process"].poll() is not None:
            fresh_handle = restart_test_daemon(sandbox_daemon, sandbox_binaries)
            sandbox_daemon["process"] = fresh_handle
            if hasattr(fresh_handle, "_sandbox_stdout_fh"):
                sandbox_daemon["_stdout_fh"] = fresh_handle._sandbox_stdout_fh
                sandbox_daemon["_stderr_fh"] = fresh_handle._sandbox_stderr_fh
