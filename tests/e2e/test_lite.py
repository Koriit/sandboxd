"""E2E tests for the M11 lite-mode container backend.

Covers the spec § "E2E tests" lite-specific assertions: feature
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
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time

import pytest

from conftest import (
    SandboxBinaries,
    cleanup_policy_file,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)
from helpers import HostResources, LiteBackendHarness


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
    """Spec § "CLI & UX → Feature-mismatch errors": ``--hardened`` ↔
    ``--lite`` is a CLI-side rejection (exit 2) with the spec-shaped
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
    assert "--hardened" in result.stderr, (
        f"stderr must mention --hardened.\nstderr: {result.stderr}"
    )
    assert "container backend" in result.stderr or "lite" in result.stderr, (
        f"stderr must reference the container backend or --lite.\n"
        f"stderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# 3.2 — `--no-cache` is rejected for `--lite`
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_no_cache_rejected_for_lite(sandbox_cli):
    """Spec § "`sandbox create --no-cache` is forbidden on container":
    ``--lite --no-cache`` exits 2 with the spec error wording. The
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
    assert "--no-cache" in result.stderr, (
        f"stderr must mention --no-cache.\nstderr: {result.stderr}"
    )
    # Spec wording: "`--no-cache` is not supported with `--lite` /
    # container backend"
    assert "not supported" in result.stderr, (
        f"stderr must say 'not supported'.\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# 3.3 — rootfs is read-only inside the lite container
# ---------------------------------------------------------------------------


@pytest.mark.timeout(300)
def test_lite_rootfs_is_readonly(lite_harness):
    """Spec § Hardening: lite containers run with ``--read-only``, so
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
    """Spec § Hardening: no privileged mode, no Docker socket mount.

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
    """Spec § Hardening: ``--cap-drop ALL`` removes CAP_SYS_ADMIN, so
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
    """Spec § "Resource defaults — container only": creating a lite
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
        # remote helper has a destination. /home/agent/workspace/ is
        # writable inside the lite image (rootfs is read-only but
        # /home/agent is the named home volume).
        exec_result = sandbox_cli(
            "exec", "lite-git-remote", "--",
            "git", "init", "--bare", "/home/agent/workspace/repo.git",
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
        remote_url = "sandbox::lite-git-remote/home/agent/workspace/repo.git"
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
            "git", "-C", "/home/agent/workspace/repo.git",
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
    """Spec § "Gateway integration": the gateway container (Envoy +
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
            "curl -s --connect-timeout 10 --max-time 15 "
            "http://denied.example.org/ 2>&1; echo EXIT:$?",
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


@pytest.mark.timeout(300)
def test_lite_workspace_uid_alignment(lite_harness, tmp_path):
    """Spec § "Workspace bind": mounting a host directory as
    ``--workspace shared:<path>`` makes it available at
    ``/home/agent/workspace/`` inside the lite container, and files
    written from inside the session land on the host with the *host*
    user's uid (not a stale container uid).
    ``ContainerNetwork.workspace_host_path`` is set to
    ``Some(<path>)`` when the request supplies ``WorkspaceMode::Shared``,
    and the container runtime renders it as ``--mount
    type=bind,src=<path>,dst=/home/agent/workspace/`` (the bind target
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

    sid = lite_harness.create(
        "--name", "lite-ws-uid",
        "--workspace", f"shared:{host_dir}",
    )
    assert sid is not None

    # 1. host -> container: write a file on the host, read it from inside.
    host_fixture = host_dir / "from-host.txt"
    host_fixture.write_text("hello from host\n")
    cat_result = lite_harness.ssh(sid, "cat", "/home/agent/workspace/from-host.txt")
    assert cat_result.returncode == 0, (
        f"cat /home/agent/workspace/from-host.txt failed inside lite session.\n"
        f"stdout: {cat_result.stdout}\nstderr: {cat_result.stderr}"
    )
    assert "hello from host" in cat_result.stdout, (
        f"workspace bind mount did not surface host fixture.\n"
        f"stdout: {cat_result.stdout!r}"
    )

    # 2. container -> host: touch a file from inside, verify host uid.
    touch_result = lite_harness.ssh(
        sid, "sh", "-c", "echo from-container > /home/agent/workspace/from-container.txt",
    )
    assert touch_result.returncode == 0, (
        f"writing /home/agent/workspace/from-container.txt failed inside lite session.\n"
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
    """Spec § "Home directory persistence (beta)": the named volume
    ``sandbox-home-<id>`` is mounted at ``/home/agent`` and survives
    ``stop`` + ``start``; ``rm`` removes the volume.

    Three steps:

    1. Create the lite session and write a marker into ``/home/agent``.
    2. Stop and restart; the marker must survive.
    3. Remove the session; ``docker volume ls`` must not list the
       ``sandbox-home-<id>`` volume.
    """
    sid = lite_harness.create("--name", "lite-home-volume")
    volume_name = f"sandbox-home-{sid}"

    # 1. Write a marker. /home/agent is the named-volume mount, so
    # writes here persist independently of the read-only rootfs.
    marker_content = "lite-home-volume-survived"
    write_result = lite_harness.ssh(
        sid, "sh", "-c",
        f"echo {marker_content} > /home/agent/marker && cat /home/agent/marker",
        timeout=60,
    )
    assert write_result.returncode == 0, (
        f"failed to write marker into /home/agent.\n"
        f"stdout: {write_result.stdout}\nstderr: {write_result.stderr}"
    )
    assert marker_content in write_result.stdout, (
        f"marker not echoed back from /home/agent/marker.\n"
        f"stdout: {write_result.stdout}"
    )

    # 2. Stop + start; the marker must survive because /home/agent
    # is on the named volume, not the container's writable layer.
    lite_harness.stop(sid)
    lite_harness.start(sid)
    # Wait briefly for the container to be exec-ready after start.
    wait_for_state(sandbox_cli, "lite-home-volume", "Running", timeout=30)

    read_result = lite_harness.ssh(
        sid, "cat", "/home/agent/marker", timeout=60,
    )
    assert read_result.returncode == 0, (
        f"failed to read /home/agent/marker after stop+start.\n"
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
    """Spec § "Orphan cleanup on daemon start" / spec § Testing line 1023:
    "kill the daemon mid-create, restart, assert orphan container and
    volume are reaped".

    We approximate "kill mid-create" with the simpler, deterministic
    variant the spec authorises: create the lite session normally,
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
    socket_path = sandbox_daemon["socket"]
    base_dir = sandbox_daemon["base_dir"]
    db_path = os.path.join(base_dir, "sessions.db")

    restarted_proc = None
    new_stdout_fh = None
    new_stderr_fh = None
    try:
        # 1. SIGKILL the daemon. Abrupt — no graceful shutdown, so the
        #    daemon has no chance to remove the container/volume on the
        #    way out. This is the regime the orphan reaper exists for.
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
        assert os.path.exists(db_path), (
            f"sessions.db not found at {db_path}; can't synthesise an orphan."
        )
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
        #    Append to the existing log files (mirrors
        #    test_networking::test_daemon_restart_recovery) so the
        #    fixture can adopt the restarted process without leaving a
        #    dangling pipe behind.
        stdout_log = sandbox_daemon["_stdout_log"]
        stderr_log = sandbox_daemon["_stderr_log"]
        new_stdout_fh = open(stdout_log, "a")
        new_stderr_fh = open(stderr_log, "a")
        restarted_proc = subprocess.Popen(
            [
                str(sandbox_binaries.sandboxd),
                "--socket", socket_path,
                "--base-dir", base_dir,
            ],
            stdout=new_stdout_fh,
            stderr=new_stderr_fh,
        )

        # Wait for the restarted daemon's socket to reappear.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if os.path.exists(socket_path):
                break
            if restarted_proc.poll() is not None:
                pytest.fail(
                    f"Restarted daemon exited early "
                    f"(code {restarted_proc.returncode}).\n"
                    f"stdout: {stdout_log.read_text()}\n"
                    f"stderr: {stderr_log.read_text()}"
                )
            time.sleep(0.2)
        else:
            restarted_proc.kill()
            pytest.fail("Restarted daemon socket did not appear within 15s")

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
        sandbox_daemon["process"] = restarted_proc
        sandbox_daemon["_stdout_fh"] = new_stdout_fh
        sandbox_daemon["_stderr_fh"] = new_stderr_fh
        restarted_proc = None  # prevent finally from killing it
        new_stdout_fh = None
        new_stderr_fh = None

    finally:
        # The lite_harness still tracks `sid` in its session list; the
        # cleanup hook will issue `sandbox rm -y <sid>` against the
        # restarted daemon, which returns "not found" (the row is
        # gone), and the harness tolerates that branch — see
        # `LiteBackendHarness.rm`.

        # Recovery path mirrors test_networking::test_daemon_restart_recovery:
        # ensure the session-scoped fixture ends the test with a live
        # daemon process. If our restart never made it that far (e.g. an
        # assertion fired between SIGKILL and the handoff), spin up a
        # fresh daemon so subsequent tests don't cascade-fail.
        if restarted_proc is not None:
            if restarted_proc.poll() is None:
                # Alive but not yet handed off — adopt it.
                sandbox_daemon["process"] = restarted_proc
                sandbox_daemon["_stdout_fh"] = new_stdout_fh
                sandbox_daemon["_stderr_fh"] = new_stderr_fh
                restarted_proc = None
                new_stdout_fh = None
                new_stderr_fh = None
            else:
                # Restarted daemon died too — fall through to recovery.
                if new_stdout_fh is not None and not new_stdout_fh.closed:
                    new_stdout_fh.close()
                if new_stderr_fh is not None and not new_stderr_fh.closed:
                    new_stderr_fh.close()
                restarted_proc = None
                new_stdout_fh = None
                new_stderr_fh = None

        if sandbox_daemon["process"].poll() is not None:
            fresh_stdout_fh = open(sandbox_daemon["_stdout_log"], "a")
            fresh_stderr_fh = open(sandbox_daemon["_stderr_log"], "a")
            fresh_proc = subprocess.Popen(
                [
                    str(sandbox_binaries.sandboxd),
                    "--socket", sandbox_daemon["socket"],
                    "--base-dir", sandbox_daemon["base_dir"],
                ],
                stdout=fresh_stdout_fh,
                stderr=fresh_stderr_fh,
            )
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if os.path.exists(sandbox_daemon["socket"]):
                    break
                if fresh_proc.poll() is not None:
                    break
                time.sleep(0.2)
            sandbox_daemon["process"] = fresh_proc
            sandbox_daemon["_stdout_fh"] = fresh_stdout_fh
            sandbox_daemon["_stderr_fh"] = fresh_stderr_fh
