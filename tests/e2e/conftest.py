"""Shared fixtures and helpers for sandbox E2E tests.

pytest-xdist parallelization is NOT supported
---------------------------------------------

This suite must run serially.  Do not add ``-n N`` to the pytest invocation
and do not reintroduce cross-worker locking.  Three independent reasons:

* **Per-worker daemons duplicate cost.**  Each xdist worker is a separate
  Python process, so session-scoped fixtures spawn one ``sandboxd`` daemon
  per worker.  Fine in isolation, but compounds the next two problems.
* **Shared Lima state races.**  All daemons share the user-global
  ``~/.lima/`` directory.  Session cleanup (stale ``sandbox-*`` VM
  removal) and golden base-image rebuilds from different workers race
  on the same on-disk state and corrupt Lima VMs mid-boot.
* **Host resource ceiling.**  Each session VM consumes 2 CPU / 2 GB; the
  base image build peaks at 4 CPU / 4 GB.  On an 8 CPU / 8 GB host there
  is no headroom for two concurrent session VMs plus daemon overhead.

Earlier revisions used ``filelock`` + ``fcntl.flock`` rwlocks to paper over
the first two points, but the host-resource ceiling is a hard physical
limit.  We removed the locking scaffolding rather than ship a knob that
only works on unobtainable hardware.
"""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CARGO_WORKSPACE = PROJECT_ROOT / "sandboxd"
SANDBOXD_BIN = CARGO_WORKSPACE / "target" / "debug" / "sandboxd"
SANDBOX_BIN = CARGO_WORKSPACE / "target" / "debug" / "sandbox"

# Maximum time to wait for the daemon socket to appear (seconds).
DAEMON_STARTUP_TIMEOUT = 10

# Paths to check for qemu-bridge-helper.
QEMU_BRIDGE_HELPER_PATHS = [
    Path("/usr/lib/qemu/qemu-bridge-helper"),
    Path("/usr/libexec/qemu-bridge-helper"),
]

BRIDGE_CONF_PATH = Path("/etc/qemu/bridge.conf")


# ---------------------------------------------------------------------------
# Shared test helpers
# ---------------------------------------------------------------------------

# Regex to extract the session ID from `sandbox create` output.
# The CLI prints lines like:  ID:       <12-hex-id>
_ID_RE = re.compile(r"^ID:\s+([0-9a-f]{12})$", re.MULTILINE)

# Default VM resource args -- kept small so tests work on hosts with limited
# memory (e.g. 4 GB total). Used only for the Lima backend; the lite container
# backend ignores --cpus/--memory/--disk (host-80% defaults).
_VM_RESOURCE_ARGS = ("--cpus", "2", "--memory", "2048", "--disk", "10")


def make_create_args(backend: str, name: str, *extra: str) -> tuple[str, ...]:
    """Build the argv for ``sandbox create`` parametrised on backend.

    For ``backend == "lima"`` (the historical default), prepends
    ``_VM_RESOURCE_ARGS`` and uses no flag.
    For ``backend == "container"``, passes ``--lite`` and skips the
    Lima-specific resource args (the lite backend uses host-80%
    defaults — see spec § "Resource defaults", line ~620).

    Tests should call this from inside a parametrized test that takes
    the ``backend`` fixture::

        result = sandbox_cli(
            "create", *make_create_args(backend, "my-name"),
            "--policy", policy_path,
            timeout=600,
        )

    Any ``extra`` args are appended after the name (so any
    backend-agnostic flags like ``--name`` and ``--policy`` keep their
    natural order).
    """
    if backend == "container":
        return ("--lite", "--name", name, *extra)
    return ("--name", name, *_VM_RESOURCE_ARGS, *extra)


def parse_session_id(create_output: str) -> str:
    """Extract the 12-character hex session ID from `sandbox create` stdout."""
    m = _ID_RE.search(create_output)
    if not m:
        raise ValueError(
            f"Could not parse session ID from create output:\n{create_output}"
        )
    return m.group(1)


def lima_vm_name(session_id: str) -> str:
    """Return the Lima VM name for a given session ID."""
    return f"sandbox-{session_id}"


def gateway_container_name(session_id: str) -> str:
    """Return the Docker gateway container name for a given session ID."""
    return f"sandbox-gw-{session_id}"


def wait_for_state(
    sandbox_cli,
    name: str,
    expected_state: str,
    timeout: int = 30,
    interval: float = 2.0,
) -> str:
    """Poll `sandbox ps` until the named session reaches the expected state.

    Returns the full ps output on success.  Raises AssertionError on timeout.
    """
    deadline = time.monotonic() + timeout
    last_output = ""
    while time.monotonic() < deadline:
        result = sandbox_cli("ps")
        last_output = result.stdout
        # The table has columns: ID, NAME, STATE, CREATED
        # We look for a line containing the session name and the expected state.
        for line in last_output.splitlines():
            if name in line and expected_state in line:
                return last_output
        time.sleep(interval)

    raise AssertionError(
        f"Session {name!r} did not reach state {expected_state!r} "
        f"within {timeout}s.\nLast ps output:\n{last_output}"
    )


def capture_lima_logs(session_id: str) -> str:
    """Best-effort capture of Lima VM logs for debugging failures."""
    vm = lima_vm_name(session_id)
    logs = []

    # ha.stderr.log is the main Lima log
    ha_log = os.path.expanduser(f"~/.lima/{vm}/ha.stderr.log")
    try:
        with open(ha_log) as f:
            content = f.read()
            if content:
                logs.append(f"--- {ha_log} (last 50 lines) ---")
                logs.extend(content.splitlines()[-50:])
    except FileNotFoundError:
        logs.append(f"(no ha.stderr.log found at {ha_log})")

    return "\n".join(logs)


def write_policy_file(policy: dict) -> str:
    """Write a policy dict to a temporary JSON file and return its path.

    The caller is responsible for cleanup (or rely on OS temp cleanup).
    The file is NOT auto-deleted so it remains available for the sandbox
    CLI to read during the test.
    """
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="sandbox-policy-", delete=False,
    )
    json.dump(policy, f)
    f.close()
    return f.name


def cleanup_policy_file(path: str) -> None:
    """Best-effort removal of a temporary policy file."""
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Pre-flight prerequisite checks
# ---------------------------------------------------------------------------

def _find_qemu_bridge_helper() -> Path | None:
    """Return the first existing qemu-bridge-helper path, or None."""
    for p in QEMU_BRIDGE_HELPER_PATHS:
        if p.exists():
            return p
    return None


@pytest.fixture(scope="session", autouse=True)
def _preflight_checks():
    """Verify that all host prerequisites are met before running any test.

    Each check produces a clear, actionable skip message so the developer
    knows exactly what to install or configure.
    """
    # 1. Docker accessible
    try:
        subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=30, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip(
            "Docker not accessible. Install Docker and ensure the current "
            "user is in the docker group (then re-login)."
        )

    # 2. KVM available
    kvm = Path("/dev/kvm")
    if not kvm.exists():
        pytest.skip(
            "/dev/kvm not found. Enable KVM in your kernel / BIOS, or "
            "load the kvm module: sudo modprobe kvm_intel  (or kvm_amd)."
        )
    if not os.access(kvm, os.R_OK):
        pytest.skip(
            "/dev/kvm exists but is not readable by the current user. "
            "Add your user to the kvm group: sudo usermod -aG kvm $USER"
        )

    # 3. Lima installed
    try:
        subprocess.run(
            ["limactl", "--version"],
            capture_output=True, timeout=15, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip(
            "Lima not installed. Install limactl: "
            "https://lima-vm.io/docs/installation/"
        )

    # 4. Gateway image exists
    try:
        subprocess.run(
            ["docker", "image", "inspect", "sandbox-gateway"],
            capture_output=True, timeout=30, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip(
            "Docker image 'sandbox-gateway' not found. Build it with: "
            "make gateway-image"
        )

    # 5. qemu-bridge-helper installed
    helper = _find_qemu_bridge_helper()
    if helper is None:
        searched = ", ".join(str(p) for p in QEMU_BRIDGE_HELPER_PATHS)
        pytest.skip(
            f"qemu-bridge-helper not found (checked: {searched}). "
            "Install the qemu-system-x86 (or qemu-utils) package."
        )

    # 6. qemu-bridge-helper has setuid bit
    helper_stat = helper.stat()
    if not (helper_stat.st_mode & stat.S_ISUID):
        pytest.skip(
            f"qemu-bridge-helper at {helper} is missing the setuid bit. "
            f"Run: sudo chmod u+s {helper}"
        )

    # 7. bridge.conf exists
    if not BRIDGE_CONF_PATH.exists():
        pytest.skip(
            f"{BRIDGE_CONF_PATH} not found. Create it with: "
            f"sudo mkdir -p {BRIDGE_CONF_PATH.parent} && "
            f'echo "allow all" | sudo tee {BRIDGE_CONF_PATH}'
        )

    # 8. Clean up stale sandbox resources from previous runs to prevent
    #    Docker subnet pool overlap errors.
    try:
        stale_containers = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=sandbox-",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=15,
        )
        for name in stale_containers.stdout.strip().splitlines():
            if name:
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    capture_output=True, timeout=30,
                )
    except Exception:
        pass

    try:
        stale_networks = subprocess.run(
            ["docker", "network", "ls", "--filter", "name=sandbox-",
             "--format", "{{.Name}}"],
            capture_output=True, text=True, timeout=15,
        )
        for name in stale_networks.stdout.strip().splitlines():
            if name:
                subprocess.run(
                    ["docker", "network", "rm", name],
                    capture_output=True, timeout=30,
                )
    except Exception:
        pass

    try:
        lima_vms = subprocess.run(
            ["limactl", "list", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        for line in (lima_vms.stdout or "").strip().splitlines():
            try:
                entry = json.loads(line)
                vm_name = entry.get("name", "")
                if vm_name.startswith("sandbox-"):
                    subprocess.run(
                        ["limactl", "delete", "--force", vm_name],
                        capture_output=True, timeout=60,
                    )
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    # Also remove orphan ~/.lima/sandbox-* directories that are not tracked
    # by limactl (e.g. from hard crashes or incomplete teardowns).  These
    # cause "open .../lima.yaml: no such file or directory" on subsequent
    # runs when limactl tries to reuse the stale instance directory.
    try:
        lima_dir = Path.home() / ".lima"
        if lima_dir.is_dir():
            for entry in lima_dir.iterdir():
                if entry.is_dir() and entry.name.startswith("sandbox-"):
                    import shutil
                    shutil.rmtree(entry, ignore_errors=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SandboxBinaries:
    """Paths to the compiled sandbox binaries."""
    sandboxd: Path
    sandbox: Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sandbox_binaries() -> SandboxBinaries:
    """Build the Rust workspace and return paths to sandboxd and sandbox binaries.

    Scoped to the test session so we only build once.
    """
    env = os.environ.copy()
    # Ensure cargo is available
    cargo_env = Path.home() / ".cargo" / "env"
    if cargo_env.exists():
        # Source the cargo env to get the PATH
        result = subprocess.run(
            ["bash", "-c", f"source {cargo_env} && echo $PATH"],
            capture_output=True, text=True, check=True,
        )
        env["PATH"] = result.stdout.strip()

    subprocess.run(
        ["cargo", "build", "--workspace"],
        cwd=str(CARGO_WORKSPACE),
        env=env,
        check=True,
        timeout=300,
        capture_output=True,
    )

    assert SANDBOXD_BIN.exists(), f"sandboxd binary not found at {SANDBOXD_BIN}"
    assert SANDBOX_BIN.exists(), f"sandbox binary not found at {SANDBOX_BIN}"

    return SandboxBinaries(sandboxd=SANDBOXD_BIN, sandbox=SANDBOX_BIN)


@pytest.fixture(scope="session")
def sandbox_daemon(sandbox_binaries: SandboxBinaries, tmp_path_factory: pytest.TempPathFactory):
    """Start a sandboxd instance with a temporary socket and base-dir.

    Session-scoped: all tests share the same daemon process.

    Yields a dict with:
      - socket: path to the Unix socket
      - base_dir: path to the temporary base directory
      - process: the Popen object for the daemon

    Shuts down the daemon (SIGTERM) and cleans up on teardown.  Also
    force-deletes any Lima VMs / Docker containers that leaked during the
    session as a safety net (individual tests clean up via try/finally).
    """
    tmp_path = tmp_path_factory.mktemp("sandboxd")
    socket_path = tmp_path / "sandboxd.sock"
    base_dir = tmp_path / "state"
    base_dir.mkdir(parents=True, exist_ok=True)

    # Redirect daemon output to files instead of PIPE to avoid pipe-buffer
    # deadlock.  With PIPE, nobody reads the daemon's stderr during the test
    # session; after enough log output the 64 KB buffer fills and the daemon
    # blocks, deadlocking the entire test suite.
    stdout_log = tmp_path / "sandboxd.stdout.log"
    stderr_log = tmp_path / "sandboxd.stderr.log"
    stdout_fh = open(stdout_log, "w")
    stderr_fh = open(stderr_log, "w")

    proc = subprocess.Popen(
        [
            str(sandbox_binaries.sandboxd),
            "--socket", str(socket_path),
            "--base-dir", str(base_dir),
        ],
        stdout=stdout_fh,
        stderr=stderr_fh,
    )

    # Wait for the socket to appear.
    deadline = time.monotonic() + DAEMON_STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if socket_path.exists():
            break
        # Check if the daemon crashed.
        if proc.poll() is not None:
            stdout_fh.close()
            stderr_fh.close()
            pytest.fail(
                f"sandboxd exited early (code {proc.returncode}).\n"
                f"stdout: {stdout_log.read_text()}\n"
                f"stderr: {stderr_log.read_text()}"
            )
        time.sleep(0.1)
    else:
        proc.kill()
        stdout_fh.close()
        stderr_fh.close()
        pytest.fail(f"sandboxd socket did not appear within {DAEMON_STARTUP_TIMEOUT}s")

    info = {
        "socket": str(socket_path),
        "base_dir": str(base_dir),
        "process": proc,
        "_stdout_fh": stdout_fh,
        "_stderr_fh": stderr_fh,
        "_stdout_log": stdout_log,
        "_stderr_log": stderr_log,
    }

    yield info

    # --- Teardown ---

    # Close daemon log file handles.  Use the current handles from info
    # because test_daemon_restart_recovery may have swapped them out.
    info["_stdout_fh"].close()
    info["_stderr_fh"].close()
    # Also close the originals if they weren't the current ones.
    if stdout_fh is not info["_stdout_fh"] and not stdout_fh.closed:
        stdout_fh.close()
    if stderr_fh is not info["_stderr_fh"] and not stderr_fh.closed:
        stderr_fh.close()

    # Collect any Lima VM names from the daemon's session db so we can clean
    # them up even if the test forgot to `rm`.
    vm_names_to_clean: list[str] = []
    try:
        lima_output = subprocess.run(
            ["limactl", "list", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if lima_output.stdout.strip():
            for line in lima_output.stdout.strip().splitlines():
                try:
                    entry = json.loads(line)
                    name = entry.get("name", "")
                    if name.startswith("sandbox-"):
                        vm_names_to_clean.append(name)
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    # Send SIGTERM and wait for graceful shutdown.
    # Use info["process"] (not the local `proc`) because a test like
    # test_daemon_restart_recovery may have replaced it with a new Popen.
    current_proc = info["process"]
    if current_proc.poll() is None:
        current_proc.terminate()
        try:
            current_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            current_proc.kill()
            current_proc.wait(timeout=5)

    # Force-delete any leftover VMs.
    for vm_name in vm_names_to_clean:
        try:
            subprocess.run(
                ["limactl", "delete", "--force", vm_name],
                capture_output=True, timeout=60,
            )
        except Exception:
            pass

    # Force-remove any leftover Docker containers and networks so they don't
    # block subsequent tests with subnet-pool overlap errors.
    try:
        containers = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=sandbox-",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=15,
        )
        for name in containers.stdout.strip().splitlines():
            if name:
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    capture_output=True, timeout=30,
                )
    except Exception:
        pass

    try:
        networks = subprocess.run(
            ["docker", "network", "ls", "--filter", "name=sandbox-",
             "--format", "{{.Name}}"],
            capture_output=True, text=True, timeout=15,
        )
        for name in networks.stdout.strip().splitlines():
            if name:
                subprocess.run(
                    ["docker", "network", "rm", name],
                    capture_output=True, timeout=30,
                )
    except Exception:
        pass


def _query_base_image_status(socket_path: str, timeout: float = 5.0) -> str | None:
    """Call the daemon's ``GET /base-image-status`` endpoint.

    Returns the status string (``"fresh"``, ``"stale"``, or ``"missing"``),
    or ``None`` if the endpoint can't be reached (e.g. socket not ready).

    Minimal HTTP-over-Unix-socket client so we don't add a dependency.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(socket_path)
            s.sendall(
                b"GET /base-image-status HTTP/1.1\r\n"
                b"Host: localhost\r\n"
                b"Connection: close\r\n\r\n"
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
        if b"200" not in status_line:
            return None
        text = body.decode("utf-8", errors="replace")
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        obj = json.loads(text[start : end + 1])
        val = obj.get("status")
        return val if isinstance(val, str) else None
    except (OSError, json.JSONDecodeError):
        return None


@pytest.fixture(scope="session")
def _ensure_base_image(sandbox_binaries: SandboxBinaries, sandbox_daemon):
    """Build the golden base image once per test session.

    This runs `sandbox rebuild-image` so that tests using clone-based
    creation (without --no-cache) have a base image available.  With the
    HTTPS apt sources and fast timeout config, this typically completes
    in ~90 seconds.

    If the daemon reports the image is already ``fresh`` (e.g. a previous
    test run left a valid base VM on disk), the rebuild is skipped.
    """
    socket_path = sandbox_daemon["socket"]

    status = _query_base_image_status(socket_path)
    if status == "fresh":
        return

    # Image is missing/stale (or we couldn't query -- rebuild to be
    # safe; rebuild is idempotent).
    result = subprocess.run(
        [str(sandbox_binaries.sandbox), "--socket", socket_path, "rebuild-image"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Failed to build base image (exit {result.returncode}).\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )


@pytest.fixture
def sandbox_cli(sandbox_binaries: SandboxBinaries, sandbox_daemon, _ensure_base_image):
    """Return a helper that invokes the sandbox CLI with the correct --socket.

    The helper returns a subprocess.CompletedProcess.  By default it does NOT
    raise on non-zero exit (check=False) so tests can inspect the result.
    """
    socket_path = sandbox_daemon["socket"]

    def run(
        *args: str,
        check: bool = False,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(sandbox_binaries.sandbox), "--socket", socket_path, *args],
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    return run


# ---------------------------------------------------------------------------
# Backend parametrization (M11 § "E2E tests" → "Parametrization", spec lines
# 990-1005)
# ---------------------------------------------------------------------------
#
# Tests that exercise behavior contracts agnostic of backend (lifecycle,
# exec, networking policy, git remote, workspace, presets, persistence)
# request the ``backend`` fixture and use ``make_create_args(backend, ...)``
# to build their ``sandbox create`` argv. pytest then runs each test twice
# — once for ``backend == "lima"`` and once for ``backend == "container"``.
#
# Lima-only tests (``test_m1_vm_lifecycle.py``, ``test_m6_hardening.py``,
# ``test_m85_golden_image.py``, ``test_m3_networking.py::
# test_concurrent_sessions``) carry an ``@pytest.mark.skipif(backend ==
# "container", reason=...)`` to declare why the backend pair is not
# applicable. Tests in ``test_lite.py`` are container-only and don't take
# this fixture.
#
# CI policy (spec lines 1060-1070): PR-time runs ``container`` only;
# merge-to-main runs the full ``[lima, container]`` matrix; nightly adds
# performance numbers.

@pytest.fixture(params=["lima", "container"])
def backend(request) -> str:
    """Parametrize a test across the two session backends.

    Yields ``"lima"`` then ``"container"`` (one test invocation each).
    The test should pass the value to :func:`make_create_args` and any
    other backend-aware helpers; nothing else should branch on the
    fixture value directly.
    """
    return request.param
