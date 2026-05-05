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

# The test daemon uses a distinct base VM name so it neither sees nor
# touches the operator's production `sandbox-base` Lima instance. We
# export this at module-import time (rather than inside `sandbox_daemon`)
# so test modules that read the name as a module-level constant — e.g.
# `test_golden_image.BASE_VM_NAME = os.environ.get("SANDBOX_BASE_VM_NAME",
# ...)` — pick up the same value the spawned daemon sees. Operators can
# override via the env var before invoking pytest.
os.environ.setdefault("SANDBOX_BASE_VM_NAME", "sandbox-test-base")

# CIDR pool of /28 blocks the e2e test daemon allocates session networks
# from. Disjoint from the production pool (10.209.0.0/20) so the
# M11-S10 CIDR-scoped reaper has something to filter on: the test
# daemon's startup cleanup only deletes session resources falling inside
# this CIDR, leaving any live production sessions in 10.209.0.0/20
# untouched.
E2E_TEST_POOL_CIDR = "10.220.0.0/20"

# The test daemon reads its users.conf from a tempfile we own, written
# at conftest-module import time. The tempfile lists ONLY the test pool
# (10.220.0.0/20) so the daemon's `find_subnet_by_uid` lookup at startup
# returns the test pool — not the production pool the canonical
# `/etc/sandboxd/users.conf` lists first. The daemon honors
# `SANDBOX_USERS_CONF` unconditionally per M11-S9 (it is not the
# privilege boundary; only the cap'd route helper is, and the helper
# default-build refuses the env var). The production route helper
# continues reading the canonical file — which lists both pools after
# `make setup-users-conf` — so authorization for the test pool's
# gateway IP succeeds without weakening the M11-S9 boundary.
#
# Tempfile is owned by the test runner's uid (the daemon does not run
# the route-helper-style ownership check on the env-var path) and is
# cleaned up at process exit via `atexit`. Like `SANDBOX_BASE_VM_NAME`
# above, we set it on the harness's own env so children inherit it; an
# operator-set value (e.g. for ad-hoc debugging) takes precedence via
# `setdefault`.
import atexit  # noqa: E402  -- after module-level setup
import getpass  # noqa: E402
if "SANDBOX_USERS_CONF" not in os.environ:
    _users_conf_payload = {
        "subnets": [
            {
                "comment": (
                    "E2E test daemon pool — see "
                    "docs/internal/milestones/M12.md S13."
                ),
                "cidr": E2E_TEST_POOL_CIDR,
                "allow_users": [getpass.getuser()],
            }
        ]
    }
    _users_conf_tf = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="sandbox-e2e-users-",
        delete=False,
    )
    json.dump(_users_conf_payload, _users_conf_tf)
    _users_conf_tf.flush()
    _users_conf_tf.close()
    os.chmod(_users_conf_tf.name, 0o600)
    os.environ["SANDBOX_USERS_CONF"] = _users_conf_tf.name

    def _cleanup_users_conf_tempfile(path: str = _users_conf_tf.name) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    atexit.register(_cleanup_users_conf_tempfile)


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
    # 1. Docker accessible — universal: both backends need Docker (Lima
    #    pulls the gateway image; the container backend needs Docker
    #    proper). KVM and Lima checks are deliberately not at session
    #    scope: KVM is Linux/QEMU-specific (the upcoming macOS VZ Lima
    #    backend has no /dev/kvm), and limactl is only needed by tests
    #    carrying the ``lima`` marker — see
    #    ``_lima_required_for_lima_tests`` below.
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

    # 2. Gateway image exists — both backends require it (the gateway
    #    container is the egress chokepoint for every session).
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

    # Cleanup of stale sandbox-* resources is intentionally NOT done here.
    # The test daemon uses a distinct base VM name
    # (SANDBOX_BASE_VM_NAME = "sandbox-test-base"; see `sandbox_daemon`)
    # and its own CIDR-scoped startup reaper handles cleanup of stale
    # test-daemon orphans without touching production resources. Sweeping
    # every `sandbox-*` resource on the host from here would clobber the
    # operator's production sandboxd — including the `sandbox-base`
    # golden image and any live production sessions.


@pytest.fixture(autouse=True)
def _lima_required_for_lima_tests(request):
    """Per-test prereq check for tests carrying the ``lima`` marker.

    Tests that need limactl / QEMU bridge helper / bridge.conf carry
    ``@pytest.mark.lima`` (module-level for whole-file Lima-only files,
    per-test for mixed files). On hosts without these prerequisites,
    each Lima-marked test emits an individual, actionable skip; the
    rest of the suite (cross-backend ``[container]`` parametrizations
    and container-only ``test_lite.py``) runs unaffected.

    Tests without the ``lima`` marker return immediately and pay no
    cost. The fixture is declared at session-default scope (function-
    scoped via autouse=True) so it runs once per test rather than once
    per session.
    """
    if request.node.get_closest_marker("lima") is None:
        return

    # 1. Lima installed.
    try:
        subprocess.run(
            ["limactl", "--version"],
            capture_output=True, timeout=15, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip(
            "Lima (limactl) not installed; install via `brew install lima` "
            "(macOS) or your distribution package (Linux), then re-run."
        )

    # 2. qemu-bridge-helper installed (Lima/QEMU-specific).
    helper = _find_qemu_bridge_helper()
    if helper is None:
        searched = ", ".join(str(p) for p in QEMU_BRIDGE_HELPER_PATHS)
        pytest.skip(
            f"qemu-bridge-helper not found (checked: {searched}). "
            "Install the qemu-system-x86 (or qemu-utils) package."
        )

    # 3. qemu-bridge-helper has setuid bit.
    helper_stat = helper.stat()
    if not (helper_stat.st_mode & stat.S_ISUID):
        pytest.skip(
            f"qemu-bridge-helper at {helper} is missing the setuid bit. "
            f"Run: sudo chmod u+s {helper}"
        )

    # 4. bridge.conf exists.
    if not BRIDGE_CONF_PATH.exists():
        pytest.skip(
            f"{BRIDGE_CONF_PATH} not found. Create it with: "
            f"sudo mkdir -p {BRIDGE_CONF_PATH.parent} && "
            f'echo "allow all" | sudo tee {BRIDGE_CONF_PATH}'
        )


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

    # The daemon inherits SANDBOX_BASE_VM_NAME from the parent test
    # process, where it is set at conftest-module import time (see the
    # `os.environ.setdefault` near the top of this file). This keeps
    # `test_golden_image.BASE_VM_NAME` and the daemon's view of the base
    # VM in lockstep without having to thread a fixture through it.
    proc = subprocess.Popen(
        [
            str(sandbox_binaries.sandboxd),
            "--socket", str(socket_path),
            "--base-dir", str(base_dir),
        ],
        stdout=stdout_fh,
        stderr=stderr_fh,
    )

    # Wait for the daemon to accept connections on its socket.
    #
    # Polling `socket_path.exists()` is not enough: the path appears the
    # moment the daemon calls `bind(2)`, but `connect(2)` keeps returning
    # ECONNREFUSED until the daemon also calls `listen(2)`.  A CLI invoked
    # in that window races and intermittently fails with "cannot connect
    # to sandboxd: Connection refused (os error 111)".  Probe with an
    # actual connect() so we only return once the listen backlog is up.
    deadline = time.monotonic() + DAEMON_STARTUP_TIMEOUT
    ready = False
    while time.monotonic() < deadline:
        # Check if the daemon crashed.
        if proc.poll() is not None:
            stdout_fh.close()
            stderr_fh.close()
            pytest.fail(
                f"sandboxd exited early (code {proc.returncode}).\n"
                f"stdout: {stdout_log.read_text()}\n"
                f"stderr: {stderr_log.read_text()}"
            )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(str(socket_path))
            ready = True
            break
        except (FileNotFoundError, ConnectionRefusedError):
            # Path not yet created (pre-bind) or bound but not yet
            # listening — keep polling.
            pass
        # Any other exception (PermissionError, OSError with a
        # non-ECONNREFUSED errno, etc.) is a real misconfiguration:
        # let it propagate so the failure is visible.
        time.sleep(0.1)
    if not ready:
        proc.kill()
        stdout_fh.close()
        stderr_fh.close()
        pytest.fail(
            f"sandboxd did not accept connections on its socket within "
            f"{DAEMON_STARTUP_TIMEOUT}s"
        )

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
        timeout=1800,
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
# Backend parametrization
# ---------------------------------------------------------------------------
#
# Three-way fixture-symmetric convention; zero convention-driven skips
# on a properly-configured host:
#
# * Cross-backend tests take the ``backend`` fixture, no marker.
#   pytest runs them twice — once with ``backend == "lima"`` and once
#   with ``backend == "container"`` — and they pass the value through
#   ``make_create_args(backend, ...)`` to build their ``sandbox
#   create`` argv.
#
# * Lima-only tests carry ``@pytest.mark.lima`` (module-level for
#   whole-file Lima-only files like ``test_vm_lifecycle.py``,
#   ``test_hardening.py``, and ``test_golden_image.py``; per-test for
#   mixed files such as ``test_networking.py::
#   test_concurrent_sessions``). They do not take the ``backend``
#   fixture and hardcode ``"lima"`` in ``make_create_args`` calls. The
#   ``lima`` marker also gates the per-test
#   ``_lima_required_for_lima_tests`` fixture, so on a host without
#   limactl / qemu-bridge-helper / bridge.conf each Lima-marked test
#   emits a justified per-test skip rather than collapsing the whole
#   session.
#
# * Container-only tests carry ``@pytest.mark.container`` (module-
#   level for ``test_lite.py``). They do not take the ``backend``
#   fixture and hardcode ``"container"`` in ``make_create_args``
#   calls.
#
# CI selection: ``make test-e2e-container`` uses ``-m "not lima" -k
# "not [lima]"`` (the ``-m`` clause excludes Lima-marked tests; the
# ``-k`` clause filters out the ``[lima]`` parametrization of cross-
# backend tests). ``make test-e2e-matrix`` runs everything.

@pytest.fixture(params=["lima", "container"])
def backend(request) -> str:
    """Parametrize a test across the two session backends.

    Yields ``"lima"`` then ``"container"`` (one test invocation each).
    The test should pass the value to :func:`make_create_args` and any
    other backend-aware helpers; nothing else should branch on the
    fixture value directly.
    """
    return request.param
