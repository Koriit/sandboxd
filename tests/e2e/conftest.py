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
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

import pytest


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Stash per-phase test outcome on the item.

    Allows fixtures (autouse or otherwise) to inspect whether the test
    body itself failed (`item.rep_call.failed`) vs. setup/teardown.
    Standard pytest plugin pattern; see pytest docs for details.
    """
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CARGO_WORKSPACE = PROJECT_ROOT / "sandboxd"
SANDBOXD_BIN = CARGO_WORKSPACE / "target" / "debug" / "sandboxd"
SANDBOX_BIN = CARGO_WORKSPACE / "target" / "debug" / "sandbox"

# Rust source-of-truth files we extract values from at test-collection time
# so the harness never drifts out of step with the daemon it drives.
SANDBOX_CORE_CARGO_TOML = CARGO_WORKSPACE / "sandbox-core" / "Cargo.toml"
SANDBOX_CORE_USERS_CONF_RS = CARGO_WORKSPACE / "sandbox-core" / "src" / "users_conf.rs"


def _read_workspace_version() -> str:
    """Extract `sandbox-core`'s package version from its Cargo.toml.

    This is the same value the Makefile's `gateway-image` target passes
    to `docker build -t sandbox-gateway:<version>` and the daemon's
    `CARGO_PKG_VERSION` at run-time. Reading the Cargo.toml directly
    keeps the preflight check working on hosts without a Rust toolchain
    (e.g. operators who only need to inspect an already-built image).
    """
    if not SANDBOX_CORE_CARGO_TOML.exists():
        raise RuntimeError(
            f"Cannot read workspace version: {SANDBOX_CORE_CARGO_TOML} not found"
        )
    text = SANDBOX_CORE_CARGO_TOML.read_text()
    # Match the first `version = "X.Y.Z"` under `[package]` — Cargo.toml's
    # package section is the first table, so the first match is correct.
    matches = re.findall(r'(?m)^\s*version\s*=\s*"([^"]+)"', text)
    if not matches:
        raise RuntimeError(
            f"Cannot extract version from {SANDBOX_CORE_CARGO_TOML}: "
            f"no `version = \"...\"` line found"
        )
    return matches[0]


def _read_min_supported_users_conf_schema() -> int:
    """Extract DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA from users_conf.rs.

    Bridges the daemon's source-of-truth schema floor into the synthesized
    users.conf payload below so a future bump of the Rust constant forces
    a deterministic test-collection failure here rather than a mid-matrix
    surprise once a test daemon refuses to boot.
    """
    if not SANDBOX_CORE_USERS_CONF_RS.exists():
        raise RuntimeError(
            f"Cannot read users.conf schema constant: "
            f"{SANDBOX_CORE_USERS_CONF_RS} not found"
        )
    text = SANDBOX_CORE_USERS_CONF_RS.read_text()
    matches = re.findall(
        r"const\s+DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA\s*:\s*\w+\s*=\s*(\d+)",
        text,
    )
    if len(matches) == 0:
        raise RuntimeError(
            f"Cannot extract DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA from "
            f"{SANDBOX_CORE_USERS_CONF_RS}: no matching `const ... = N;` line found"
        )
    if len(matches) > 1:
        raise RuntimeError(
            f"Cannot extract DAEMON_MIN_SUPPORTED_USERS_CONF_SCHEMA from "
            f"{SANDBOX_CORE_USERS_CONF_RS}: expected one declaration, "
            f"found {len(matches)}"
        )
    return int(matches[0])


SANDBOX_GATEWAY_IMAGE_TAG = f"sandbox-gateway:{_read_workspace_version()}"

# Maximum time to wait for the daemon socket to appear (seconds).
DAEMON_STARTUP_TIMEOUT = 30

# Paths to check for qemu-bridge-helper.
QEMU_BRIDGE_HELPER_PATHS = [
    Path("/usr/lib/qemu/qemu-bridge-helper"),
    Path("/usr/libexec/qemu-bridge-helper"),
]

BRIDGE_CONF_PATH = Path("/etc/qemu/bridge.conf")

# ---------------------------------------------------------------------------
# Cross-user harness
# ---------------------------------------------------------------------------
#
# The e2e harness launches the daemon as the ``sandbox`` system user via
# ``sudo -u sandbox``, the single cross-user path. All sudo is
# pre-authorized at ``make setup-dev-env`` time via a NOPASSWD sudoers
# fragment (``/etc/sudoers.d/sandboxd-test``); no runtime root sudo is
# ever issued.
#
# The operator must be a member of the ``sandbox`` group so the pytest
# process can reach the daemon socket (mode 0660, group=sandbox). Group
# changes from ``usermod -aG sandbox <operator>`` do not take effect in
# the current login session; ``make test-e2e`` / ``make test-e2e-container``
# wrap pytest in ``sg sandbox -c '…'`` to activate the group without
# requiring a re-login.

# Socket lives inside the sandbox base dir so the sandbox-user daemon
# can create it with no elevated privileges and the operator (group
# sandbox; base dir 0750 → group r-x) can connect.
_SANDBOX_PROD_SOCKET = Path("/var/lib/sandbox/sandboxd.sock")
_SANDBOX_PROD_BASE_DIR = Path("/var/lib/sandbox")

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
# CIDR-scoped reaper has something to filter on: the test daemon's
# startup cleanup only deletes session resources falling inside this
# CIDR, leaving any live production sessions in 10.209.0.0/20 untouched.
E2E_TEST_POOL_CIDR = "10.220.0.0/20"

# The test daemon reads its users.conf from a tempfile we own, written
# at conftest-module import time. The tempfile lists ONLY the test pool
# (10.220.0.0/20) so the daemon's `find_subnet_by_uid` lookup at startup
# returns the test pool — not the production pool the canonical
# `/etc/sandboxd/users.conf` lists first. The daemon honors
# `SANDBOX_USERS_CONF` unconditionally — it is not the privilege
# boundary; only the cap'd route helper is, and the helper
# default-build refuses the env var. The production route helper
# continues reading the canonical file — which lists both pools after
# `make setup-users-conf` — so authorization for the test pool's
# gateway IP succeeds without weakening the privilege boundary.
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
    # ``allow_users`` lists the operator AND the ``sandbox`` system user.
    # The daemon runs as the ``sandbox`` system user; its startup-time
    # ``find_subnet_by_uid`` lookup requires the daemon's own uid to
    # appear in some pool's ``allow_users``. Names that do not resolve
    # to a uid on a given host are silently skipped by the daemon
    # ("unresolvable allow_users entries are treated as non-matches"),
    # so listing ``sandbox`` is a no-op on hosts that have not
    # provisioned the system user.
    _users_conf_payload = {
        "_schema_version": _read_min_supported_users_conf_schema(),
        "subnets": [
            {
                "comment": (
                    "E2E test daemon pool — see "
                    "docs/internal/milestones/M12.md S13."
                ),
                "cidr": E2E_TEST_POOL_CIDR,
                "allow_users": [getpass.getuser(), "sandbox"],
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
    # Mode 0644 (world-readable) is required so the daemon running as
    # the ``sandbox`` system user can read the file (it lives under
    # /tmp, owned by the test operator). The file lists only CIDR pool
    # definitions for the test daemon — no secrets — so 0644 is safe.
    os.chmod(_users_conf_tf.name, 0o644)
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
    defaults — see , line ~620).

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


# ---------------------------------------------------------------------------
# Cross-user Lima helpers
# ---------------------------------------------------------------------------
#
# The daemon runs as the ``sandbox`` system user; every Lima control-plane
# operation goes through ``sandbox-lima-helper``, which pivots to the
# *operator* uid before exec'ing limactl.  The resulting Lima state lives at
# the per-operator path:
#
#   /var/lib/sandboxd/<op_uid>/lima/
#
# NOT at the test-runner's ``~/.lima/``.  Any test-side helper that invokes
# ``limactl`` directly (for inspection or cleanup) must therefore pass
# ``env LIMA_HOME=<OP_LIMA_HOME>`` so limactl queries the right registry.
#
# IMPORTANT: the per-operator LIMA_HOME and all its contents (lima.yaml,
# _config/user, VM dirs) are owned by the OPERATOR uid (the test runner)
# with mode 0600/0700 — they are operator-private.  Running limactl as the
# ``sandbox`` system user (uid 999) via ``sudo -n -u sandbox`` therefore
# fails with EACCES ("open .../lima.yaml: permission denied" →
# "instance has no configuration").  The test process already IS the operator
# uid, so the correct approach is to run limactl directly (no sudo) with
# LIMA_HOME set to the per-operator path.
#
# Use ``limactl_cmd()`` for the argv prefix and ``OP_LIMA_HOME`` for the path
# constant in assertions.


#: Absolute path to the per-operator LIMA_HOME under the cross-user harness.
#: Derived once at import time from the test runner's uid (the operator).
OP_LIMA_HOME: str = f"/var/lib/sandboxd/{os.getuid()}/lima"


def limactl_cmd(*args: str) -> list[str]:
    """Build a limactl argv that queries the per-operator LIMA_HOME.

    The VM registry lives at ``/var/lib/sandboxd/<op_uid>/lima/`` (the
    per-operator LIMA_HOME).  Bare ``limactl`` would look in ``~/.lima/``
    and see nothing, so this wrapper sets ``LIMA_HOME`` to the per-operator
    path via ``env``.

    The per-operator LIMA_HOME and all its files (lima.yaml, _config/user,
    VM directories) are owned by the OPERATOR uid and are operator-private
    (0600/0700).  Running limactl as the ``sandbox`` system user via
    ``sudo -n -u sandbox`` would fail with EACCES.  The test process already
    runs as the operator uid, so we invoke limactl directly — no sudo prefix
    — with only the LIMA_HOME override.

    Usage::

        subprocess.run(limactl_cmd("list", "--json"), ...)
        subprocess.run(limactl_cmd("shell", vm_name, "--", "uname", "-a"), ...)
    """
    return ["env", f"LIMA_HOME={OP_LIMA_HOME}", "limactl", *args]


#: In-VM home directory for the ``sandbox`` user inside Lima VMs.
#: Files written here persist across stop/start (non-tmpfs, on the VM's disk).
LIMA_VM_HOME: str = "/home/sandbox"

#: In-VM home directory for the ``sandbox`` user inside lite (Docker) containers.
#: The lite Dockerfile runs ``useradd ... sandbox`` and the container runtime
#: mounts the home volume at ``/home/sandbox``.  Both backends now share the
#: same user name and home directory path.  Cross-backend tests may use
#: ``guest_home(backend)`` or either constant directly — they resolve to the
#: same value.
CONTAINER_HOME: str = "/home/sandbox"


def guest_home(backend: str) -> str:
    """Return the in-VM home directory appropriate for ``backend``.

    Both Lima and container (lite) sessions now use ``/home/sandbox`` — the
    ``sandbox`` user is created with that home on both backends.

    Cross-backend tests parametrized via the ``backend`` fixture may call
    this helper for clarity; both arms resolve to ``/home/sandbox``.

    Single-backend tests should use the appropriate constant directly:
    ``LIMA_VM_HOME`` for Lima-only tests, ``CONTAINER_HOME`` for
    container-only tests.
    """
    return LIMA_VM_HOME if backend == "lima" else CONTAINER_HOME


def wait_for_daemon_ready(
    socket_path,
    proc: subprocess.Popen,
    timeout: float,
) -> None:
    """Block until ``sandboxd`` accepts connections on ``socket_path``.

    Polling ``os.path.exists(socket_path)`` is not enough: the path
    appears the moment the daemon calls ``bind(2)``, but ``connect(2)``
    keeps returning ``ECONNREFUSED`` until the daemon also calls
    ``listen(2)``. A CLI invoked in that window races and intermittently
    fails with "cannot connect to sandboxd: Connection refused (os error
    111)". Probe with an actual ``connect()`` so we only return once the
    listen backlog is up.

    Treats ``FileNotFoundError`` (pre-bind) and ``ConnectionRefusedError``
    (bound but not listening) as "keep polling". Any other exception
    (e.g. ``PermissionError`` or an unrelated ``OSError`` errno) is a
    real misconfiguration and is allowed to propagate so the failure is
    visible.

    Fails the test via ``pytest.fail`` if the daemon process exits or if
    the deadline expires before the socket starts accepting connections.
    The caller is responsible for any process/file-handle cleanup on
    failure paths.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(
                f"sandboxd exited early (code {proc.returncode}) before "
                f"its socket started accepting connections."
            )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(str(socket_path))
            return
        except (FileNotFoundError, ConnectionRefusedError):
            # Path not yet created (pre-bind) or bound but not yet
            # listening — keep polling.
            pass
        time.sleep(0.1)
    pytest.fail(
        f"sandboxd did not accept connections on {socket_path} within "
        f"{timeout}s"
    )


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
    """Best-effort capture of Lima VM logs for debugging failures.

    Lima state lives at ``OP_LIMA_HOME`` (``/var/lib/sandboxd/<op_uid>/lima/``).
    """
    vm = lima_vm_name(session_id)
    logs = []

    # ha.stderr.log is the main Lima log.  The VM dir is inside OP_LIMA_HOME.
    ha_log = os.path.join(OP_LIMA_HOME, vm, "ha.stderr.log")
    try:
        with open(ha_log) as f:
            content = f.read()
            if content:
                logs.append(f"--- {ha_log} (last 50 lines) ---")
                logs.extend(content.splitlines()[-50:])
            else:
                logs.append(f"(no ha.stderr.log found for {vm} in {OP_LIMA_HOME})")
    except FileNotFoundError:
        logs.append(f"(no ha.stderr.log found for {vm} in {OP_LIMA_HOME})")

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
    #    container is the egress chokepoint for every session). The
    #    daemon composes the tag as `sandbox-gateway:<workspace-version>`
    #    at run-time (see `CARGO_PKG_VERSION` use in the backend) and
    #    refuses `:latest`, so the preflight must inspect the same
    #    versioned tag that `make gateway-image` produces.
    try:
        subprocess.run(
            ["docker", "image", "inspect", SANDBOX_GATEWAY_IMAGE_TAG],
            capture_output=True, timeout=30, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pytest.skip(
            f"Docker image {SANDBOX_GATEWAY_IMAGE_TAG!r} not found. "
            f"Build it with: make gateway-image"
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


def _assert_operator_in_sandbox_group() -> None:
    """Fail loudly if the calling pytest process is not in the ``sandbox`` group.

    The daemon socket is mode 0660 with ``group=sandbox``. A test process
    whose effective groups do not include ``sandbox`` cannot read or write
    the socket and every CLI invocation fails with EACCES — a setup gap,
    not the cross-user bug under test.

    Group changes from ``usermod -aG sandbox <operator>`` do **not** take
    effect in the current login session. The remediation depends on context:

      * Interactive: log out + log back in, or re-launch the shell.
      * Scripted: wrap the invocation in ``sg sandbox -c '…'``.
      * CI: ensure the user that runs pytest was added to the group at
        image-build time (before the session starts).
    """
    import grp
    try:
        sandbox_gid = grp.getgrnam("sandbox").gr_gid
    except KeyError:
        pytest.fail(
            "The `sandbox` system group does not exist on this host. "
            "Run `make setup-sandbox-user` from the workspace root and "
            "re-run the tests."
        )
    # The socket is mode 0660, group=sandbox, so access is granted when the
    # sandbox gid is the process's effective GID *or* in its supplementary
    # set. `sg sandbox -c …` (how the make targets wrap pytest) sets sandbox
    # as the *primary/effective* GID and does not add it to the supplementary
    # list — and Linux `getgroups()` does not report the effective GID — so
    # checking `os.getgroups()` alone spuriously fails under the sg wrap even
    # though the process can read the socket. Accept either.
    if sandbox_gid == os.getegid() or sandbox_gid in os.getgroups():
        return
    # Membership exists in /etc/group but is not yet active in this
    # process — most likely the operator was just added and has not
    # re-logged-in. The remediation depends on whether the operator
    # statically is a member.
    operator = getpass.getuser()
    static_groups = subprocess.run(
        ["id", "-nG", operator],
        capture_output=True, text=True, timeout=5,
    ).stdout.split()
    if "sandbox" in static_groups:
        remediation = (
            "Operator '{op}' is listed in /etc/group as a member of "
            "'sandbox' but the group is not active in the current "
            "process. Log out and back in, or re-run pytest under "
            "`sg sandbox -c 'python -m pytest …'` so the new group "
            "is visible to the test process."
        ).format(op=operator)
    else:
        remediation = (
            "Operator '{op}' is not a member of the 'sandbox' group. "
            "Run `make setup-operator-group-membership` from the "
            "workspace root, log out and back in, then re-run pytest."
        ).format(op=operator)
    pytest.fail(
        "The pytest process must be a member of the 'sandbox' system "
        "group (the daemon socket is mode 0660, group=sandbox). "
        f"{remediation}"
    )


def _wait_for_daemon_socket(
    socket_path: Path,
    is_dead: "callable[[], tuple[bool, str]]",
    timeout: float,
) -> None:
    """Block until ``socket_path`` accepts unix-socket connections.

    Generalisation of :func:`wait_for_daemon_ready` that takes an
    ``is_dead`` callback instead of a ``Popen``. ``is_dead`` returns
    ``(True, "<reason>")`` when the daemon is known to have exited and
    ``(False, "")`` otherwise. The callback indirection lets a caller
    supply its own liveness check; the ``sudo -u sandbox`` launcher
    passes a closure over ``proc.poll()``.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        dead, reason = is_dead()
        if dead:
            pytest.fail(
                f"sandboxd exited early before its socket started "
                f"accepting connections: {reason}"
            )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect(str(socket_path))
            return
        except (FileNotFoundError, ConnectionRefusedError, PermissionError):
            # Path not yet created (pre-bind), bound but not yet
            # listening, or briefly visible at mode 0700 between
            # ``bind`` and the daemon's explicit ``chmod 0660`` — keep
            # polling. ``PermissionError`` is accepted here (unlike in
            # :func:`wait_for_daemon_ready`) because the daemon now
            # runs as a different uid than the test process; a transient
            # EACCES against the socket during the bind→chmod window is
            # routine, not a misconfiguration.
            pass
        time.sleep(0.1)
    pytest.fail(
        f"sandboxd did not accept connections on {socket_path} within "
        f"{timeout}s"
    )


def _sudo_rm_children_except(directory: Path, keep: list[str]) -> None:
    """As the ``sandbox`` user, remove every direct child of ``directory``
    whose name is not in ``keep``.

    Implementation-independent on purpose: it uses
    ``find -maxdepth 1 … -exec rm -rf {} +`` rather than ``find … -delete``.
    ``-delete`` silently turns on ``-depth``, which in turn neuters
    ``-prune`` (GNU find documents this) — so the previous
    ``( -path … ) -prune -o -delete`` idiom both failed to reliably remove
    top-level state like ``sessions.db`` *and* over-deleted the preserved
    cache directories' contents. ``-maxdepth 1`` + ``rm -rf`` sidesteps the
    whole ``-depth``/``-prune`` interaction and behaves identically across
    GNU find and other implementations.

    Skipped silently when ``directory`` does not exist.
    """
    if not directory.exists():
        return
    argv = [
        "sudo", "-n", "-u", "sandbox",
        "find", str(directory), "-mindepth", "1", "-maxdepth", "1",
    ]
    for name in keep:
        argv += ["!", "-name", name]
    argv += ["-exec", "rm", "-rf", "{}", "+"]
    subprocess.run(argv, capture_output=True, timeout=120)


def _reset_sandbox_state_dir() -> None:
    """Wipe ``/var/lib/sandbox`` between pytest sessions, preserving the
    Lima base-image cache and the golden base VM.

    The daemon writes all files under ``/var/lib/sandbox`` as the
    ``sandbox`` user, so deletes are issued as the ``sandbox`` user via
    :func:`_sudo_rm_children_except`.  The base dir itself is left intact
    (owned sandbox:sandbox 0750, provisioned by
    ``make setup-sandbox-prod-base-dir``); we only remove daemon-managed
    state so a fresh ``sessions.db`` lands on the next session start.

    This is the safety net that keeps a crashed run (which never reached
    its teardown) from leaking its sessions into the *next* run's daemon —
    where a stale, same-named session would shadow the freshly created one
    and route ``ssh``/``proxy`` at a long-gone container.

    What we explicitly **keep**:

    * ``.cache/lima/download/`` — the Ubuntu cloud-image qcow2 cache.
      The download is ~580 MiB and on slow-network hosts takes 7-10+
      minutes; nuking it between every pytest session forces the
      session-scoped pre-warm fixture to re-download from scratch,
      which collides with the per-test pytest-timeout once Lima
      tests start running. The cache is content-addressed
      (``by-url-sha256/<hash>/``) so it cannot pollute future
      sessions with stale data.
    * ``.lima/<SANDBOX_BASE_VM_NAME>/`` — the golden base VM that
      ``limactl clone`` derives every per-session VM from. Building
      it from scratch costs the cloud-init provisioning round on top
      of the download.
    * ``base-image-meta.json`` — the freshness metadata the daemon
      writes after a successful base-image build. Without this file
      ``check_base_image()`` reports ``Stale`` even when the VM
      itself is on disk, defeating the pre-warm short-circuit.

    All three kept paths are managed via Lima's own age/freshness
    semantics: ``BASE_IMAGE_MAX_AGE_DAYS`` in ``sandbox-core::lima``
    forces a rebuild after 10 days regardless of what's on disk.

    Skipped silently when the dir does not exist (first-ever run).
    """
    base_vm = os.environ.get("SANDBOX_BASE_VM_NAME", "sandbox-test-base")

    # Prod base dir: remove every top-level entry — sessions.db,
    # per-session dirs, listeners, events, the socket — except the Lima
    # cache, the .lima tree, and the freshness metadata. Then prune the
    # .lima tree down to the golden base VM (dropping per-session clones).
    _sudo_rm_children_except(
        _SANDBOX_PROD_BASE_DIR, [".cache", ".lima", "base-image-meta.json"]
    )
    _sudo_rm_children_except(_SANDBOX_PROD_BASE_DIR / ".lima", [base_vm])

    # Per-operator LIMA_HOME (``/var/lib/sandboxd/<op_uid>/lima``): keep the
    # download cache, the golden base VM, and the freshness metadata; remove
    # per-session VM clones and any stale config so a partially-initialised
    # base VM left by a killed run is not reused via a stale meta file. The
    # base VM lives directly under LIMA_HOME here (LIMA_HOME *is* the Lima
    # home), not under a .lima subdir.
    op_uid = os.getuid()
    op_lima_home = Path(f"/var/lib/sandboxd/{op_uid}/lima")
    _sudo_rm_children_except(
        op_lima_home, [".cache", base_vm, "base-image-meta.json"]
    )


def _stage_binaries_for_sandbox_user(sandbox_binaries: SandboxBinaries) -> dict:
    """Copy the freshly-built ``sandboxd`` and ``sandbox-guest`` binaries into
    a world-traversable directory the ``sandbox`` system user can reach.

    The workspace lives under the operator's home directory (commonly mode
    0750), which the unprivileged ``sandbox`` user cannot search.  So
    ``sudo -u sandbox <workspace>/target/debug/sandboxd`` fails the
    post-setuid ``execve`` permission check with EACCES ("Permission
    denied") — the kernel resolves the path *as the sandbox user*, which
    needs search (``x``) on every ancestor directory.  We stage the
    binaries into a fresh ``/tmp`` subdirectory (``/tmp`` is mode 1777, so
    every user can traverse it) owned by the operator at mode 0755, and run
    the daemon from there.  No host-permission changes and no root required.

    Returns a dict with ``dir`` (the staging directory, removed at session
    teardown), ``sandboxd`` and ``sandbox_guest`` (the staged paths).
    """
    # ``mkdtemp`` yields a unique dir each session, so a still-running daemon
    # from a prior session can never collide here (no ETXTBSY on copy).
    stage_dir = Path(tempfile.mkdtemp(prefix="sandboxd-e2e-", dir="/tmp"))
    # mkdtemp creates the dir 0700; widen to 0755 so `sandbox` can traverse.
    os.chmod(stage_dir, 0o755)

    src_sandboxd = Path(sandbox_binaries.sandboxd)
    src_guest = src_sandboxd.parent / "sandbox-guest"
    staged_sandboxd = stage_dir / "sandboxd"
    staged_guest = stage_dir / "sandbox-guest"
    shutil.copy2(src_sandboxd, staged_sandboxd)
    shutil.copy2(src_guest, staged_guest)
    os.chmod(staged_sandboxd, 0o755)
    os.chmod(staged_guest, 0o755)
    return {
        "dir": stage_dir,
        "sandboxd": staged_sandboxd,
        "sandbox_guest": staged_guest,
    }


def _launch_daemon_as_sandbox_via_sudo(
    sandbox_binaries: SandboxBinaries,
    tmp_path: Path,
) -> dict:
    """Start the daemon as the ``sandbox`` user via ``sudo -u sandbox``.

    This is the sole launch path. Requires the NOPASSWD sudoers fragment
    at ``/etc/sudoers.d/sandboxd-test`` (installed by
    ``make setup-test-sudoers-fragment``); a missing fragment causes sudo
    to prompt and hang the wait-for-socket deadline, so the harness probes
    up front and fails with a precise error.

    The base dir ``/var/lib/sandbox`` must already exist with
    ``sandbox:sandbox`` ownership and mode 0750 — provisioned once by
    ``make setup-sandbox-prod-base-dir`` (part of ``make setup-dev-env``).
    The socket lives inside the base dir so the daemon can create it
    without root.  The daemon (and guest) binaries are staged into a
    world-traversable ``/tmp`` dir so the ``sandbox`` user can exec them
    despite the workspace living under the operator's 0750 home — see
    :func:`_stage_binaries_for_sandbox_user`.
    """
    _assert_operator_in_sandbox_group()

    # Assert the base dir is provisioned. The daemon writes the socket
    # and all state here; if it is missing the daemon will fail to start.
    if not _SANDBOX_PROD_BASE_DIR.exists():
        pytest.fail(
            f"{_SANDBOX_PROD_BASE_DIR} does not exist. "
            "Run `make setup-sandbox-prod-base-dir` (or `make setup-dev-env`) "
            "from the workspace root to create it, then re-run."
        )

    staged = _stage_binaries_for_sandbox_user(sandbox_binaries)

    # Probe NOPASSWD authorisation *and* binary reachability in one shot.
    # ``sudo -n -u sandbox <staged-binary> --version`` returns rc=1 with
    # "a password is required" on stderr when the sudoers fragment is
    # absent/mis-scoped, or "Permission denied" if the sandbox user cannot
    # exec the staged binary. rc=0 confirms the full chain works. Failing
    # here prevents a silent hang at the wait-for-socket deadline.
    probe = subprocess.run(
        ["sudo", "-n", "-u", "sandbox",
         str(staged["sandboxd"]), "--version"],
        capture_output=True, text=True, timeout=10,
    )
    if probe.returncode != 0:
        shutil.rmtree(staged["dir"], ignore_errors=True)
        pytest.fail(
            "The NOPASSWD sudoers fragment at /etc/sudoers.d/sandboxd-test "
            "is missing or does not authorise the operator to run commands "
            "as the `sandbox` user. "
            "Run `make setup-test-sudoers-fragment` from the workspace "
            "root and re-run.\n"
            f"sudo probe stderr: {probe.stderr.strip()!r}"
        )

    _reset_sandbox_state_dir()

    stdout_log = tmp_path / "sandboxd.stdout.log"
    stderr_log = tmp_path / "sandboxd.stderr.log"
    stdout_fh = open(stdout_log, "w")
    stderr_fh = open(stderr_log, "w")

    daemon_env = os.environ.copy()
    # The sudoers fragment installed by ``make setup-test-sudoers-fragment``
    # declares ``Defaults:$USER env_keep += "SANDBOX_USERS_CONF ..."``
    # so the variables propagate through sudo without ``--preserve-env``
    # (which is more brittle to whitelist).
    #
    # ``SANDBOX_LIMA_HELPER_PATH`` points the daemon's lima-helper resolver
    # at the test-cap'd binary so all Lima control-plane operations go
    # through sandbox-lima-helper and pivot to the operator's uid.
    proc = subprocess.Popen(
        [
            "sudo", "-n", "-u", "sandbox",
            str(staged["sandboxd"]),
            "--socket", str(_SANDBOX_PROD_SOCKET),
            "--base-dir", str(_SANDBOX_PROD_BASE_DIR),
        ],
        env={
            **daemon_env,
            "SANDBOX_USERS_CONF": os.environ["SANDBOX_USERS_CONF"],
            "SANDBOX_BASE_VM_NAME": os.environ["SANDBOX_BASE_VM_NAME"],
            "SANDBOX_LIMA_HELPER_PATH":
                "/usr/local/libexec/sandboxd-test/sandbox-lima-helper",
            # Override the guest-agent binary path so the test lima-helper
            # (built with --features test-env-override) copies the staged
            # debug build into the VM instead of looking for the prod install.
            # Staged alongside sandboxd so the sandbox user / lima-helper can
            # read it without traversing the operator's 0750 home.
            "SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH":
                str(staged["sandbox_guest"]),
        },
        stdout=stdout_fh,
        stderr=stderr_fh,
    )

    def _is_dead() -> tuple[bool, str]:
        rc = proc.poll()
        if rc is None:
            return (False, "")
        return (True, f"sandboxd exited rc={rc}")

    try:
        _wait_for_daemon_socket(
            _SANDBOX_PROD_SOCKET, _is_dead, DAEMON_STARTUP_TIMEOUT,
        )
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        stdout_fh.close()
        stderr_fh.close()
        shutil.rmtree(staged["dir"], ignore_errors=True)
        try:
            stderr_text = stderr_log.read_text()
        except OSError:
            stderr_text = "(could not read stderr log)"
        print(
            f"sandboxd-via-sudo startup failed.\n"
            f"stderr: {stderr_text}",
            file=sys.stderr,
        )
        raise

    return {
        "socket": str(_SANDBOX_PROD_SOCKET),
        "base_dir": str(_SANDBOX_PROD_BASE_DIR),
        "process": proc,
        "_stdout_fh": stdout_fh,
        "_stderr_fh": stderr_fh,
        "_stdout_log": stdout_log,
        "_stderr_log": stderr_log,
        "_stage_dir": staged["dir"],
        "_staged_sandboxd": staged["sandboxd"],
    }


def restart_test_daemon(
    sandbox_daemon: dict,
    sandbox_binaries: SandboxBinaries,
    *,
    ready_timeout: float = 15,
) -> subprocess.Popen:
    """Restart the daemon mid-test as the ``sandbox`` user via ``sudo -u sandbox``.

    Used by the restart-recovery e2e tests (``test_networking::
    test_daemon_restart_recovery``, ``test_lite::
    test_lite_orphan_cleanup_on_daemon_restart``, ``test_policy_persistence::
    test_policy_persists_across_daemon_restart``). All three tests
    SIGKILL the daemon first to assert state-reconciliation behaviour
    that depends on no graceful shutdown happening; this helper handles
    the *restart* leg and the in-place re-registration into
    ``sandbox_daemon`` so the session-scoped fixture stays coherent.

    Re-spawns ``sudo -n -u sandbox sandboxd`` against the same socket
    and base-dir. Reuses the session-scope log files (the session teardown
    reads them via the existing ``_stdout_log``/``_stderr_log`` keys);
    append-mode so the per-test dump fixture's offset book-keeping still
    works.

    Callers are expected to register the returned ``Popen`` into
    ``sandbox_daemon["process"]`` before returning, so the session-scoped
    teardown operates on the live daemon. The helper does not do this
    automatically because the tests need the returned handle accessible to
    their per-test cleanup ``finally`` blocks.
    """
    socket_path = sandbox_daemon["socket"]
    base_dir = sandbox_daemon["base_dir"]
    stdout_log = sandbox_daemon["_stdout_log"]
    stderr_log = sandbox_daemon["_stderr_log"]
    new_stdout_fh = open(stdout_log, "a")
    new_stderr_fh = open(stderr_log, "a")

    # Relaunch from the same staged binary the session launcher used (the
    # sandbox user cannot exec the workspace build under the operator's
    # 0750 home — see _stage_binaries_for_sandbox_user). Mirror the
    # launcher's lima-helper env so the restarted daemon is configured
    # identically to the one it replaces.
    staged_sandboxd = sandbox_daemon["_staged_sandboxd"]
    staged_guest = Path(staged_sandboxd).parent / "sandbox-guest"
    daemon_env = os.environ.copy()
    daemon_env["SANDBOX_USERS_CONF"] = os.environ["SANDBOX_USERS_CONF"]
    daemon_env["SANDBOX_BASE_VM_NAME"] = os.environ["SANDBOX_BASE_VM_NAME"]
    daemon_env["SANDBOX_LIMA_HELPER_PATH"] = \
        "/usr/local/libexec/sandboxd-test/sandbox-lima-helper"
    daemon_env["SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH"] = str(staged_guest)

    proc = subprocess.Popen(
        [
            "sudo", "-n", "-u", "sandbox",
            str(staged_sandboxd),
            "--socket", str(socket_path),
            "--base-dir", str(base_dir),
        ],
        env=daemon_env,
        stdout=new_stdout_fh,
        stderr=new_stderr_fh,
    )

    try:
        wait_for_daemon_ready(socket_path, proc, ready_timeout)
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        new_stdout_fh.close()
        new_stderr_fh.close()
        raise

    # Stash the new file-handles on the proc itself so the test's
    # finally-block can re-register them into sandbox_daemon alongside
    # the new process handle. ``Popen`` objects accept attribute
    # assignment.
    proc._sandbox_stdout_fh = new_stdout_fh  # type: ignore[attr-defined]
    proc._sandbox_stderr_fh = new_stderr_fh  # type: ignore[attr-defined]
    return proc


def _purge_sessions_via_api(socket_path: str) -> None:
    """Delete every session known to the daemon via the HTTP API.

    Used during teardown so the next pytest session boots against a clean
    DB. Sessions left behind would survive a daemon restart and corrupt the
    next session. Best-effort: any failure is logged but does not block
    teardown — the dir-wipe at the start of the next session handles the
    cold-state case.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(socket_path)
            s.sendall(
                b"GET /sessions HTTP/1.1\r\n"
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
        _, _, body = raw.partition(b"\r\n\r\n")
        text = body.decode("utf-8", errors="replace")
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            return
        sessions = json.loads(text[start : end + 1])
    except (OSError, json.JSONDecodeError):
        return

    for entry in sessions:
        if not isinstance(entry, dict):
            continue
        sid = entry.get("id") or entry.get("session_id")
        if not sid:
            continue
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(60.0)
                s.connect(socket_path)
                s.sendall(
                    f"DELETE /sessions/{sid} HTTP/1.1\r\n"
                    f"Host: localhost\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
                # Drain.
                while s.recv(4096):
                    pass
        except OSError:
            pass


@pytest.fixture(scope="session")
def sandbox_daemon(sandbox_binaries: SandboxBinaries, tmp_path_factory: pytest.TempPathFactory):
    """Start a sandboxd instance for the test session.

    Session-scoped: all tests share the same daemon process.

    Launches the daemon as the ``sandbox`` system user via
    ``sudo -u sandbox``. All sudo is pre-authorized at
    ``make setup-dev-env`` time via the NOPASSWD fragment at
    ``/etc/sudoers.d/sandboxd-test``; no runtime root sudo is ever issued.

    Yields a dict with:
      - ``socket``       — path to the daemon's unix socket
      - ``base_dir``     — daemon's base directory
      - ``process``      — subprocess.Popen for the running daemon
      - ``_stdout_log``, ``_stderr_log`` — log file paths
      - ``_stdout_fh``,  ``_stderr_fh``  — open writers on the above

    Tears down the daemon (SIGTERM), purges any sessions left behind via
    the daemon HTTP API, then force-deletes any Lima VMs / Docker containers
    / networks that leaked during the session as a final safety net.
    """
    tmp_path = tmp_path_factory.mktemp("sandboxd")
    info = _launch_daemon_as_sandbox_via_sudo(sandbox_binaries, tmp_path)

    yield info

    # --- Teardown ---

    # Best-effort: purge sessions via API before stopping the daemon so
    # the next pytest session boots against a clean DB. The dir-wipe at
    # the start of the next session catches anything that survives this.
    try:
        _purge_sessions_via_api(info["socket"])
    except Exception:
        pass

    # Close daemon log file handles.  Use the current handles from info
    # because restart_test_daemon may have swapped them out.
    try:
        info["_stdout_fh"].close()
    except Exception:
        pass
    try:
        info["_stderr_fh"].close()
    except Exception:
        pass

    # Remove the /tmp staging dir holding the daemon/guest binaries.
    try:
        shutil.rmtree(info["_stage_dir"], ignore_errors=True)
    except Exception:
        pass

    # Collect any Lima VM names from the daemon's session db so we can
    # clean them up even if the test forgot to `rm`. The daemon owns its
    # Lima registry at ``/var/lib/sandboxd/<op-uid>/lima/`` (the
    # per-operator LIMA_HOME); bare ``limactl`` would look in ``~/.lima/``
    # and see nothing. We set LIMA_HOME to the per-operator path so the
    # list/delete calls reach the right registry. The per-operator LIMA_HOME
    # is owned by the operator uid (operator-private, 0600/0700), so we run
    # limactl directly as the test operator — no ``sudo -n -u sandbox``
    # prefix, which would hit EACCES on the operator-owned files.
    op_uid = os.getuid()
    op_lima_home = f"/var/lib/sandboxd/{op_uid}/lima"
    limactl_argv_prefix: list[str] = [
        "env", f"LIMA_HOME={op_lima_home}",
        "limactl",
    ]

    vm_names_to_clean: list[str] = []
    try:
        lima_output = subprocess.run(
            limactl_argv_prefix + ["list", "--json"],
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

    # Force-delete any leftover VMs through the same prefix so we
    # actually mutate the daemon-owned registry under cross-user.
    for vm_name in vm_names_to_clean:
        try:
            subprocess.run(
                limactl_argv_prefix + ["delete", "--force", vm_name],
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


# Per-test dump-window caps: keep failure output bounded even when a test
# generates a torrent of daemon logs.
_DUMP_MAX_LINES = 4000
_DUMP_MAX_BYTES = 1 << 20  # 1 MiB


def _capture_log_offset(path: Path) -> int:
    """Return current size of ``path``, or 0 if it doesn't exist yet."""
    try:
        return os.path.getsize(path)
    except FileNotFoundError:
        return 0


def _read_log_window(path: Path, start_offset: int) -> tuple[str, int, int]:
    """Read ``path`` from ``start_offset`` to EOF.

    Returns ``(text, effective_start, end)`` where ``effective_start`` may
    differ from ``start_offset`` if the file shrunk (rotation/truncation),
    in which case we read from 0. Caps the returned text at
    ``_DUMP_MAX_LINES`` lines / ``_DUMP_MAX_BYTES`` bytes from the tail of
    the window, prefixing a ``(truncated)`` marker when capped.
    """
    try:
        end = os.path.getsize(path)
    except FileNotFoundError:
        return ("(log file does not exist)", start_offset, start_offset)

    effective_start = start_offset if end >= start_offset else 0
    try:
        with open(path, "rb") as f:
            f.seek(effective_start)
            window = f.read(end - effective_start)
    except OSError as e:
        return (f"(could not read {path}: {e})", effective_start, end)

    text = window.decode("utf-8", errors="replace")
    truncated = False
    if len(window) > _DUMP_MAX_BYTES:
        text = text[-_DUMP_MAX_BYTES:]
        truncated = True
    lines = text.splitlines()
    if len(lines) > _DUMP_MAX_LINES:
        lines = lines[-_DUMP_MAX_LINES:]
        truncated = True
    if truncated:
        lines.insert(0, "(truncated)")
    return ("\n".join(lines), effective_start, end)


@pytest.fixture(autouse=True)
def _dump_daemon_log_on_failure(request, sandbox_daemon):
    """Print the per-test window of sandboxd's stderr+stdout on failure.

    Captures ``os.path.getsize`` of each log before the test runs and, on
    failure, emits exactly the bytes appended during the test body — not
    the last 100 lines of the whole-session log, which conflate output
    from earlier tests (and from the restarted daemon spawned by
    ``test_daemon_restart_recovery``, which deliberately writes to the
    same log paths).

    The daemon runs as the ``sandbox`` user via ``sudo -u sandbox`` and
    writes its stdout/stderr to the per-session log files at
    ``_stdout_log``/``_stderr_log`` in ``sandbox_daemon``.

    Driven by the per-phase outcome stashed by ``pytest_runtest_makereport``.
    Only fires when ``rep_call`` (the test body) failed — setup/teardown
    failures get reported separately and rarely correlate with daemon logs.

    The file window is capped at ``_DUMP_MAX_LINES`` / ``_DUMP_MAX_BYTES``
    from the tail with a ``(truncated)`` marker; if the file shrank
    during the test (rotation), the dump falls back to reading from offset 0.

    Depends on ``sandbox_daemon`` (session-scoped) so every test that uses
    a daemon — directly or transitively — gets the dump for free. Tests
    that don't request the daemon at all still pull this fixture (it's
    autouse), but ``sandbox_daemon`` will only spin up the actual process
    on first request from any test, so the cost is just two ``stat`` calls
    plus, on failure, two bounded reads.
    """
    offsets = {
        key: _capture_log_offset(sandbox_daemon[key])
        for _, key in (("stderr", "_stderr_log"), ("stdout", "_stdout_log"))
    }
    yield
    rep = getattr(request.node, "rep_call", None)
    if rep is None or not rep.failed:
        return
    for label, key in (("stderr", "_stderr_log"), ("stdout", "_stdout_log")):
        path = sandbox_daemon[key]
        text, eff_start, end = _read_log_window(path, offsets[key])
        print(
            f"\n=== sandboxd {label} "
            f"(test window bytes [{eff_start}, {end}), from {path}) ===\n"
            f"{text}\n"
            f"=== end sandboxd {label} ===\n",
            file=sys.stderr,
        )


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


def _lima_available_for_prewarm() -> bool:
    """Return True if the host can plausibly build a Lima base image.

    Mirrors the prereq probes in ``_lima_required_for_lima_tests`` but
    at session scope: when limactl is not installed, qemu-bridge-helper
    is missing, or the bridge.conf is absent, there is no point burning
    ten minutes of session-fixture setup on a doomed download — every
    Lima-marked test will skip downstream anyway. Container tests can
    still run.
    """
    try:
        subprocess.run(
            ["limactl", "--version"],
            capture_output=True, timeout=15, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
    if _find_qemu_bridge_helper() is None:
        return False
    if not BRIDGE_CONF_PATH.exists():
        return False
    return True


@pytest.fixture(scope="session", autouse=True)
def _ensure_base_image(sandbox_binaries: SandboxBinaries, sandbox_daemon):
    """Pre-warm the golden base image once per test session.

    This runs ``sandbox rebuild-image`` so that tests using clone-based
    creation (without ``--no-cache``) have a base image available. With
    HTTPS apt sources and fast timeout config, the container rebuild
    typically completes in ~30 s; the Lima rebuild downloads a ~580 MiB
    cloud-image qcow2 on first use and can take anywhere from 60 s on a
    fast mirror to 10+ minutes on slow-network hosts.

    Why session-scoped autouse — and why this fixture is load-bearing:

    The pytest-timeout ``--timeout`` flag applies to test items and
    per-test setup, but **not** to session-scoped fixture setup. So by
    forcing this rebuild to land at session start (autouse, before any
    test runs) the wall-clock cost of a slow base-image download does
    not consume any per-test budget. Without the autouse hoist this
    fixture would fire transitively from ``sandbox_cli`` the first time
    a test pulls it in, and a 600 s pytest-timeout on that test would
    end up racing the 580 MiB download — exactly the failure mode that
    M18-S9 unblocking work exists to eliminate.

    If the daemon reports the image is already ``fresh`` (e.g. a previous
    test run left a valid base VM on disk), the rebuild is skipped.

    Lima prereq probe: when limactl / qemu-bridge-helper / bridge.conf
    are absent, every Lima-marked test will skip via
    ``_lima_required_for_lima_tests``; rebuilding a Lima base image on
    such a host is wasted time. The container rebuild still runs.

    A Lima rebuild *failure* (as opposed to absent prereqs) is fatal: the
    pre-warm hoist exists specifically to make Lima-backed tests reliable;
    if the build fails here, the operator needs to know up front rather than
    watch every Lima test fail downstream with an opaque per-test timeout.
    The container rebuild is also fatal-on-failure.
    """
    socket_path = sandbox_daemon["socket"]

    status = _query_base_image_status(socket_path)
    if status == "fresh":
        print(
            "[conftest] base image already fresh; skipping pre-warm",
            file=sys.stderr,
        )
        return

    # Run the two backend rebuilds separately. The container rebuild is fast
    # (~30 s) and required; the Lima rebuild downloads a 580 MiB qcow2 on
    # first use and is required when Lima prereqs are present.
    print(
        "[conftest] pre-warming container base image",
        file=sys.stderr,
    )
    container_result = subprocess.run(
        [str(sandbox_binaries.sandbox), "--socket", socket_path,
         "rebuild-image", "--backend", "container"],
        capture_output=True,
        text=True,
        timeout=2000,
    )
    if container_result.returncode != 0:
        pytest.fail(
            "Failed to build container base image (exit "
            f"{container_result.returncode}).\n"
            f"stdout: {container_result.stdout}\n"
            f"stderr: {container_result.stderr}"
        )

    if not _lima_available_for_prewarm():
        print(
            "[conftest] skipping Lima base-image pre-warm — limactl / "
            "qemu-bridge-helper / bridge.conf not all present; every "
            "Lima-marked test will skip via "
            "_lima_required_for_lima_tests",
            file=sys.stderr,
        )
        return

    print(
        "[conftest] pre-warming Lima base image "
        "— downloads ~580 MiB cloud-image qcow2 on first use; this can "
        "take 1-10+ minutes depending on network throughput. Subsequent "
        "sessions reuse the cached image.",
        file=sys.stderr,
    )
    lima_result = subprocess.run(
        [str(sandbox_binaries.sandbox), "--socket", socket_path,
         "rebuild-image", "--backend", "lima"],
        capture_output=True,
        text=True,
        timeout=2000,
    )
    if lima_result.returncode != 0:
        # Fatal — the operator needs to see this up front rather than
        # learn about it from one Lima test at a time. With the pre-warm
        # hoist in place there is no legitimate "build the container
        # image so at least the container tests pass" fallback worth
        # absorbing the noise from.
        pytest.fail(
            "Failed to build Lima base image during session pre-warm "
            f"(exit {lima_result.returncode}). All Lima-marked tests "
            "will fail downstream until this is resolved. See "
            "docs/guides/troubleshooting.md for slow-network "
            "remediation.\n"
            f"stdout: {lima_result.stdout}\n"
            f"stderr: {lima_result.stderr}"
        )
    print(
        "[conftest] Lima base image pre-warm completed successfully",
        file=sys.stderr,
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
