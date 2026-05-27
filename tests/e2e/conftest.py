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
# Cross-user harness selection
# ---------------------------------------------------------------------------
#
# Three harness modes, selected at session start by the ``SANDBOX_HARNESS``
# environment variable:
#
# * ``"sandbox-systemd"`` (default) — Launch the daemon as the ``sandbox``
#   system user via systemd, using the production unit at
#   ``sandboxd/contrib/systemd/sandboxd.service``. The harness installs a
#   throw-away copy of the unit as ``sandboxd-test.service`` (to avoid
#   clobbering any production unit on the host) together with a drop-in
#   override that points ``ExecStart`` at the workspace's debug binary,
#   disables ``ProtectHome`` (the unit's hardening blocks reads of the
#   workspace binary and writes to ``/home/sandbox/.lima/`` — and the
#   cross-user Lima bug requires both), and threads through the test
#   harness's ``SANDBOX_USERS_CONF`` tempfile via ``Environment=``. Falls
#   back automatically to ``"sandbox-sudo"`` when systemd is not running
#   on the host (``/run/systemd/system`` missing).
#
# * ``"sandbox-sudo"`` — Launch the daemon as the ``sandbox`` system user
#   via ``sudo -u sandbox <test-binary>``. Used in environments without
#   systemd (CI containers, the install-e2e suite). Requires the NOPASSWD
#   sudoers fragment installed by ``make setup-test-sudoers-fragment``
#   (``/etc/sudoers.d/sandboxd-test``).
#
# * ``"test-user"`` — Legacy harness that launches the daemon as the
#   pytest process's own user with temp paths. Retained for the
#   diff-the-outcomes baseline run (see Spec § Phase 1 step 4) and as a
#   one-shot regression check until the harness flip is fully validated;
#   the production ``sandbox`` group's cross-user bug is invisible under
#   this harness because the daemon and the CLI share a uid.
#
# Both new modes require the operator to be a member of the ``sandbox``
# group (the daemon socket is mode 0660, group=sandbox). The harness
# asserts membership at start-up and fails loudly with a remediation
# message if not — group changes do **not** take effect in the current
# shell, so adding the operator to the group requires re-login or
# wrapping the test invocation in ``sg sandbox -c '…'``.
SANDBOX_HARNESS = os.environ.get("SANDBOX_HARNESS", "sandbox-systemd").strip()
_VALID_HARNESSES = {"sandbox-systemd", "sandbox-sudo", "test-user"}
if SANDBOX_HARNESS not in _VALID_HARNESSES:
    raise RuntimeError(
        f"SANDBOX_HARNESS={SANDBOX_HARNESS!r} is not one of "
        f"{sorted(_VALID_HARNESSES)}. Set SANDBOX_HARNESS=test-user for "
        f"the legacy daemon-as-test-user path; default is sandbox-systemd "
        f"(auto-falls-back to sandbox-sudo if systemd is unavailable)."
    )

# Resolve the systemd→sudo auto-fallback at module-import time so the
# fixture (and every test that prints the selected harness in its log
# output) sees a stable value. The check is intentionally narrow — we
# only require ``/run/systemd/system`` to exist and ``systemctl`` to be
# executable; we do not also probe ``systemctl is-system-running``
# because the host being in degraded state is fine as long as we can
# still issue ``systemctl daemon-reload`` and ``systemctl start``.
def _systemd_available() -> bool:
    if not Path("/run/systemd/system").exists():
        return False
    try:
        subprocess.run(
            ["systemctl", "--version"],
            capture_output=True, timeout=5, check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


if SANDBOX_HARNESS == "sandbox-systemd" and not _systemd_available():
    print(
        "[conftest] SANDBOX_HARNESS=sandbox-systemd requested but systemd "
        "is not available on this host; falling back to sandbox-sudo.",
        file=sys.stderr,
    )
    SANDBOX_HARNESS = "sandbox-sudo"

# Production-shaped paths used by both ``sandbox-systemd`` and
# ``sandbox-sudo``. Matches the systemd unit's ``ExecStart`` so the bug
# the harness is intended to reproduce — daemon-vs-CLI uid mismatch —
# does not get masked by an idiosyncratic per-test path layout.
_SANDBOX_PROD_SOCKET = Path("/run/sandbox/sandboxd.sock")
_SANDBOX_PROD_BASE_DIR = Path("/var/lib/sandbox")

# Test service name used by the sandbox-systemd path. Deliberately
# distinct from the production ``sandboxd.service`` so installing the
# harness does not silently overwrite an operator-curated production
# unit on the same host. The drop-in override lives at
# ``/etc/systemd/system/sandboxd-test.service.d/99-test.conf``.
_SANDBOXD_TEST_SERVICE = "sandboxd-test.service"
_SANDBOXD_TEST_UNIT_PATH = Path("/etc/systemd/system") / _SANDBOXD_TEST_SERVICE
_SANDBOXD_TEST_DROPIN_DIR = Path(
    f"/etc/systemd/system/{_SANDBOXD_TEST_SERVICE}.d"
)
_SANDBOXD_TEST_DROPIN_PATH = _SANDBOXD_TEST_DROPIN_DIR / "99-test.conf"

# Path of the source unit file in the workspace; the systemd path
# copies this to ``_SANDBOXD_TEST_UNIT_PATH`` with a single-word rename
# so the file's hardening and restart-policy stanzas match production.
_SANDBOXD_SOURCE_UNIT = (
    PROJECT_ROOT / "sandboxd" / "contrib" / "systemd" / "sandboxd.service"
)

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
    # ``allow_users`` lists the operator AND the ``sandbox`` system user
    # because, depending on SANDBOX_HARNESS, the daemon's effective uid
    # at startup is either the test operator's (test-user harness) or
    # the ``sandbox`` system user's (sandbox-systemd / sandbox-sudo).
    # The daemon's startup-time ``find_subnet_by_uid`` lookup requires
    # its own uid to appear in some pool's ``allow_users``; listing
    # both names keeps the same tempfile usable across all three
    # harnesses without re-rendering the JSON. Names that do not
    # resolve to a uid on a given host are silently skipped by the
    # daemon (Spec § users.conf — "unresolvable allow_users entries
    # are treated as non-matches"), so listing ``sandbox`` is a no-op
    # on hosts that have not provisioned the system user.
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
    # the ``sandbox`` system user under SANDBOX_HARNESS=sandbox-systemd
    # / sandbox-sudo can read the file (it lives under /tmp owned by
    # the test operator). The file lists only CIDR pool definitions
    # for the test daemon — no secrets — so widening to 0644 is safe.
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

    The new harness modes (``sandbox-systemd``, ``sandbox-sudo``) leave
    the daemon socket at mode 0660 with ``group=sandbox``. A test process
    whose effective groups do not include ``sandbox`` cannot read or
    write the socket and every CLI invocation fails with EACCES — which
    is the symptom the harness is meant to catch, but the cause is a
    setup gap, not the cross-user bug under test.

    Group changes from ``usermod -aG sandbox <operator>`` do **not** take
    effect in the current login session. The remediation depends on
    context:

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
            "SANDBOX_HARNESS={harness!r} requires the `sandbox` system "
            "group to exist on the host. Run `make setup-sandbox-user` "
            "from the workspace root and re-run the tests.".format(
                harness=SANDBOX_HARNESS
            )
        )
    if sandbox_gid in os.getgroups():
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
        f"SANDBOX_HARNESS={SANDBOX_HARNESS!r} requires the pytest process "
        f"to be a member of the 'sandbox' system group (the daemon's "
        f"unix socket is mode 0660, group=sandbox). {remediation}"
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
    ``(False, "")`` otherwise. The systemd-launched daemon does not
    expose a ``Popen`` for the harness to ``poll()`` (the daemon is a
    grandchild of systemd, not of the test process), so the readiness
    helper queries ``systemctl is-active`` via the callback instead.
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


class _SystemdDaemonHandle:
    """Stand-in for ``subprocess.Popen`` exposing the daemon process API.

    The systemd-launched daemon is a grandchild of systemd, not of the
    pytest process, so the harness cannot ``Popen`` it directly. The
    existing fixture API contract (``process.poll()``,
    ``process.terminate()``, ``process.wait(timeout=...)``,
    ``process.kill()``, ``process.returncode``) is implemented here in
    terms of ``systemctl`` commands so existing test code that pokes
    ``sandbox_daemon["process"]`` keeps working without change.

    The restart-recovery e2e tests use :func:`restart_test_daemon` to
    drive a harness-aware "kill the daemon, restart, hand it back to the
    session-scoped fixture" workflow. Under the systemd harness that
    routes through ``systemctl kill`` + ``systemctl start`` on this same
    handle (no ``Popen`` swap); under the test-user / sandbox-sudo
    harnesses it produces a fresh ``Popen``. Tests should not poke at
    ``systemctl`` directly — call :func:`restart_test_daemon` and let it
    dispatch on ``sandbox_daemon["_harness"]``.
    """

    def __init__(self, service: str):
        self._service = service
        self._returncode: int | None = None

    def _is_active(self) -> bool:
        # ``systemctl is-active`` exits 0 only while the unit is in
        # state "active"; "activating"/"inactive"/"failed"/"deactivating"
        # all exit non-zero.
        rc = subprocess.run(
            ["systemctl", "is-active", "--quiet", self._service],
            timeout=10,
        ).returncode
        return rc == 0

    def poll(self) -> int | None:
        if self._returncode is not None:
            return self._returncode
        if self._is_active():
            return None
        # Daemon stopped on its own (or never started). Best-effort fetch
        # the unit's exit status via ``systemctl show``; default to 1
        # when we cannot decode the field.
        out = subprocess.run(
            ["systemctl", "show", self._service, "-p", "ExecMainStatus"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        try:
            self._returncode = int(out.split("=", 1)[1]) if "=" in out else 1
        except (ValueError, IndexError):
            self._returncode = 1
        return self._returncode

    def terminate(self) -> None:
        if self.poll() is None:
            subprocess.run(
                ["sudo", "-n", "systemctl", "stop", self._service],
                capture_output=True, timeout=30,
            )
            self._returncode = 0

    def kill(self) -> None:
        # ``--kill-who=main`` to match :py:meth:`subprocess.Popen.kill`
        # — only the daemon process receives SIGKILL, not the cgroup
        # (see send_signal() for the full rationale).
        if self.poll() is None:
            subprocess.run(
                ["sudo", "-n", "systemctl", "kill",
                 "--kill-who=main", "-s", "SIGKILL",
                 self._service],
                capture_output=True, timeout=30,
            )
            self._returncode = -9

    def send_signal(self, sig: int) -> None:
        """Send ``sig`` to the unit's main process via ``systemctl kill``.

        Implements the same surface as :py:meth:`subprocess.Popen.send_signal`
        so the restart-recovery tests can ``daemon_proc.send_signal(SIGKILL)``
        on either flavour of handle without branching. ``systemctl kill``
        accepts the signal name (``SIGKILL``, ``SIGTERM``, ...) or the
        numeric form; we translate from the Python ``signal.SIG*``
        integer to a name for clarity in ``journalctl``.

        ``--kill-who=main`` is load-bearing: without it ``systemctl
        kill`` defaults to ``--kill-who=cgroup``, which delivers the
        signal to *every* process in the unit's cgroup — including the
        daemon's children (``limactl``, ``qemu-system-x86_64``, ``ssh``
        forwarders, ...). The restart-recovery tests are reproducing
        an abrupt daemon crash where the VM is expected to *survive*
        the kill and be recovered as Running after the daemon comes
        back; a cgroup-wide SIGKILL would also tear down QEMU and
        defeat that contract. ``--kill-who=main`` matches the kernel
        semantics of :py:meth:`subprocess.Popen.send_signal` — only
        the parent process receives the signal.

        Does *not* eagerly set ``_returncode`` — we leave that to the
        next ``poll()`` / ``wait()`` call, which queries ``systemctl
        show`` for the actual ``ExecMainStatus``. Setting it eagerly
        here would race with the kernel: ``systemctl kill`` only
        guarantees the signal has been *delivered* by the time it
        returns, not that the unit has transitioned to inactive.
        """
        if self.poll() is not None:
            return
        # Translate the int to its canonical SIG* name when possible;
        # fall back to the integer for exotic signals.
        try:
            import signal as _sig
            sig_name = _sig.Signals(sig).name
        except (ValueError, ImportError):
            sig_name = str(int(sig))
        subprocess.run(
            ["sudo", "-n", "systemctl", "kill",
             "--kill-who=main", "-s", sig_name,
             self._service],
            capture_output=True, timeout=30,
        )

    def wait(self, timeout: float | None = None) -> int:
        deadline = (
            None if timeout is None
            else time.monotonic() + float(timeout)
        )
        while self.poll() is None:
            if deadline is not None and time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(self._service, timeout)
            time.sleep(0.1)
        return self._returncode if self._returncode is not None else 0

    def reset_for_restart(self) -> None:
        """Forget the cached exit status so the next ``poll()`` re-evaluates
        the live unit.

        Called by :func:`restart_test_daemon` after re-starting the unit
        via ``systemctl start``; without this the handle would still
        report the pre-kill exit code.
        """
        self._returncode = None

    @property
    def returncode(self) -> int | None:
        return self._returncode


def _write_systemd_drop_in(
    sandbox_binaries: SandboxBinaries,
    users_conf_path: str,
    sandbox_base_vm_name: str,
) -> None:
    """Install the systemd unit and drop-in override at session start.

    The drop-in overrides three things from the production unit so the
    test daemon can:

    * Read the workspace's debug binary under ``/home/<operator>/...``
      (``ProtectHome=no``) — the production unit hardens this away.
    * Read the test harness's per-session ``SANDBOX_USERS_CONF``
      tempfile (which lives under ``/tmp`` and is therefore opaque to
      ``PrivateTmp=yes``) — set ``PrivateTmp=no``.
    * See the harness's chosen base-VM name and the test users.conf
      path via ``Environment=`` (the production unit inherits nothing
      from systemd's caller environment).

    The unit name (``sandboxd-test.service``, not ``sandboxd.service``)
    is deliberately distinct so a production install on the same host
    is untouched.
    """
    # ``sudo -n install -D`` would refuse the drop-in dir's automatic
    # creation on some sudoers configs; do it in two explicit steps
    # so the failure mode is obvious if the operator does not have
    # passwordless ``sudo install``/``mkdir`` available.
    subprocess.run(
        ["sudo", "-n", "install", "-d", "-m", "0755",
         str(_SANDBOXD_TEST_DROPIN_DIR)],
        check=True, capture_output=True, timeout=10,
    )

    # Copy the in-tree production unit verbatim to the test unit path.
    # The unit's ``User=sandbox``, ``Group=sandbox``,
    # ``StateDirectory=sandbox``, and ``RuntimeDirectory=sandbox``
    # stanzas all describe the production posture we want to reproduce;
    # the drop-in below overrides only the parts that must be relaxed
    # for the test binary to be readable.
    if not _SANDBOXD_SOURCE_UNIT.exists():
        pytest.fail(
            f"systemd source unit not found at {_SANDBOXD_SOURCE_UNIT}; "
            f"cannot launch the daemon under SANDBOX_HARNESS=sandbox-systemd."
        )
    subprocess.run(
        ["sudo", "-n", "install", "-m", "0644",
         str(_SANDBOXD_SOURCE_UNIT), str(_SANDBOXD_TEST_UNIT_PATH)],
        check=True, capture_output=True, timeout=10,
    )

    # ``ExecStart=`` (empty) before the new ``ExecStart=`` directive
    # is required by systemd to clear the inherited value before
    # appending the new one; otherwise systemd refuses the unit with
    # "Service has more than one ExecStart= setting".
    drop_in = textwrap.dedent(
        f"""\
        # Managed by tests/e2e/conftest.py (cross-user harness).
        # Do not edit by hand — `make setup-dev-env` does not touch
        # this file, but every pytest session re-installs it.
        [Service]
        # Clear inherited ExecStart before re-defining; systemd otherwise
        # rejects the unit for having multiple ExecStart directives.
        ExecStart=
        ExecStart={sandbox_binaries.sandboxd} \\
            --base-dir {_SANDBOX_PROD_BASE_DIR} \\
            --socket {_SANDBOX_PROD_SOCKET}
        # Relax ProtectHome so the daemon can read its own binary under
        # /home/<operator>/Projects/.../sandboxd/target/debug/sandboxd
        # AND write Lima VMs under /var/lib/sandbox/.lima/ (which is the
        # sandbox user's home, but treated by systemd as "home-like").
        ProtectHome=no
        # Relax PrivateTmp so the daemon can read the harness's
        # SANDBOX_USERS_CONF tempfile (it lives under /tmp owned by the
        # test operator).
        PrivateTmp=no
        # Reset UMask back to a sane default. The production unit pins
        # UMask=0117 as defence-in-depth for the unix socket's 0660 mode;
        # but that same UMask makes Lima's auto-created
        # ``$HOME/.lima/<vm>/`` directories land at 0660 (no execute bit),
        # so a follow-up ``limactl create`` call sees ``EACCES`` opening
        # ``lima.yaml`` inside it and reports the misleading
        # ``instance "sandbox-test-base" already exists``. The daemon
        # explicitly chmods the socket to 0660 after bind regardless, so
        # losing the UMask hardening here is no-op for the socket's
        # security posture.
        UMask=0022
        # Allow privilege elevation in spawned children. The daemon
        # itself is unprivileged, but it execs ``sandbox-route-helper``
        # which carries file capabilities (``cap_net_admin,
        # cap_sys_admin=eip``) to perform per-session ``setns(2)`` and
        # ``RTM_NEWROUTE`` operations. The production unit pins
        # ``NoNewPrivileges=yes`` defensively, but that flag blocks the
        # kernel from honouring file caps on a ``execve(2)`` — the
        # route helper would then fail with ``EPERM`` on the first
        # ``setns`` call. The harness reverts to ``no`` so the cap'd
        # helper still works; the daemon binary itself remains
        # unprivileged.
        NoNewPrivileges=no
        # Reset DeviceAllow back to "allow everything". The production
        # unit pins ``DeviceAllow=/dev/kvm rw`` so the daemon's cgroup
        # only sees ``/dev/kvm``; but QEMU (spawned via ``limactl
        # start``) also needs ``/dev/net/tun`` (TAP for bridged
        # networking), ``/dev/random``/``/dev/urandom``, and several
        # other character devices — without them QEMU exits with
        # status 1 before opening its QMP socket and Lima reports
        # ``Driver stopped due to error: exit status 1`` with no
        # actionable detail. Resetting (empty list overrides the
        # inherited setting; ``DeviceAllow=`` with no arg clears any
        # previous ``DeviceAllow=`` directives) keeps the harness on
        # the production-shaped path everywhere except this one knob
        # that breaks QEMU.
        DeviceAllow=
        # Thread test-harness env-vars through to the daemon.
        Environment="SANDBOX_USERS_CONF={users_conf_path}"
        Environment="SANDBOX_BASE_VM_NAME={sandbox_base_vm_name}"
        # Disable Restart= so a daemon that crashes mid-test stays down
        # and the test fails with a clear "daemon exited" diagnostic
        # rather than mysteriously coming back up.
        Restart=no
        # ``KillMode=process`` so a ``systemctl kill`` (and the
        # eventual main-process exit it triggers) leaves the daemon's
        # children alone — most importantly QEMU and limactl
        # forwarders that own per-session VMs. The default
        # ``KillMode=control-group`` would propagate SIGTERM/SIGKILL
        # to every process in the cgroup once the main process dies,
        # which the restart-recovery tests cannot tolerate: they
        # SIGKILL the daemon and then assert the surviving VM is
        # recovered as Running once the daemon comes back up.
        # Matches the semantics of ``Popen.send_signal`` /
        # ``Popen.kill`` from the legacy test-user harness.
        KillMode=process
        """
    )
    # Stage to a tempfile in /tmp the operator can write, then
    # ``sudo install`` into place. Skipping the visudo-equivalent
    # ``systemd-analyze verify`` step here would let a malformed unit
    # land in /etc/systemd/system/; do not paper over that.
    tf = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".conf",
        prefix="sandboxd-test-dropin-",
        delete=False,
    )
    try:
        tf.write(drop_in)
        tf.flush()
        tf.close()
        subprocess.run(
            ["sudo", "-n", "install", "-m", "0644",
             tf.name, str(_SANDBOXD_TEST_DROPIN_PATH)],
            check=True, capture_output=True, timeout=10,
        )
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass

    subprocess.run(
        ["sudo", "-n", "systemd-analyze", "verify", _SANDBOXD_TEST_SERVICE],
        capture_output=True, timeout=15,
    )
    # ``systemd-analyze verify`` exits 0 with warnings, non-zero on
    # outright load failures. Re-running ``daemon-reload`` after every
    # drop-in install is required — systemd caches the previous unit
    # graph in-memory between reloads.
    subprocess.run(
        ["sudo", "-n", "systemctl", "daemon-reload"],
        check=True, capture_output=True, timeout=10,
    )


def _reset_sandbox_state_dir() -> None:
    """Wipe ``/var/lib/sandbox`` between pytest sessions, preserving the
    Lima base-image cache and the golden base VM.

    The systemd unit's ``StateDirectory=sandbox`` re-creates the dir
    on the next start with the right ownership and mode; we just need
    the daemon-managed state (``sessions.db``, per-session subdirs,
    gateway-container artefacts, etc.) gone so a fresh ``sessions.db``
    lands.

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
    if not _SANDBOX_PROD_BASE_DIR.exists():
        return
    # ``find ... -prune`` excludes both kept paths from the delete
    # sweep. ``-mindepth 1`` keeps the base dir itself intact (its
    # mode and ownership come from the systemd unit's
    # ``StateDirectory=`` directive and we do not want to recreate
    # them on every run). The two pruned trees stay byte-for-byte
    # identical across reset, which is exactly what the pre-warm
    # fixture's "is the image fresh?" check needs to short-circuit.
    cache_dir = str(_SANDBOX_PROD_BASE_DIR / ".cache" / "lima")
    base_vm_dir = str(
        _SANDBOX_PROD_BASE_DIR / ".lima" /
        os.environ.get("SANDBOX_BASE_VM_NAME", "sandbox-test-base")
    )
    meta_file = str(_SANDBOX_PROD_BASE_DIR / "base-image-meta.json")
    subprocess.run(
        [
            "sudo", "-n", "find", str(_SANDBOX_PROD_BASE_DIR),
            "-mindepth", "1",
            # Order matters: the prunes go first, then the delete
            # branch. ``find`` evaluates left-to-right with implicit
            # ``-and``; once ``-prune`` succeeds it short-circuits
            # the rest, so the pruned subtree is never visited for
            # deletion.
            "(",
            "-path", cache_dir,
            "-o", "-path", base_vm_dir,
            "-o", "-path", meta_file,
            ")",
            "-prune",
            "-o", "-delete",
        ],
        capture_output=True, timeout=30,
    )


def _launch_daemon_as_sandbox_via_systemd(
    sandbox_binaries: SandboxBinaries,
    tmp_path: Path,
) -> dict:
    """Start the daemon as the ``sandbox`` user via systemd.

    The unit and drop-in override are written/refreshed every pytest
    session — see :func:`_write_systemd_drop_in` for what gets
    overridden and why. State is wiped before the start so each
    session begins from a clean DB.
    """
    _assert_operator_in_sandbox_group()
    _write_systemd_drop_in(
        sandbox_binaries=sandbox_binaries,
        users_conf_path=os.environ["SANDBOX_USERS_CONF"],
        sandbox_base_vm_name=os.environ["SANDBOX_BASE_VM_NAME"],
    )
    _reset_sandbox_state_dir()

    # Stop any prior instance from a previous (possibly crashed)
    # pytest session before we daemon-reload + start. ``stop`` on
    # an inactive unit is a no-op exit 0.
    subprocess.run(
        ["sudo", "-n", "systemctl", "stop", _SANDBOXD_TEST_SERVICE],
        capture_output=True, timeout=30,
    )
    subprocess.run(
        ["sudo", "-n", "systemctl", "reset-failed", _SANDBOXD_TEST_SERVICE],
        capture_output=True, timeout=10,
    )
    start = subprocess.run(
        ["sudo", "-n", "systemctl", "start", _SANDBOXD_TEST_SERVICE],
        capture_output=True, text=True, timeout=30,
    )
    if start.returncode != 0:
        # Dump journalctl so the failure is actionable.
        journal = subprocess.run(
            ["sudo", "-n", "journalctl", "-u", _SANDBOXD_TEST_SERVICE,
             "--no-pager", "-n", "200"],
            capture_output=True, text=True, timeout=15,
        )
        pytest.fail(
            "Failed to start sandboxd via systemd "
            f"(rc={start.returncode}).\n"
            f"systemctl stdout: {start.stdout}\n"
            f"systemctl stderr: {start.stderr}\n"
            f"journalctl tail:\n{journal.stdout}\n{journal.stderr}"
        )

    handle = _SystemdDaemonHandle(_SANDBOXD_TEST_SERVICE)

    # Per-session log files live under the harness's tmp_path so the
    # existing _dump_daemon_log_on_failure plumbing keeps working
    # without touching every test that reads ``_stdout_log``/
    # ``_stderr_log``. Under systemd the daemon's output goes to the
    # journal, so the "log file" is the on-disk projection of
    # journalctl --since=<session start>.
    stdout_log = tmp_path / "sandboxd.stdout.log"
    stderr_log = tmp_path / "sandboxd.stderr.log"
    stdout_log.touch()
    stderr_log.touch()
    stdout_fh = open(stdout_log, "a")
    stderr_fh = open(stderr_log, "a")

    def _is_dead() -> tuple[bool, str]:
        rc = handle.poll()
        if rc is None:
            return (False, "")
        # Daemon exited; dump the journal so the failure path emits
        # something actionable.
        journal = subprocess.run(
            ["sudo", "-n", "journalctl", "-u", _SANDBOXD_TEST_SERVICE,
             "--no-pager", "-n", "200"],
            capture_output=True, text=True, timeout=15,
        ).stdout
        return (True, f"systemd unit exited rc={rc}; journal tail:\n{journal}")

    try:
        _wait_for_daemon_socket(
            _SANDBOX_PROD_SOCKET, _is_dead, DAEMON_STARTUP_TIMEOUT,
        )
    except BaseException:
        # Tear the unit down so a half-started instance does not
        # leak into the next session.
        subprocess.run(
            ["sudo", "-n", "systemctl", "stop", _SANDBOXD_TEST_SERVICE],
            capture_output=True, timeout=30,
        )
        stdout_fh.close()
        stderr_fh.close()
        raise

    return {
        "socket": str(_SANDBOX_PROD_SOCKET),
        "base_dir": str(_SANDBOX_PROD_BASE_DIR),
        "process": handle,
        "_stdout_fh": stdout_fh,
        "_stderr_fh": stderr_fh,
        "_stdout_log": stdout_log,
        "_stderr_log": stderr_log,
        "_harness": "sandbox-systemd",
    }


def _launch_daemon_as_sandbox_via_sudo(
    sandbox_binaries: SandboxBinaries,
    tmp_path: Path,
) -> dict:
    """Start the daemon as the ``sandbox`` user via ``sudo -u sandbox``.

    Used in environments without systemd (CI containers, install-e2e
    suites that exercise a non-systemd Linux). Requires the NOPASSWD
    sudoers fragment at ``/etc/sudoers.d/sandboxd-test`` (installed by
    ``make setup-test-sudoers-fragment``); a missing fragment causes
    sudo to silently prompt and hang the wait-for-socket deadline, so
    the harness probes for it up front and fails with a precise error.
    """
    _assert_operator_in_sandbox_group()

    # Probe NOPASSWD authorisation. ``sudo -n -u sandbox true`` returns
    # rc=1 with "a password is required" on stderr when the fragment
    # is missing; rc=0 when the fragment grants the operator passwordless
    # sandbox access. We probe with the binary path (not ``true``)
    # because the fragment whitelists only the test binary — using a
    # different command would falsely report "not allowed" when in fact
    # the fragment is fine.
    probe = subprocess.run(
        ["sudo", "-n", "-u", "sandbox",
         str(sandbox_binaries.sandboxd), "--version"],
        capture_output=True, text=True, timeout=10,
    )
    if probe.returncode != 0:
        pytest.fail(
            "SANDBOX_HARNESS=sandbox-sudo requires a NOPASSWD sudoers "
            "fragment authorising the test operator to run the "
            "workspace's debug sandboxd binary as the `sandbox` user. "
            "Run `make setup-test-sudoers-fragment` from the workspace "
            "root and re-run.\n"
            f"sudo probe stderr: {probe.stderr.strip()!r}"
        )

    _reset_sandbox_state_dir()

    # Re-create the production state and runtime dirs owned by sandbox
    # so the daemon can write into them. ``install -d`` is idempotent
    # against an already-correct dir; ``-o sandbox -g sandbox`` is the
    # production ownership the systemd unit's ``StateDirectory=`` and
    # ``RuntimeDirectory=`` would otherwise create.
    for d in (_SANDBOX_PROD_BASE_DIR, _SANDBOX_PROD_SOCKET.parent):
        subprocess.run(
            ["sudo", "-n", "install", "-d", "-o", "sandbox", "-g", "sandbox",
             "-m", "0750", str(d)],
            check=True, capture_output=True, timeout=10,
        )

    stdout_log = tmp_path / "sandboxd.stdout.log"
    stderr_log = tmp_path / "sandboxd.stderr.log"
    stdout_fh = open(stdout_log, "w")
    stderr_fh = open(stderr_log, "w")

    daemon_env = os.environ.copy()
    # The sudoers fragment installed by
    # ``make setup-test-sudoers-fragment`` declares
    # ``env_keep += "SANDBOX_USERS_CONF SANDBOX_BASE_VM_NAME SANDBOX_SOCKET"``
    # for this specific binary, so the variables propagate through sudo
    # without ``--preserve-env`` (which itself would also have to be
    # whitelisted by sudoers and is more brittle).
    proc = subprocess.Popen(
        [
            "sudo", "-n", "-u", "sandbox",
            str(sandbox_binaries.sandboxd),
            "--socket", str(_SANDBOX_PROD_SOCKET),
            "--base-dir", str(_SANDBOX_PROD_BASE_DIR),
        ],
        env={
            **daemon_env,
            "SANDBOX_USERS_CONF": os.environ["SANDBOX_USERS_CONF"],
            "SANDBOX_BASE_VM_NAME": os.environ["SANDBOX_BASE_VM_NAME"],
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
        "_harness": "sandbox-sudo",
    }


def _launch_daemon_as_test_user(
    sandbox_binaries: SandboxBinaries,
    tmp_path: Path,
) -> dict:
    """Legacy harness: launch the daemon as the test process's own user.

    Identical to the historical pre-cross-user-harness path. Retained
    for the diff-the-outcomes baseline run; the cross-user Lima bug
    the spec is reproducing is invisible under this harness because
    the daemon and the operator's CLI share a uid.
    """
    socket_path = tmp_path / "sandboxd.sock"
    base_dir = tmp_path / "state"
    base_dir.mkdir(parents=True, exist_ok=True)

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

    def _is_dead() -> tuple[bool, str]:
        rc = proc.poll()
        if rc is None:
            return (False, "")
        return (True, f"sandboxd exited rc={rc}")

    try:
        _wait_for_daemon_socket(socket_path, _is_dead, DAEMON_STARTUP_TIMEOUT)
    except BaseException:
        if proc.poll() is None:
            proc.kill()
        stdout_fh.close()
        stderr_fh.close()
        try:
            stderr_text = stderr_log.read_text()
        except OSError:
            stderr_text = "(could not read stderr log)"
        print(
            f"sandboxd-as-test-user startup failed.\n"
            f"stderr: {stderr_text}",
            file=sys.stderr,
        )
        raise

    return {
        "socket": str(socket_path),
        "base_dir": str(base_dir),
        "process": proc,
        "_stdout_fh": stdout_fh,
        "_stderr_fh": stderr_fh,
        "_stdout_log": stdout_log,
        "_stderr_log": stderr_log,
        "_harness": "test-user",
    }


def restart_test_daemon(
    sandbox_daemon: dict,
    sandbox_binaries: SandboxBinaries,
    *,
    ready_timeout: float = 15,
) -> "subprocess.Popen | _SystemdDaemonHandle":
    """Harness-aware "restart the daemon mid-test" helper.

    Used by the restart-recovery e2e tests (``test_networking::
    test_daemon_restart_recovery``, ``test_lite::
    test_lite_orphan_cleanup_on_daemon_restart``, ``test_policy_persistence::
    test_policy_persists_across_daemon_restart``). All three tests
    SIGKILL the daemon first to assert state-reconciliation behaviour
    that depends on no graceful shutdown happening; this helper handles
    the *restart* leg and the in-place re-registration into
    ``sandbox_daemon`` so the session-scoped fixture stays coherent.

    Dispatch on ``sandbox_daemon["_harness"]``:

    * **sandbox-systemd** — Re-start the unit via ``sudo systemctl
      start <unit>``, reset the cached exit-code on the existing
      :class:`_SystemdDaemonHandle`, wait for the socket to come back
      up, and return the *same* handle (no swap). The session-scope
      fixture's teardown closes ``info["_stdout_fh"]``/``_stderr_fh``
      so we leave those alone — under systemd the daemon's output
      goes to the journal anyway, and tests dumping logs on failure
      should use :func:`journalctl_for_test_window` instead of the
      log-file path.

    * **sandbox-sudo** — Re-spawn the daemon as the ``sandbox`` user via
      ``sudo -n -u sandbox sandboxd``, returning the fresh
      :class:`subprocess.Popen`. Tests re-register it into
      ``sandbox_daemon["process"]``.

    * **test-user** — Re-spawn the daemon as the test process's own
      user, returning the fresh ``Popen``. Identical to the legacy
      Popen-swap pattern.

    Callers are expected to register the returned handle into
    ``sandbox_daemon["process"]`` before returning, so the session-
    scoped teardown operates on the live daemon. The helper does not
    do this automatically because the tests need the returned handle
    accessible to their per-test cleanup ``finally`` blocks.
    """
    harness = sandbox_daemon.get("_harness", "test-user")
    socket_path = sandbox_daemon["socket"]
    base_dir = sandbox_daemon["base_dir"]

    if harness == "sandbox-systemd":
        handle = sandbox_daemon["process"]
        if not isinstance(handle, _SystemdDaemonHandle):
            pytest.fail(
                "restart_test_daemon: harness=sandbox-systemd but "
                f"sandbox_daemon['process'] is {type(handle).__name__}, "
                "expected _SystemdDaemonHandle"
            )
        # Best-effort reset of any "failed" state from the SIGKILL the
        # test issued; ``systemctl start`` on a unit in failed state
        # without ``reset-failed`` will refuse to re-start.
        subprocess.run(
            ["sudo", "-n", "systemctl", "reset-failed",
             _SANDBOXD_TEST_SERVICE],
            capture_output=True, timeout=10,
        )
        start = subprocess.run(
            ["sudo", "-n", "systemctl", "start", _SANDBOXD_TEST_SERVICE],
            capture_output=True, text=True, timeout=30,
        )
        if start.returncode != 0:
            journal = subprocess.run(
                ["sudo", "-n", "journalctl", "-u", _SANDBOXD_TEST_SERVICE,
                 "--no-pager", "-n", "200"],
                capture_output=True, text=True, timeout=15,
            )
            pytest.fail(
                "restart_test_daemon: systemctl start failed (rc="
                f"{start.returncode}).\nstdout: {start.stdout}\n"
                f"stderr: {start.stderr}\njournal tail:\n{journal.stdout}"
            )
        handle.reset_for_restart()
        # Use a per-handle _is_dead closure so the ready probe can
        # surface a re-killed unit as a clean failure (mirrors
        # _launch_daemon_as_sandbox_via_systemd).
        def _is_dead() -> tuple[bool, str]:
            rc = handle.poll()
            if rc is None:
                return (False, "")
            journal = subprocess.run(
                ["sudo", "-n", "journalctl", "-u", _SANDBOXD_TEST_SERVICE,
                 "--no-pager", "-n", "200"],
                capture_output=True, text=True, timeout=15,
            ).stdout
            return (True, f"unit exited rc={rc}; journal:\n{journal}")

        _wait_for_daemon_socket(
            Path(socket_path), _is_dead, ready_timeout,
        )
        return handle

    # Non-systemd harnesses: spawn a fresh subprocess.Popen against the
    # same socket and base-dir. Re-use the session-scope log files (the
    # session teardown reads them via the existing `_stdout_log`/
    # `_stderr_log` keys); append-mode so the per-test dump fixture's
    # offset book-keeping still works.
    stdout_log = sandbox_daemon["_stdout_log"]
    stderr_log = sandbox_daemon["_stderr_log"]
    new_stdout_fh = open(stdout_log, "a")
    new_stderr_fh = open(stderr_log, "a")

    argv: list[str]
    daemon_env = os.environ.copy()
    if harness == "sandbox-sudo":
        argv = [
            "sudo", "-n", "-u", "sandbox",
            str(sandbox_binaries.sandboxd),
            "--socket", str(socket_path),
            "--base-dir", str(base_dir),
        ]
        daemon_env["SANDBOX_USERS_CONF"] = os.environ["SANDBOX_USERS_CONF"]
        daemon_env["SANDBOX_BASE_VM_NAME"] = os.environ["SANDBOX_BASE_VM_NAME"]
    else:
        argv = [
            str(sandbox_binaries.sandboxd),
            "--socket", str(socket_path),
            "--base-dir", str(base_dir),
        ]

    proc = subprocess.Popen(
        argv,
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

    Used during teardown of the production-shaped harnesses
    (``sandbox-systemd`` and ``sandbox-sudo``) where the state dir is
    not tmp-isolated per pytest run. Sessions left behind would survive
    a daemon restart and corrupt the next session. Best-effort: any
    failure is logged but does not block teardown — the dir-wipe below
    handles the cold-state case.
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

    The launch strategy is selected by the ``SANDBOX_HARNESS`` env-var
    at conftest-import time — see the comment block near the top of
    the module for the three modes and their respective trade-offs.

    Yields a dict shaped identically across all three modes:
      - ``socket``       — path to the daemon's unix socket
      - ``base_dir``     — daemon's base directory
      - ``process``      — process handle (``Popen`` for sudo / test-user,
                           ``_SystemdDaemonHandle`` shim for systemd)
      - ``_stdout_log``, ``_stderr_log`` — log file paths
      - ``_stdout_fh``,  ``_stderr_fh``  — open writers on the above
      - ``_harness``     — the resolved harness mode (one of
                           ``sandbox-systemd``, ``sandbox-sudo``,
                           ``test-user``)

    Tears down the daemon (SIGTERM / ``systemctl stop``), purges any
    sessions left behind via the daemon HTTP API in the production-shaped
    modes, then force-deletes any Lima VMs / Docker containers / networks
    that leaked during the session as a final safety net.
    """
    tmp_path = tmp_path_factory.mktemp("sandboxd")

    if SANDBOX_HARNESS == "sandbox-systemd":
        info = _launch_daemon_as_sandbox_via_systemd(sandbox_binaries, tmp_path)
    elif SANDBOX_HARNESS == "sandbox-sudo":
        info = _launch_daemon_as_sandbox_via_sudo(sandbox_binaries, tmp_path)
    elif SANDBOX_HARNESS == "test-user":
        info = _launch_daemon_as_test_user(sandbox_binaries, tmp_path)
    else:  # pragma: no cover -- guarded at module import time
        raise RuntimeError(f"unreachable: SANDBOX_HARNESS={SANDBOX_HARNESS!r}")

    yield info

    # --- Teardown ---

    # Best-effort: purge sessions via API before stopping the daemon so
    # the next pytest session boots against a clean DB. The dir-wipe at
    # the start of the next session catches anything that survives this.
    if info.get("_harness") in ("sandbox-systemd", "sandbox-sudo"):
        try:
            _purge_sessions_via_api(info["socket"])
        except Exception:
            pass

    # Close daemon log file handles.  Use the current handles from info
    # because test_daemon_restart_recovery may have swapped them out.
    try:
        info["_stdout_fh"].close()
    except Exception:
        pass
    try:
        info["_stderr_fh"].close()
    except Exception:
        pass

    # Collect any Lima VM names from the daemon's session db so we can
    # clean them up even if the test forgot to `rm`. Under the
    # production-shaped harnesses (``sandbox-systemd`` / ``sandbox-
    # sudo``) the daemon owns its Lima registry at
    # ``/home/sandbox/.lima/``; bare ``limactl`` runs as the test
    # operator and only sees ``~/.lima/`` — so we route the probe and
    # the delete through ``sudo -n -u sandbox`` to query the right
    # registry. The ``sandbox`` NOPASSWD sudoers fragment installed by
    # ``make setup-dev-env`` (see Phase 1 of the 2026-05-24 spec)
    # authorises the test operator for these specific commands. In the
    # legacy ``test-user`` harness the daemon and the test operator
    # share a uid, so the bare ``limactl`` is correct.
    if info.get("_harness") in ("sandbox-systemd", "sandbox-sudo"):
        limactl_argv_prefix: list[str] = ["sudo", "-n", "-u", "sandbox", "limactl"]
    else:
        limactl_argv_prefix = ["limactl"]

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


def _dump_journalctl_for_test_window(
    service: str, since: str, fallback_lines: int = 200
) -> str:
    """Return the ``journalctl -u <service>`` output for a given window.

    Used by the dump-on-failure fixture in ``sandbox-systemd`` mode to
    extract just the lines logged during the test that just failed,
    rather than every line since boot. Falls back to the last
    ``fallback_lines`` lines if ``--since`` produces nothing (e.g. very
    short tests that didn't emit anything within the window).

    Best-effort: returns a descriptive placeholder if ``journalctl`` is
    not available or the sudo probe denies access; never raises.
    """
    try:
        cp = subprocess.run(
            ["sudo", "-n", "journalctl", "-u", service,
             f"--since={since}", "--no-pager"],
            capture_output=True, text=True, timeout=15,
        )
        text = cp.stdout
        if not text.strip():
            # Empty window — fall back to a small tail so we still get
            # *something* actionable. ``-n N`` is unioned with
            # ``--since=`` so we explicitly drop the latter for the
            # fallback.
            cp_tail = subprocess.run(
                ["sudo", "-n", "journalctl", "-u", service,
                 f"-n", str(fallback_lines), "--no-pager"],
                capture_output=True, text=True, timeout=15,
            )
            text = (
                "(no entries since test start; falling back to last "
                f"{fallback_lines} lines)\n{cp_tail.stdout}"
            )
        return text
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return f"(journalctl unavailable: {exc!r})"


@pytest.fixture(autouse=True)
def _dump_daemon_log_on_failure(request, sandbox_daemon):
    """Print the per-test window of sandboxd's stderr+stdout on failure.

    Captures ``os.path.getsize`` of each log before the test runs and, on
    failure, emits exactly the bytes appended during the test body — not
    the last 100 lines of the whole-session log, which conflate output
    from earlier tests (and from the restarted daemon spawned by
    ``test_daemon_restart_recovery``, which deliberately writes to the
    same log paths).

    Under ``SANDBOX_HARNESS=sandbox-systemd`` the daemon's output goes to
    the systemd journal, *not* the per-session log files: those files
    exist as zero-byte placeholders just so the offset book-keeping
    above is uniform across harnesses. To make systemd failures
    debuggable we additionally dump ``journalctl --since=<test start>``
    for the test unit on failure. The journal window is anchored to the
    pre-yield timestamp captured here so the dump shows exactly the
    lines emitted during the failing test body, mirroring the file-log
    window behaviour for the other harnesses.

    Driven by the per-phase outcome stashed by ``pytest_runtest_makereport``.
    Only fires when ``rep_call`` (the test body) failed — setup/teardown
    failures get reported separately and rarely correlate with daemon logs.

    The file window is capped at ``_DUMP_MAX_LINES`` / ``_DUMP_MAX_BYTES``
    from the tail with a ``(truncated)`` marker; if the file shrank
    during the test (rotation), the dump falls back to reading from
    offset 0. The journalctl window has no analogous cap because
    journalctl itself bounds output, but we apply a 15 s subprocess
    timeout so a stuck journald daemon cannot hang teardown.

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
    # journalctl --since= accepts the "YYYY-MM-DD HH:MM:SS" format
    # (local time) directly; we snapshot it pre-yield so the post-test
    # dump targets exactly the test's wall-clock window.
    journal_since = time.strftime("%Y-%m-%d %H:%M:%S")
    yield
    rep = getattr(request.node, "rep_call", None)
    if rep is None or not rep.failed:
        return
    harness = sandbox_daemon.get("_harness", "test-user")
    if harness == "sandbox-systemd":
        # The file-log windows under systemd are zero-byte placeholders
        # (the daemon's output is routed to the journal, not those
        # files). Emitting them anyway is just noise; jump straight to
        # the journalctl dump.
        journal = _dump_journalctl_for_test_window(
            _SANDBOXD_TEST_SERVICE, journal_since,
        )
        print(
            f"\n=== sandboxd journalctl "
            f"(unit={_SANDBOXD_TEST_SERVICE}, --since={journal_since!r}) ===\n"
            f"{journal}\n"
            f"=== end sandboxd journalctl ===\n",
            file=sys.stderr,
        )
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

    Under the production-shaped harnesses (``sandbox-systemd`` and
    ``sandbox-sudo``), a Lima rebuild *failure* (as opposed to absent
    prereqs) is fatal: the pre-warm hoist exists specifically to make
    Lima-backed tests reliable; if the build fails here, the operator
    needs to know up front rather than watch every Lima test fail
    downstream with an opaque per-test timeout. The container rebuild
    is also fatal-on-failure in every harness.
    """
    socket_path = sandbox_daemon["socket"]

    status = _query_base_image_status(socket_path)
    if status == "fresh":
        print(
            "[conftest] base image already fresh; skipping pre-warm",
            file=sys.stderr,
        )
        return

    # In the legacy ``test-user`` harness, daemon-uid == operator-uid
    # and both backend rebuilds are expected to succeed; keep the old
    # behaviour of a single ``rebuild-image`` (default ``--backend
    # all``) with a hard fail on non-zero exit.
    if sandbox_daemon.get("_harness", "test-user") == "test-user":
        print(
            "[conftest] pre-warming base image "
            "(harness=test-user, backend=all) — this can take several "
            "minutes on a slow mirror",
            file=sys.stderr,
        )
        result = subprocess.run(
            [str(sandbox_binaries.sandbox), "--socket", socket_path,
             "rebuild-image"],
            capture_output=True,
            text=True,
            timeout=2000,
        )
        if result.returncode != 0:
            pytest.fail(
                f"Failed to build base image (exit {result.returncode}).\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            )
        return

    # Production-shaped harnesses (``sandbox-systemd`` and
    # ``sandbox-sudo``): run the two backend rebuilds separately. The
    # container rebuild is fast (~30 s) and required; the Lima rebuild
    # downloads a 580 MiB qcow2 on first use and is required when Lima
    # prereqs are present.
    print(
        "[conftest] pre-warming container base image "
        f"(harness={SANDBOX_HARNESS})",
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
        f"(harness={SANDBOX_HARNESS}) — downloads ~580 MiB cloud-image "
        "qcow2 on first use; this can take 1-10+ minutes depending on "
        "network throughput. Subsequent sessions reuse the cached image.",
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
