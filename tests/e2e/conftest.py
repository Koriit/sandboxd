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
import pwd
import re
import shutil
import signal
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

# Test-feature sandbox-agent binary installed by `make install-agent-test`.
# Built with --features sandbox-agent/test-env-override so it honours the
# SANDBOX_AGENT_TEST_* env-var seams without an Aqua/GUI session or
# _sandboxd group membership.  Used by the _macos_operator_agent fixture.
AGENT_TEST_BIN = Path("/usr/local/libexec/sandboxd-test/sandbox-agent")

# Rust source-of-truth files we extract values from at test-collection time
# so the harness never drifts out of step with the daemon it drives.
WORKSPACE_CARGO_TOML = CARGO_WORKSPACE / "Cargo.toml"
SANDBOX_CORE_USERS_CONF_RS = CARGO_WORKSPACE / "sandbox-core" / "src" / "users_conf.rs"


def _read_workspace_version() -> str:
    """Extract the workspace version from the root Cargo.toml.

    This is the same value the Makefile's `gateway-image` target passes
    to `docker build -t sandbox-gateway:<version>` and the daemon's
    `CARGO_PKG_VERSION` at run-time. Reading the Cargo.toml directly
    keeps the preflight check working on hosts without a Rust toolchain
    (e.g. operators who only need to inspect an already-built image).

    Individual crate manifests use `version.workspace = true` and carry no
    standalone `version = "..."` line, so we read the workspace root manifest
    where `[workspace.package] version = "X.Y.Z"` is the single source of truth.
    """
    if not WORKSPACE_CARGO_TOML.exists():
        raise RuntimeError(
            f"Cannot read workspace version: {WORKSPACE_CARGO_TOML} not found"
        )
    text = WORKSPACE_CARGO_TOML.read_text()
    # Match the first `version = "X.Y.Z"` line — in the workspace root
    # Cargo.toml this appears under [workspace.package] and is the only
    # such line.
    matches = re.findall(r'(?m)^\s*version\s*=\s*"([^"]+)"', text)
    if not matches:
        raise RuntimeError(
            f"Cannot extract version from {WORKSPACE_CARGO_TOML}: "
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
SANDBOX_LITE_IMAGE_TAG = f"sandboxd-lite:{_read_workspace_version()}"

# Maximum time to wait for the daemon socket to appear (seconds).
# On macOS the daemon blocks in ensure_ready() (gateway Lima VM boot) before
# binding its socket — this can take 5-10 minutes on first boot. On Linux the
# daemon binds its socket immediately, so 30 s is sufficient there.
DAEMON_STARTUP_TIMEOUT = 900 if sys.platform == "darwin" else 30

# Paths to check for qemu-bridge-helper.
QEMU_BRIDGE_HELPER_PATHS = [
    Path("/usr/lib/qemu/qemu-bridge-helper"),
    Path("/usr/libexec/qemu-bridge-helper"),
]

BRIDGE_CONF_PATH = Path("/etc/qemu/bridge.conf")

# ---------------------------------------------------------------------------
# Platform seam
# ---------------------------------------------------------------------------
#
# A thin dataclass records the per-platform values that differ between the
# Linux cross-user harness and the macOS operator-uid harness.  Everything
# else — state paths, limactl_cmd(), the daemon HTTP API — is platform-
# agnostic and remains unchanged.
#
# PLATFORM is selected once at import time on sys.platform; every downstream
# constant and fixture reads it instead of hard-coding Linux values.


@dataclass
class _PlatformConfig:
    """Per-platform constants for the e2e harness."""

    #: Username of the dedicated e2e daemon system user on this platform.
    daemon_test_user: str

    #: Name of the group the operator must belong to for socket access.
    group_name: str


def _make_platform_config() -> _PlatformConfig:
    if sys.platform == "darwin":
        # macOS: a dedicated _sandboxd-test system user + group (created by
        # `make setup-dev-env`), isolated from the operator's real environment —
        # the macOS equivalent of Linux's sandbox-test. The e2e daemon runs as
        # this user (via `sudo -u _sandboxd-test`); its per-uid state tree,
        # LIMA_HOME, gateway VM, and socket live under that user, never touching
        # the operator's own sandboxd state.
        return _PlatformConfig(
            daemon_test_user="_sandboxd-test",
            group_name="_sandboxd-test",
        )
    # Linux: dedicated sandbox-test system user + group.
    return _PlatformConfig(
        daemon_test_user="sandbox-test",
        group_name="sandbox-test",
    )


PLATFORM: _PlatformConfig = _make_platform_config()

# ---------------------------------------------------------------------------
# Cross-user harness
# ---------------------------------------------------------------------------
#
# The e2e harness launches the daemon as a dedicated system user via
# ``sudo -u <daemon_test_user>``.  On Linux this is ``sandbox-test``; on
# macOS this is ``_sandboxd-test``.  All sudo is pre-authorized at
# ``make setup-dev-env`` time via a NOPASSWD sudoers fragment; no runtime
# root sudo is ever issued.
#
# The operator must be a member of the daemon-test group so the pytest
# process can reach the e2e daemon socket (mode 0660, group=<daemon_test_user>).
# On Linux: ``make test-e2e`` wraps pytest in ``sg sandbox-test -c '…'`` to
# activate the group without requiring a re-login.  macOS has no ``sg`` and
# ``make test-e2e-macos`` has no substitute for it — it activates the venv and
# runs pytest directly, so pytest carries the invoking shell's groups.
# Activating a freshly-added membership there is the caller's job (re-login),
# and :func:`_assert_operator_in_sandbox_group` fails the run with that
# instruction rather than letting every CLI call fail with EACCES.
# Re-exec'ing pytest under sudo is not an alternative ``make setup-dev-env``
# provides: the NOPASSWD fragment it installs has runas list
# ``(_sandboxd-test)``, which authorizes no sudo to the operator's own account.

# The e2e daemon runs as the dedicated test system user so its per-uid
# state tree is structurally disjoint from the prod daemon's tree
# (/var/lib/sandboxd/<sandbox-uid>/). Base-dir and socket are keyed on the
# daemon-test uid: /var/lib/sandboxd/<daemon-test-uid>/.
#
# Isolation guarantee: the state-dir reset operates only within
# /var/lib/sandboxd/<_SANDBOX_TEST_UID>/ and can never name a path
# inside the prod daemon's /var/lib/sandboxd/<sandbox-uid>/ tree.
# Created by `make setup-sandboxd-per-uid-state-dir` (part of
# `make setup-dev-env`).
#
# Guarded for cross-platform import-safety: the daemon test user only exists
# on a provisioned harness host. On hosts where it is absent the lookup
# degrades to a None sentinel; the constants derived below are consumed only
# by the cross-user fixtures/helpers, which skip cleanly when the user is
# absent (see _launch_daemon_as_sandbox_via_sudo).
try:
    _SANDBOX_TEST_UID: int | None = pwd.getpwnam(PLATFORM.daemon_test_user).pw_uid
except KeyError:
    _SANDBOX_TEST_UID = None
_SANDBOX_E2E_BASE_DIR = Path(f"/var/lib/sandboxd/{_SANDBOX_TEST_UID}")
_SANDBOX_E2E_SOCKET = _SANDBOX_E2E_BASE_DIR / "sandboxd.sock"

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
    # ``allow_users`` lists the operator AND the daemon test system user.
    # The e2e daemon runs as the test user (``sudo -u <daemon_test_user>``);
    # its startup-time ``find_subnet_by_uid`` lookup requires the daemon's
    # own uid to appear in some pool's ``allow_users``.  Names that do not
    # resolve to a uid on a given host are silently skipped by the daemon
    # ("unresolvable allow_users entries are treated as non-matches"), so
    # listing the test user is a no-op on un-provisioned hosts.
    _users_conf_payload = {
        "_schema_version": _read_min_supported_users_conf_schema(),
        "subnets": [
            {
                "comment": "E2E test daemon pool (disjoint from the production pool).",
                "cidr": E2E_TEST_POOL_CIDR,
                "allow_users": [getpass.getuser(), PLATFORM.daemon_test_user],
            }
        ]
    }
    # On macOS, tempfile.NamedTemporaryFile uses $TMPDIR which resolves to
    # a per-user /var/folders/.../.../T/ directory (mode drwx------). Even
    # with 0644 on the file itself, _sandboxd-test cannot traverse that
    # parent directory to reach it. Use /tmp explicitly (mode 1777,
    # world-traversable) so the daemon can read the file.
    _users_conf_tmpdir = "/tmp" if sys.platform == "darwin" else None
    _users_conf_tf = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="sandbox-e2e-users-",
        delete=False,
        dir=_users_conf_tmpdir,
    )
    json.dump(_users_conf_payload, _users_conf_tf)
    _users_conf_tf.flush()
    _users_conf_tf.close()
    # Mode 0644 (world-readable) is required so the daemon running as
    # the ``sandbox-test`` system user can read the file (it lives under
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


#: Per-session Docker resource names, and the session ID inside them:
#: ``sandbox-<id>`` (the lite container), ``sandbox-gw-<id>`` (its gateway)
#: and ``sandbox-net-<id>`` (its network). Anchored and ID-shaped on purpose:
#: cleanup driven by this pattern can only ever name a per-session resource,
#: never a long-lived one that merely starts with ``sandbox``.
_SESSION_DOCKER_RESOURCE_RE = re.compile(r"^sandbox-(?:gw-|net-)?([0-9a-f]{12})$")


#: ``find -name`` patterns matching every gateway Lima instance directory,
#: for use in the state-dir reset's keep lists.
#:
#: A pattern, not a name, and deliberately so. The reset deletes everything a
#: keep list does not match, so spelling one instance name there is only safe
#: while exactly one gateway VM can exist. The moment gateway VMs are owned
#: per operator, a literal name preserves one operator's instance and deletes
#: every other operator's on every pytest session — a destructive act by a
#: test harness against state it does not own. The prefix is the stable part
#: of the naming scheme; what follows it identifies the owner.
_GATEWAY_INSTANCE_KEEP: tuple[str, ...] = ("sandboxd-gateway*",)


# ---------------------------------------------------------------------------
# Cross-user Lima helpers
# ---------------------------------------------------------------------------
#
# The daemon runs as the ``sandbox`` system user; every Lima control-plane
# operation goes through ``sandbox-lima-helper``, which pivots to the
# *operator* uid before exec'ing limactl.  The resulting Lima state lives at
# the per-operator path:
#
#   /var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/
#
# NOT at the test-runner's ``~/.lima/``.  Any test-side helper that invokes
# ``limactl`` directly (for inspection or cleanup) must therefore pass
# ``env LIMA_HOME=<OP_LIMA_HOME>`` so limactl queries the right registry.
#
# IMPORTANT: the per-operator LIMA_HOME and all its contents (lima.yaml,
# _config/user, VM dirs) are owned by the OPERATOR uid (the test runner)
# with mode 0600/0700 — they are operator-private.  Running limactl as the
# ``sandbox-test`` system user via ``sudo -n -u sandbox-test`` therefore
# fails with EACCES ("open .../lima.yaml: permission denied" →
# "instance has no configuration").  The test process already IS the operator
# uid, so the correct approach is to run limactl directly (no sudo) with
# LIMA_HOME set to the per-operator path.
#
# Use ``limactl_cmd()`` for the argv prefix and ``OP_LIMA_HOME`` for the path
# constant in assertions.


#: Absolute path to the per-operator LIMA_HOME under the cross-user harness.
#: 3-level path: /var/lib/sandboxd/<daemon_uid>/<operator_uid>/lima, where
#: daemon_uid is the sandbox-test uid and operator_uid is the test runner's uid.
OP_LIMA_HOME: str = f"/var/lib/sandboxd/{_SANDBOX_TEST_UID}/{os.getuid()}/lima"


def limactl_cmd(*args: str) -> list[str]:
    """Build a limactl argv that queries the per-operator LIMA_HOME.

    The VM registry lives at
    ``/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/`` (the 3-level
    per-operator LIMA_HOME, where daemon_uid = sandbox-test uid).  Bare
    ``limactl`` would look in ``~/.lima/`` and see nothing, so this wrapper
    sets ``LIMA_HOME`` to the per-operator path via ``env``.

    The per-operator LIMA_HOME and all its files (lima.yaml, _config/user,
    VM directories) are owned by the OPERATOR uid and are operator-private
    (0600/0700).  Running limactl as the ``sandbox-test`` system user via
    ``sudo -n -u sandbox-test`` would fail with EACCES.  The test process
    already runs as the operator uid, so we invoke limactl directly — no
    sudo prefix — with only the LIMA_HOME override.

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

    Lima state lives at ``OP_LIMA_HOME``
    (``/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/``).
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

    # Checks 2-4 are LINUX full-backend preconditions. The Linux Lima/QEMU
    # backend bridges the session VM through a host TAP via the setuid
    # qemu-bridge-helper governed by /etc/qemu/bridge.conf. macOS uses
    # socket_vmnet instead (a per-slot pool provisioned by `make setup-dev-env`
    # and validated at daemon startup) — there is no qemu-bridge-helper or
    # bridge.conf on the macOS full-backend path — so these checks are
    # Linux-only. (A missing/broken socket_vmnet pool surfaces as a clear
    # daemon-startup error rather than a silent skip.)
    if sys.platform != "darwin":
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

    # On macOS the daemon's broker gate honours SANDBOX_BROKER_TEST_SANDBOX_GROUP
    # only when the daemon is compiled with sandboxd/test-env-override.  Build
    # with that feature (and the companion sandbox-agent seam) so the e2e
    # harness can redirect the broker's enrollment-group check to _sandboxd-test
    # without requiring the real _sandboxd group.
    build_cmd = ["cargo", "build", "--workspace"]
    if sys.platform == "darwin":
        build_cmd += ["--features", "sandboxd/test-env-override"]

    # macOS feature-builds compile from a cold cache (the test-env-override
    # feature changes the build graph) and the host's syspolicyd stall slows
    # fresh-binary exec, so the workspace build legitimately exceeds 5 min there.
    _build_timeout = 1800 if sys.platform == "darwin" else 300
    subprocess.run(
        build_cmd,
        cwd=str(CARGO_WORKSPACE),
        env=env,
        check=True,
        timeout=_build_timeout,
        capture_output=True,
    )

    assert SANDBOXD_BIN.exists(), f"sandboxd binary not found at {SANDBOXD_BIN}"
    assert SANDBOX_BIN.exists(), f"sandbox binary not found at {SANDBOX_BIN}"

    return SandboxBinaries(sandboxd=SANDBOXD_BIN, sandbox=SANDBOX_BIN)


def _assert_operator_in_sandbox_group() -> None:
    """Fail loudly if the calling pytest process is not in the daemon-test group.

    The e2e daemon socket is mode 0660 with ``group=<daemon_test_user>``. A
    test process whose effective groups do not include that group cannot read
    or write the socket and every CLI invocation fails with EACCES — a setup
    gap, not the cross-user bug under test.

    On Linux, group changes from ``usermod -aG sandbox-test <operator>`` do
    **not** take effect in the current login session; the Makefile wraps pytest
    in ``sg sandbox-test -c '…'`` to activate the group without a re-login.
    On macOS there is no ``sg`` and the Makefile does not substitute for it:
    ``test-e2e-macos`` runs pytest as the invoking user, so the group has to be
    active in the calling shell already — which is why this check exists and
    why the remediation below has a macOS branch.
    """
    import grp
    group_name = PLATFORM.group_name
    try:
        sandbox_gid = grp.getgrnam(group_name).gr_gid
    except KeyError:
        pytest.fail(
            f"The `{group_name}` system group does not exist on this host. "
            "Run `make setup-dev-env` from the workspace root and "
            "re-run the tests."
        )
    # The socket is mode 0660, group=<daemon_test_user>, so access is granted
    # when that gid is the process's effective GID *or* in its supplementary
    # set. `sg sandbox-test -c …` (how Linux make targets wrap pytest) sets
    # the group as the *primary/effective* GID and does not add it to the
    # supplementary list — and Linux `getgroups()` does not report the
    # effective GID — so checking `os.getgroups()` alone spuriously fails
    # under the sg wrap even though the process can read the socket.
    # Accept either.
    if sandbox_gid == os.getegid() or sandbox_gid in os.getgroups():
        return
    # Membership is configured but is not yet active in this process —
    # most likely the operator was just added and has not re-logged-in.
    # The remediation depends on whether the operator statically is a
    # member. The `id -nG` probe below resolves membership through
    # getgrouplist(3)/NSS, whose backing store varies by platform and
    # host configuration — so neither this comment nor the message it
    # feeds names one. (On this project's macOS hosts the group is in
    # the local Directory Services node and absent from /etc/group, so
    # naming a file would send a blocked operator to an empty grep.)
    operator = getpass.getuser()
    static_groups = subprocess.run(
        ["id", "-nG", operator],
        capture_output=True, text=True, timeout=5,
    ).stdout.split()
    if group_name in static_groups:
        if sys.platform == "darwin":
            # No `sg` on macOS, and no sudo shortcut either: the NOPASSWD
            # fragment `make setup-dev-env` installs has runas list
            # `(<daemon_test_user>)` alone, so it grants the operator no sudo
            # to their own account. A fresh login session is the remediation.
            group_activate_steps = (
                "Log out and back in, then re-run pytest. (macOS has no `sg`, "
                "and the NOPASSWD sudoers fragment `make setup-dev-env` "
                f"installs has runas list `({PLATFORM.daemon_test_user})`, "
                "which authorizes no sudo to your own account.)"
            )
        else:
            group_activate_steps = (
                "Log out and back in, or re-run pytest under "
                f"`sg {group_name} -c 'python -m pytest …'` "
                "so the new group is visible to the test process."
            )
        remediation = (
            "Operator '{op}' is listed as a member of "
            "'{grp}' but the group is not active in the current "
            "process. {steps}"
        ).format(op=operator, grp=group_name, steps=group_activate_steps)
    else:
        remediation = (
            "Operator '{op}' is not a member of the '{grp}' group. "
            "Run `make setup-dev-env` from the workspace root, "
            "log out and back in, then re-run pytest."
        ).format(op=operator, grp=group_name)
    pytest.fail(
        f"The pytest process must be a member of the '{group_name}' system "
        f"group (the e2e daemon socket is mode 0660, group={group_name}). "
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
    supply its own liveness check; the ``sudo -u sandbox-test`` launcher
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
    whose name matches no entry in ``keep``.

    ``keep`` entries are ``find -name`` patterns, not literal names, so a
    trailing ``*`` preserves a whole family of instance directories. That
    matters wherever the thing being preserved is one of N per-owner
    instances rather than a fixed singleton: a literal name preserves the
    one instance it spells and deletes every sibling.

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
        "sudo", "-n", "-u", PLATFORM.daemon_test_user,
        "find", str(directory), "-mindepth", "1", "-maxdepth", "1",
    ]
    for name in keep:
        argv += ["!", "-name", name]
    argv += ["-exec", "rm", "-rf", "{}", "+"]
    subprocess.run(argv, capture_output=True, timeout=120)


def _reset_sandbox_state_dir() -> None:
    """Wipe the e2e daemon's per-uid state tree between pytest sessions,
    preserving the Lima base-image cache and the golden base VM.

    The daemon writes all files under ``/var/lib/sandboxd/<_SANDBOX_TEST_UID>/``
    as the ``sandbox-test`` user, so deletes are issued as the
    ``sandbox-test`` user via :func:`_sudo_rm_children_except`.  The base
    dir itself is left intact (owned sandbox-test:sandbox-test 0750,
    provisioned by ``make setup-sandboxd-per-uid-state-dir``); we only
    remove daemon-managed state so a fresh ``sessions.db`` lands on the
    next session start.

    Safety: this function asserts that ``_SANDBOX_TEST_UID`` is distinct
    from both the operator uid and the prod daemon uid before any deletion,
    so a misconfigured host cannot accidentally wipe the prod daemon's tree
    (``/var/lib/sandboxd/<sandbox-uid>/``) or the operator's home.

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
    # Safety assertion: _SANDBOX_TEST_UID must be distinct from BOTH the
    # operator uid and the prod daemon's uid. A collision would mean the
    # delete loop below could reach into the wrong tree.
    operator_uid = os.getuid()
    try:
        prod_uid = pwd.getpwnam("sandbox").pw_uid
    except KeyError:
        prod_uid = None  # dev host without prod daemon user — no collision risk

    daemon_test_user = PLATFORM.daemon_test_user
    assert _SANDBOX_TEST_UID != operator_uid, (
        f"FATAL: {daemon_test_user} uid ({_SANDBOX_TEST_UID}) equals the operator uid "
        f"({operator_uid}). This would allow the state reset to wipe operator "
        "files. Aborting to prevent data loss."
    )
    if prod_uid is not None:
        assert _SANDBOX_TEST_UID != prod_uid, (
            f"FATAL: {daemon_test_user} uid ({_SANDBOX_TEST_UID}) equals the prod daemon "
            f"uid ({prod_uid}). This would allow the state reset to wipe the prod "
            "daemon's /var/lib/sandboxd tree. Aborting to prevent data loss."
        )

    base_vm = os.environ.get("SANDBOX_BASE_VM_NAME", "sandbox-test-base")

    if sys.platform == "darwin":
        # On macOS the daemon's Lima home lives at the 3-level path
        # ``{state_root}/{daemon_uid}/{op_uid}/lima`` where daemon_uid = op_uid
        # = _SANDBOX_TEST_UID (the e2e daemon runs as the test user and creates
        # sessions for itself). ``_SANDBOX_E2E_BASE_DIR`` is
        # ``{state_root}/{daemon_uid}``, i.e. the first two components of that
        # path already. This subtree contains staging artifacts
        # (gateway-image.tar, lite-image.tar, sandbox-route-helper) that the
        # daemon needs at startup and which are not cheaply re-downloadable.
        #
        # Preserve ``str(_SANDBOX_TEST_UID)`` (the per-daemon subtree) from the
        # top-level sweep so those artifacts survive. A separate, targeted reset
        # below cleans the gateway Lima VM directory (which must be recreated
        # fresh each session) while keeping the staging artifacts.
        #
        # Also preserve ``Library/`` — Lima stores its cloud-image download cache
        # under ``{HOME}/Library/Caches/lima/download/`` (HOME = base dir).
        # Wiping it would force a ~580 MiB Ubuntu cloud-image re-download on
        # every test session.
        daemon_uid_subdir = str(_SANDBOX_TEST_UID)
        top_level_keep = [".cache", ".lima", "base-image-meta.json", daemon_uid_subdir, "Library"]
    else:
        top_level_keep = [".cache", ".lima", "base-image-meta.json"]

    # E2E base dir: remove every top-level entry — sessions.db,
    # per-session dirs, listeners, events, the socket — except the Lima
    # cache, the .lima tree, and the freshness metadata. Then prune the
    # .lima tree down to the golden base VM (dropping per-session clones).
    _sudo_rm_children_except(
        _SANDBOX_E2E_BASE_DIR, top_level_keep
    )
    _sudo_rm_children_except(_SANDBOX_E2E_BASE_DIR / ".lima", [base_vm])

    if sys.platform == "darwin":
        # macOS: reset the daemon's Lima home. Keep the gateway VM instance so
        # ensure_ready() can start it without re-creating (and re-downloading
        # the cloud image). Also keep staging artifacts and the Lima SSH config.
        #
        # Daemon Lima home = _SANDBOX_E2E_BASE_DIR / {op_uid} / lima, which is
        # the 3-level path above: the base dir supplies state root + daemon
        # uid, and this adds the operator uid (also _SANDBOX_TEST_UID in the
        # e2e setup, where the daemon is its own operator).
        daemon_lima_home = (
            _SANDBOX_E2E_BASE_DIR / str(_SANDBOX_TEST_UID) / "lima"
        )
        # Remove per-session Lima clones (if any leaked from a crashed run).
        # Keep: staging artifacts, Lima SSH config, every gateway VM, and the
        # golden base VM (if it exists).
        _sudo_rm_children_except(
            daemon_lima_home,
            [
                "gateway-image.tar",
                "lite-image.tar",
                "sandbox-route-helper-linux-aarch64",
                "_config",
                *_GATEWAY_INSTANCE_KEEP,
                base_vm,
                ".cache",
                "base-image-meta.json",
            ],
        )

    # Per-operator LIMA_HOME under the 3-level path
    # (``/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima``): keep the download
    # cache, the golden base VM, the freshness metadata and any gateway VM
    # instance; remove per-session VM clones and any stale config so a
    # partially-initialised base VM left by a killed run is not reused via a
    # stale meta file. The base VM lives directly under LIMA_HOME here
    # (LIMA_HOME *is* the Lima home), not under a .lima subdir.
    # The LIMA_HOME root is sandbox-test-owned (provisioned by the daemon via
    # ensure_operator_lima_home); delete via the sandbox-test pivot so rm has
    # write+exec on the parent dir even when child files are operator-owned.
    op_lima_home = Path(OP_LIMA_HOME)
    _sudo_rm_children_except(
        op_lima_home,
        [".cache", base_vm, "base-image-meta.json", *_GATEWAY_INSTANCE_KEEP],
    )


def _stage_binaries_for_sandbox_user(sandbox_binaries: SandboxBinaries) -> dict:
    """Copy the freshly-built ``sandboxd`` binary into a world-traversable
    directory the ``sandbox-test`` system user can reach.

    The workspace lives under the operator's home directory (commonly mode
    0750), which the unprivileged ``sandbox-test`` user cannot search.  So
    ``sudo -u sandbox-test <workspace>/target/debug/sandboxd`` fails the
    post-setuid ``execve`` permission check with EACCES ("Permission
    denied") — the kernel resolves the path *as the sandbox-test user*, which
    needs search (``x``) on every ancestor directory.  We stage the
    binary into a fresh ``/tmp`` subdirectory (``/tmp`` is mode 1777, so
    every user can traverse it) owned by the operator at mode 0755, and run
    the daemon from there.  No host-permission changes and no root required.

    Only ``sandboxd`` is staged: the guest agent is installed at the canonical
    ``/usr/local/libexec/sandboxd/sandbox-guest`` by ``make install-guest-prod``
    and read from there by the prod lima-helper, so it no longer needs staging.

    Returns a dict with ``dir`` (the staging directory, removed at session
    teardown) and ``sandboxd`` (the staged path).
    """
    # ``mkdtemp`` yields a unique dir each session, so a still-running daemon
    # from a prior session can never collide here (no ETXTBSY on copy).
    stage_dir = Path(tempfile.mkdtemp(prefix="sandboxd-e2e-", dir="/tmp"))
    # mkdtemp creates the dir 0700; widen to 0755 so `sandbox` can traverse.
    os.chmod(stage_dir, 0o755)

    src_sandboxd = Path(sandbox_binaries.sandboxd)
    staged_sandboxd = stage_dir / "sandboxd"
    shutil.copy2(src_sandboxd, staged_sandboxd)
    os.chmod(staged_sandboxd, 0o755)
    return {
        "dir": stage_dir,
        "sandboxd": staged_sandboxd,
    }


def _launch_daemon_as_sandbox_via_sudo(
    sandbox_binaries: SandboxBinaries,
    tmp_path: Path,
) -> dict:
    """Start the daemon as the dedicated test user via ``sudo -u <daemon_test_user>``.

    This is the sole launch path. Requires the NOPASSWD sudoers fragment
    at ``/etc/sudoers.d/sandboxd-test`` (installed by
    ``make setup-dev-env``); a missing fragment causes sudo to prompt and
    hang the wait-for-socket deadline, so the harness probes up front and
    fails with a precise error.

    The base dir ``/var/lib/sandboxd/<_SANDBOX_TEST_UID>`` must already exist
    with ``<daemon_test_user>:<daemon_test_user>`` ownership and mode 0750 —
    provisioned once by ``make setup-sandboxd-per-uid-state-dir`` (part of
    ``make setup-dev-env``).  The socket lives inside the base dir so the
    daemon can create it without root.  The daemon (and guest) binaries are
    staged into a world-traversable ``/tmp`` dir so the daemon test user can
    exec them despite the workspace living under the operator's 0750 home —
    see :func:`_stage_binaries_for_sandbox_user`.
    """
    daemon_test_user = PLATFORM.daemon_test_user
    if _SANDBOX_TEST_UID is None:
        pytest.skip(
            f"The e2e harness requires the '{daemon_test_user}' system user; "
            "not present on this host. Run `make setup-dev-env` to provision "
            "it, then re-run the tests."
        )
    _assert_operator_in_sandbox_group()

    # Assert the base dir is provisioned. The daemon writes the socket
    # and all state here; if it is missing the daemon will fail to start.
    if not _SANDBOX_E2E_BASE_DIR.exists():
        pytest.fail(
            f"{_SANDBOX_E2E_BASE_DIR} does not exist. "
            "Run `make setup-sandboxd-per-uid-state-dir` (or `make setup-dev-env`) "
            "from the workspace root to create it, then re-run."
        )

    staged = _stage_binaries_for_sandbox_user(sandbox_binaries)

    # Probe NOPASSWD authorisation *and* binary reachability in one shot.
    # ``sudo -n -u <daemon_test_user> <staged-binary> --version`` returns
    # rc=1 with "a password is required" on stderr when the sudoers fragment
    # is absent/mis-scoped, or "Permission denied" if the daemon test user
    # cannot exec the staged binary. rc=0 confirms the full chain works.
    # Failing here prevents a silent hang at the wait-for-socket deadline.
    probe = subprocess.run(
        ["sudo", "-n", "-u", daemon_test_user,
         str(staged["sandboxd"]), "--version"],
        capture_output=True, text=True, timeout=10,
    )
    if probe.returncode != 0:
        shutil.rmtree(staged["dir"], ignore_errors=True)
        pytest.fail(
            "The NOPASSWD sudoers fragment at /etc/sudoers.d/sandboxd-test "
            f"is missing or does not authorise the operator to run commands "
            f"as the `{daemon_test_user}` user. "
            "Run `make setup-dev-env` from the workspace root and re-run.\n"
            f"sudo probe stderr: {probe.stderr.strip()!r}"
        )

    _reset_sandbox_state_dir()

    stdout_log = tmp_path / "sandboxd.stdout.log"
    stderr_log = tmp_path / "sandboxd.stderr.log"
    stdout_fh = open(stdout_log, "w")
    stderr_fh = open(stderr_log, "w")

    daemon_env = os.environ.copy()
    # The sudoers fragment installed by ``make setup-dev-env`` declares
    # ``Defaults:$USER env_keep += "SANDBOX_USERS_CONF ..."`` so the
    # variables propagate through sudo without ``--preserve-env`` (which
    # is more brittle to whitelist).
    #
    # The e2e suite uses the TEST-cap lima-helper
    # (/usr/local/libexec/sandboxd-test/sandbox-lima-helper, installed by
    # ``make install-lima-helper-test-cap``) with ``SANDBOX_LIMA_HELPER_PATH``
    # pointing at it. This helper is built with ``--features test-env-override``
    # and resolves its sandbox-user name via the
    # ``SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER`` seam, which we set to the
    # daemon test user so the caller-uid gate accepts the e2e daemon's uid.
    # ``SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP`` is set identically so the
    # helper's group gate matches. Both env vars are in the sudoers env_keep
    # list so they propagate through the sudo invocation.
    #
    # HOME and DOCKER_CONFIG are NOT in env_keep, so sudo's env_reset
    # always sets HOME=/nonexistent for the daemon test user regardless of
    # what the Popen env dict contains. We use an ``env KEY=VAL ...`` wrapper
    # *after* the sudo user switch to override HOME before execing the
    # daemon. This gives docker (invoked by the daemon for
    # ``rebuild-image --backend container``) a writable config dir under
    # the test-user-owned base dir instead of /nonexistent. The base
    # dir reset wipes the resulting .docker/ subtree between sessions.
    #
    # On macOS, additional redirects are required:
    # - SANDBOX_BROKER_SOCKET: the broker binds /var/run/sandbox/broker.sock
    #   by default, which uid 309 cannot write. Redirected here via the env
    #   wrapper so it is set after the sudo boundary (not in env_keep).
    # - DOCKER_HOST: points the daemon's Docker client at the gateway Lima VM's
    #   forwarded Docker socket. The daemon calls `docker image inspect
    #   sandbox-gateway:<ver>` in gateway_image_present() during session create;
    #   on macOS the gateway image lives in the VM's Docker (not the host's
    #   /var/run/docker.sock which does not exist). Setting DOCKER_HOST routes
    #   all host-docker calls through the gateway VM's forwarded socket, which
    #   is created by ensure_ready() during daemon startup.
    # - --log-file: without it, init_tracing() opens a rolling appender at
    #   /var/log/sandbox (root:wheel 0744), which uid 309 cannot write and
    #   which aborts the daemon before it binds its socket. Routing logs to
    #   the base dir lets the harness surface them on failure.
    # Gateway VM Docker socket path, under the 3-level LIMA_HOME:
    # {state_root}/{daemon_uid}/{op_uid}/lima/sandboxd-gateway/gateway-docker.sock
    # On the e2e harness daemon_uid == op_uid == _SANDBOX_TEST_UID.
    # _SANDBOX_E2E_BASE_DIR is {state_root}/{daemon_uid}, so the remainder
    # appended below is: {_SANDBOX_TEST_UID} / lima / ...
    _gateway_docker_sock = (
        _SANDBOX_E2E_BASE_DIR
        / str(_SANDBOX_TEST_UID)
        / "lima"
        / "sandboxd-gateway"
        / "gateway-docker.sock"
    )
    _macos_env_extras: list[str] = (
        [
            f"SANDBOX_BROKER_SOCKET={_SANDBOX_E2E_BASE_DIR / 'broker.sock'}",
            f"DOCKER_HOST=unix://{_gateway_docker_sock}",
            # Override the broker's enrollment-group check so the operator (uid
            # 501), who is in _sandboxd-test but not _sandboxd, can check in.
            # Requires the daemon to be compiled with sandboxd/test-env-override
            # (sandbox_binaries adds that feature on Darwin).
            f"SANDBOX_BROKER_TEST_SANDBOX_GROUP={PLATFORM.daemon_test_user}",
        ]
        if sys.platform == "darwin"
        else []
    )
    _macos_argv_extras: list[str] = (
        ["--log-file", str(_SANDBOX_E2E_BASE_DIR / "sandboxd.log")]
        if sys.platform == "darwin"
        else []
    )
    proc = subprocess.Popen(
        [
            "sudo", "-n", "-u", daemon_test_user,
            "env",
            f"HOME={_SANDBOX_E2E_BASE_DIR}",
            f"DOCKER_CONFIG={_SANDBOX_E2E_BASE_DIR / 'docker'}",
            *_macos_env_extras,
            str(staged["sandboxd"]),
            "--socket", str(_SANDBOX_E2E_SOCKET),
            "--base-dir", str(_SANDBOX_E2E_BASE_DIR),
            *_macos_argv_extras,
        ],
        env={
            **daemon_env,
            "SANDBOX_USERS_CONF": os.environ["SANDBOX_USERS_CONF"],
            "SANDBOX_BASE_VM_NAME": os.environ["SANDBOX_BASE_VM_NAME"],
            # Pin the ephemeral runtime dirs under the test base dir. The
            # daemon runs via sudo with no XDG_RUNTIME_DIR, so without these
            # they fall back to $HOME (/nonexistent) and fail. The state-dir
            # reset wipes these along with the rest of the test base dir.
            "SANDBOX_LISTENER_DIR": str(_SANDBOX_E2E_BASE_DIR / "listeners"),
            "SANDBOX_EVENTS_DIR": str(_SANDBOX_E2E_BASE_DIR / "events"),
            # Point at the TEST-cap lima-helper; the helper resolves the
            # sandbox-user name to the daemon test user via these seams so
            # the caller-uid gate accepts the e2e daemon.
            "SANDBOX_LIMA_HELPER_PATH": "/usr/local/libexec/sandboxd-test/sandbox-lima-helper",
            "SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER": daemon_test_user,
            "SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP": daemon_test_user,
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
            _SANDBOX_E2E_SOCKET, _is_dead, DAEMON_STARTUP_TIMEOUT,
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
        # On macOS, tracing output goes to --log-file rather than stderr;
        # include it in the failure dump so startup errors are visible.
        daemon_log_text = ""
        if sys.platform == "darwin":
            daemon_log_path = _SANDBOX_E2E_BASE_DIR / "sandboxd.log"
            try:
                daemon_log_text = f"\ndaemon log ({daemon_log_path}):\n{daemon_log_path.read_text()}"
            except OSError:
                daemon_log_text = f"\ndaemon log ({daemon_log_path}): (could not read)"
        print(
            f"sandboxd-via-sudo startup failed.\n"
            f"stderr: {stderr_text}{daemon_log_text}",
            file=sys.stderr,
        )
        raise

    return {
        "socket": str(_SANDBOX_E2E_SOCKET),
        "base_dir": str(_SANDBOX_E2E_BASE_DIR),
        "process": proc,
        "_stdout_fh": stdout_fh,
        "_stderr_fh": stderr_fh,
        "_stdout_log": stdout_log,
        "_stderr_log": stderr_log,
        "_stage_dir": staged["dir"],
        "_staged_sandboxd": staged["sandboxd"],
    }


def _daemon_pids(staged_sandboxd: str | Path) -> list[int]:
    """PIDs of live ``sandboxd`` processes launched from ``staged_sandboxd``.

    The harness starts the daemon as ``sudo -n -u <daemon_test_user> env …
    <staged_sandboxd> …``, so the ``Popen`` handle names ``sudo``, not the
    daemon. ``sudo`` is setuid-root but keeps the caller's *real* uid, which
    is why signalling that handle from the test runner succeeds — and why it
    is misleading: SIGKILL cannot be forwarded, so it kills only the wrapper
    and the daemon is reparented to PID 1, keeps its bound sockets, and
    outlives the "restart". (SIGTERM *is* forwarded by sudo; only the
    SIGKILL path orphans, which matches the daemons found alive after past
    runs.)

    Matching is on (uid == daemon test uid, argv contains the staged path).
    The uid clause excludes the ``sudo`` wrapper, whose argv also contains
    that path but which runs as uid 0; the staged path is a fresh mkdtemp
    per pytest session, so this can never name a daemon from another
    session — nor the production daemon, which runs as a different user
    from a different binary.
    """
    marker = str(staged_sandboxd)
    try:
        listing = subprocess.run(
            ["ps", "-axww", "-o", "pid=,uid=,command="],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    pids: list[int] = []
    for line in listing.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) < 3:
            continue
        pid_text, uid_text, command = fields
        try:
            pid, uid = int(pid_text), int(uid_text)
        except ValueError:
            continue
        if uid == _SANDBOX_TEST_UID and marker in command:
            pids.append(pid)
    return pids


def stop_test_daemon(
    sandbox_daemon: dict,
    sig: int = signal.SIGKILL,
    *,
    timeout: float = 20.0,
    escalate: bool = True,
) -> list[int]:
    """Stop the daemon(s) this pytest session started, and prove they died.

    Signals the real ``sandboxd`` process rather than the ``sudo`` wrapper —
    see :func:`_daemon_pids` for why the wrapper is the wrong target. The
    signal is delivered via ``sudo -n -u <daemon_test_user> kill``: the
    daemon runs as that user, so the test runner cannot signal it directly,
    and running ``kill`` as that user also means this can only ever reach
    processes of the e2e daemon's uid.

    Kills every daemon started from this session's staged binary, not just
    the one in ``sandbox_daemon["process"]``. That matters because an
    earlier restart may have left one behind, and a stale daemon is not
    inert: each new one unlinks and rebinds ``broker.sock``, so a leftover
    that later exits leaves the path naming a dead socket while the live
    daemon holds the old, unlinked inode — after which no agent can check
    in for the rest of the run.

    Escalates to SIGKILL if a gentler signal has not taken effect by half
    the timeout, and raises if anything is still alive at the end rather
    than letting the run continue against a daemon that was supposed to be
    gone. Returns the PIDs it signalled.

    Pass ``escalate=False`` when the point of the call is to *assert* that
    the daemon honours the signal — a test of the graceful-shutdown
    contract must not have its subject killed out from under it at the
    halfway mark.
    """
    staged = sandbox_daemon["_staged_sandboxd"]
    pids = _daemon_pids(staged)
    if pids:
        subprocess.run(
            [
                "sudo", "-n", "-u", PLATFORM.daemon_test_user,
                "kill", f"-{int(sig)}", *[str(pid) for pid in pids],
            ],
            capture_output=True, timeout=30,
        )

    deadline = time.monotonic() + timeout
    escalate_at = time.monotonic() + timeout / 2
    escalated = sig == signal.SIGKILL or not escalate
    while True:
        alive = _daemon_pids(staged)
        if not alive:
            break
        now = time.monotonic()
        if now >= deadline:
            raise RuntimeError(
                f"sandboxd still alive after {timeout}s: pids {alive} "
                f"(staged binary {staged}). Leaving it running would let it "
                "keep or rebind broker.sock behind the next daemon."
            )
        if not escalated and now >= escalate_at:
            subprocess.run(
                [
                    "sudo", "-n", "-u", PLATFORM.daemon_test_user,
                    "kill", "-9", *[str(pid) for pid in alive],
                ],
                capture_output=True, timeout=30,
            )
            escalated = True
        time.sleep(0.25)

    # The wrapper exits on its own once its child is gone; reap it so the
    # handle reports a status, and only force it if it somehow outlives the
    # daemon it was waiting on.
    proc = sandbox_daemon.get("process")
    if proc is not None and proc.poll() is None:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    return pids


def restart_test_daemon(
    sandbox_daemon: dict,
    sandbox_binaries: SandboxBinaries,
    *,
    ready_timeout: float = 15,
) -> subprocess.Popen:
    """Restart the daemon mid-test as the ``sandbox-test`` user via
    ``sudo -u sandbox-test``.

    Used by the restart-recovery e2e tests (``test_networking::
    test_daemon_restart_recovery``, ``test_lite::
    test_lite_orphan_cleanup_on_daemon_restart``, ``test_policy_persistence::
    test_policy_persists_across_daemon_restart``). Those tests stop the
    daemon first — mostly via SIGKILL, to assert state-reconciliation
    behaviour that depends on no graceful shutdown happening; this helper
    handles the *restart* leg and the in-place re-registration into
    ``sandbox_daemon`` so the session-scoped fixture stays coherent.

    Stops any surviving daemon before spawning the replacement, so a
    restart replaces rather than accumulates. This is deliberately
    unconditional and not an assertion: a test that fails between its
    create and its stop still reaches its ``finally`` restart, and the
    honest thing to do there is take the old daemon down rather than let
    two of them fight over ``broker.sock``. When the caller already
    stopped it, :func:`stop_test_daemon` finds nothing and returns.

    Re-spawns ``sudo -n -u sandbox-test sandboxd`` against the same socket
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
    stop_test_daemon(sandbox_daemon)

    socket_path = sandbox_daemon["socket"]
    base_dir = sandbox_daemon["base_dir"]
    stdout_log = sandbox_daemon["_stdout_log"]
    stderr_log = sandbox_daemon["_stderr_log"]
    new_stdout_fh = open(stdout_log, "a")
    new_stderr_fh = open(stderr_log, "a")

    # Relaunch from the same staged binary the session launcher used (the
    # sandbox-test user cannot exec the workspace build under the operator's
    # 0750 home — see _stage_binaries_for_sandbox_user). Mirror the
    # launcher's env so the restarted daemon is configured identically to the
    # one it replaces, including the TEST-cap helper path and sandbox-user seams.
    staged_sandboxd = sandbox_daemon["_staged_sandboxd"]
    daemon_env = os.environ.copy()
    daemon_test_user = PLATFORM.daemon_test_user
    daemon_env["SANDBOX_USERS_CONF"] = os.environ["SANDBOX_USERS_CONF"]
    daemon_env["SANDBOX_BASE_VM_NAME"] = os.environ["SANDBOX_BASE_VM_NAME"]
    # Pin the ephemeral runtime dirs under the test base dir (see launcher).
    daemon_env["SANDBOX_LISTENER_DIR"] = str(_SANDBOX_E2E_BASE_DIR / "listeners")
    daemon_env["SANDBOX_EVENTS_DIR"] = str(_SANDBOX_E2E_BASE_DIR / "events")
    # Mirror the TEST-cap helper env from the initial launcher.
    daemon_env["SANDBOX_LIMA_HELPER_PATH"] = "/usr/local/libexec/sandboxd-test/sandbox-lima-helper"
    daemon_env["SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER"] = daemon_test_user
    daemon_env["SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP"] = daemon_test_user

    # Mirror the macOS-specific env/argv additions from the initial launcher
    # so the restarted daemon is configured identically.
    _restart_gateway_docker_sock = (
        _SANDBOX_E2E_BASE_DIR
        / str(_SANDBOX_TEST_UID)
        / "lima"
        / "sandboxd-gateway"
        / "gateway-docker.sock"
    )
    _restart_macos_env_extras: list[str] = (
        [
            f"SANDBOX_BROKER_SOCKET={_SANDBOX_E2E_BASE_DIR / 'broker.sock'}",
            f"DOCKER_HOST=unix://{_restart_gateway_docker_sock}",
            f"SANDBOX_BROKER_TEST_SANDBOX_GROUP={PLATFORM.daemon_test_user}",
        ]
        if sys.platform == "darwin"
        else []
    )
    _restart_macos_argv_extras: list[str] = (
        ["--log-file", str(_SANDBOX_E2E_BASE_DIR / "sandboxd.log")]
        if sys.platform == "darwin"
        else []
    )
    proc = subprocess.Popen(
        [
            "sudo", "-n", "-u", daemon_test_user,
            # Mirror the HOME/DOCKER_CONFIG env wrapper from the initial
            # launcher: sudo env_reset sets HOME=/nonexistent for the daemon
            # test user regardless of the Popen env dict, so we must
            # override after the user switch via an explicit ``env`` prefix.
            "env",
            f"HOME={_SANDBOX_E2E_BASE_DIR}",
            f"DOCKER_CONFIG={_SANDBOX_E2E_BASE_DIR / 'docker'}",
            *_restart_macos_env_extras,
            str(staged_sandboxd),
            "--socket", str(socket_path),
            "--base-dir", str(base_dir),
            *_restart_macos_argv_extras,
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


def _get_sessions_via_api(socket_path: str, timeout: float = 5.0) -> list | None:
    """Return the daemon's session list, or ``None`` if it could not be asked.

    The ``None`` case is deliberately distinct from the empty list: callers
    that decide what to *delete* based on which sessions are live must do
    nothing at all when the daemon is unreachable, rather than conclude that
    nothing is live.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
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
            return None
        parsed = json.loads(text[start : end + 1])
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, list) else None


def _purge_sessions_via_api(socket_path: str) -> None:
    """Delete every session known to the daemon via the HTTP API.

    Used during teardown so the next pytest session boots against a clean
    DB. Sessions left behind would survive a daemon restart and corrupt the
    next session. Best-effort: any failure is logged but does not block
    teardown — the dir-wipe at the start of the next session handles the
    cold-state case.
    """
    sessions = _get_sessions_via_api(socket_path)
    if sessions is None:
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


def _gateway_vm_docker_argv(*args: str) -> list[str] | None:
    """Argv for a ``docker`` call against the gateway VM's Docker daemon.

    Returns ``None`` where no such endpoint exists — on Linux the session
    containers live in the host's own Docker, which plain ``docker`` already
    reaches.

    On macOS they do not: every session container and gateway container runs
    *inside* the gateway Lima VM, reachable only through the socket that VM
    forwards. Plain ``docker`` on a macOS host talks to Docker Desktop or
    colima, which has never held a sandbox session container — so cleanup
    written against it silently sweeps nothing while reporting success.

    The forwarded socket is mode 0600 under a 0700 directory, both owned by
    the daemon test user, so the test runner cannot open it directly however
    many groups it is in: the call has to pivot through
    ``sudo -u <daemon test user>``. That pivot is also what bounds the blast
    radius — this endpoint belongs to the e2e daemon's own gateway VM, and
    the production daemon's gateway VM lives under a different uid's state
    tree entirely.
    """
    if sys.platform != "darwin" or _SANDBOX_TEST_UID is None:
        return None
    sock = (
        _SANDBOX_E2E_BASE_DIR
        / str(_SANDBOX_TEST_UID)
        / "lima"
        / "sandboxd-gateway"
        / "gateway-docker.sock"
    )
    return [
        "sudo", "-n", "-u", PLATFORM.daemon_test_user,
        # sudo's env_reset would otherwise leave DOCKER_CONFIG pointing at
        # the operator's ~/.docker, which the daemon user cannot read.
        "env", f"DOCKER_CONFIG={_SANDBOX_E2E_BASE_DIR / 'docker'}",
        "docker", "-H", f"unix://{sock}",
        *args,
    ]


def _sweep_session_docker_state(docker_argv: list[str]) -> None:
    """Force-remove every per-session container and network at one endpoint.

    Teardown-only: it does not ask which sessions are live, so it must run
    after the sessions have been purged and the daemon stopped.
    """
    try:
        containers = subprocess.run(
            docker_argv + [
                "ps", "-a", "--filter", "name=sandbox-", "--format", "{{.Names}}",
            ],
            capture_output=True, text=True, timeout=15,
        )
        for name in containers.stdout.strip().splitlines():
            if name:
                subprocess.run(
                    docker_argv + ["rm", "-f", name],
                    capture_output=True, timeout=30,
                )
    except Exception:
        pass

    try:
        networks = subprocess.run(
            docker_argv + [
                "network", "ls", "--filter", "name=sandbox-", "--format", "{{.Name}}",
            ],
            capture_output=True, text=True, timeout=15,
        )
        for name in networks.stdout.strip().splitlines():
            if name:
                subprocess.run(
                    docker_argv + ["network", "rm", name],
                    capture_output=True, timeout=30,
                )
    except Exception:
        pass


def _reap_orphaned_session_docker_state(socket_path: str) -> list[str]:
    """Remove per-session containers/networks the daemon no longer owns.

    Runs *between* tests, unlike :func:`_sweep_session_docker_state`, so it
    cannot simply delete everything: it removes only resources whose session
    ID the daemon does not know about, and among those only containers that
    are not running. Either condition alone would be enough to protect a live
    session; both are cheap.

    This exists because an orphan here is not inert. A gateway container
    whose session is gone keeps its ``unless-stopped`` restart policy, and
    its entrypoint waits for an Envoy bootstrap file the daemon deleted with
    the session's staging dir — so it exits, restarts ~every 30 s, and spawns
    another mitmproxy each cycle, inside a gateway VM with under 2 GiB of
    RAM. Past runs ended with several of these looping at restart counts in
    the tens, and the VM's dockerd stalled mid-run.

    Best-effort throughout: this is a safety net, and it must never turn a
    passing test into a failing one. When the daemon cannot be asked which
    sessions are live, it does nothing.
    """
    docker_argv = _gateway_vm_docker_argv()
    if docker_argv is None:
        return []
    sessions = _get_sessions_via_api(socket_path)
    if sessions is None:
        return []
    live = {
        str(entry.get("id") or entry.get("session_id") or "")[:12]
        for entry in sessions
        if isinstance(entry, dict)
    }

    removed: list[str] = []
    try:
        listing = subprocess.run(
            docker_argv + [
                "ps", "-a", "--filter", "name=sandbox-",
                "--format", "{{.Names}}\t{{.State}}",
            ],
            capture_output=True, text=True, timeout=30,
        )
        for line in listing.stdout.strip().splitlines():
            name, _, state = line.partition("\t")
            match = _SESSION_DOCKER_RESOURCE_RE.match(name.strip())
            if match is None or match.group(1) in live:
                continue
            if state.strip() == "running":
                continue
            result = subprocess.run(
                docker_argv + ["rm", "-f", name.strip()],
                capture_output=True, timeout=60,
            )
            if result.returncode == 0:
                removed.append(name.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        networks = subprocess.run(
            docker_argv + [
                "network", "ls", "--filter", "name=sandbox-", "--format", "{{.Name}}",
            ],
            capture_output=True, text=True, timeout=30,
        )
        for line in networks.stdout.strip().splitlines():
            name = line.strip()
            match = _SESSION_DOCKER_RESOURCE_RE.match(name)
            if match is None or match.group(1) in live:
                continue
            # A network still attached to something refuses removal; that is
            # the desired outcome, and docker says so on stderr.
            result = subprocess.run(
                docker_argv + ["network", "rm", name],
                capture_output=True, timeout=30,
            )
            if result.returncode == 0:
                removed.append(name)
    except (OSError, subprocess.TimeoutExpired):
        pass

    return removed


@pytest.fixture(autouse=True)
def _reap_gateway_container_leaks(request):
    """Reap orphaned session containers/networks after every test.

    The session-scoped teardown sweep is not enough on its own: orphans do
    damage while the run is still going (see
    :func:`_reap_orphaned_session_docker_state`), and a leak that stalls the
    gateway VM's dockerd mid-run costs every test that follows it.

    No-op off macOS — there the session containers are in the host's Docker,
    shared with any production daemon on the box, and a between-tests reaper
    pointed at a shared endpoint is exactly the destructive sweep this
    harness deliberately removed years ago.
    """
    if _SANDBOX_TEST_UID is None or _gateway_vm_docker_argv() is None:
        yield
        return
    sandbox_daemon = request.getfixturevalue("sandbox_daemon")
    yield
    removed = _reap_orphaned_session_docker_state(sandbox_daemon["socket"])
    if removed:
        print(
            "[conftest] reaped orphaned gateway-VM Docker resources: "
            + ", ".join(removed),
            file=sys.stderr,
        )


@pytest.fixture(scope="session")
def sandbox_daemon(sandbox_binaries: SandboxBinaries, tmp_path_factory: pytest.TempPathFactory):
    """Start a sandboxd instance for the test session.

    Session-scoped: all tests share the same daemon process.

    Launches the daemon as the ``sandbox-test`` system user via
    ``sudo -u sandbox-test``. All sudo is pre-authorized at
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
    # Lima registry at the 3-level path
    # ``/var/lib/sandboxd/<daemon_uid>/<op_uid>/lima/`` (the per-operator
    # LIMA_HOME, where daemon_uid = sandbox-test uid); bare ``limactl``
    # would look in ``~/.lima/`` and see nothing. We set LIMA_HOME to
    # ``OP_LIMA_HOME`` so the list/delete calls reach the right registry.
    # The per-operator LIMA_HOME is owned by the operator uid
    # (operator-private, 0600/0700), so we run limactl directly as the
    # test operator — no ``sudo -n -u sandbox-test`` prefix, which would
    # hit EACCES on the operator-owned files.
    limactl_argv_prefix: list[str] = [
        "env", f"LIMA_HOME={OP_LIMA_HOME}",
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

    # Send SIGTERM and wait for graceful shutdown, escalating to SIGKILL.
    # Goes through stop_test_daemon rather than info["process"] so it stops
    # the daemon itself rather than the sudo wrapper, and so it also
    # collects any daemon a restart test left behind — an orphan holding a
    # rebound broker.sock is what makes the *next* session's agent
    # unreachable. Report rather than raise: the rest of this teardown
    # still has VMs, containers and networks to reap, and a surviving
    # daemon must not cost us those too.
    try:
        stop_test_daemon(info, signal.SIGTERM)
    except RuntimeError as exc:
        print(f"[conftest] daemon teardown: {exc}", file=sys.stderr)

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
    _sweep_session_docker_state(["docker"])

    # On macOS the sweep above reaches only the host's Docker, which never
    # holds a sandbox session container — those live inside the gateway Lima
    # VM. Sweep that endpoint too, or every gateway container the run leaked
    # survives it, crash-looping in a memory-constrained VM until someone
    # notices. No-op elsewhere.
    gateway_vm_docker = _gateway_vm_docker_argv()
    if gateway_vm_docker is not None:
        _sweep_session_docker_state(gateway_vm_docker)


# Per-test dump-window caps: keep failure output bounded even when a test
# generates a torrent of daemon logs.
_DUMP_MAX_LINES = 4000
_DUMP_MAX_BYTES = 1 << 20  # 1 MiB

#: Path the operator agent's merged stdout+stderr is written to, set by
#: ``_macos_operator_agent`` when it launches the agent. Read by
#: ``_dump_daemon_log_on_failure`` so a failing macOS test shows the agent's
#: own view alongside the daemon's. ``None`` when no agent was launched
#: (non-macOS, or the test-feature binary is not installed).
_AGENT_LOG_PATH: Path | None = None


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


def _read_log_tail(path: Path, max_bytes: int = 4096) -> str:
    """Return the last ``max_bytes`` of ``path``, for inclusion in an error.

    Used where a fixture is about to raise and the process it was waiting on
    wrote its diagnosis to a log file rather than to a pipe the fixture could
    ``communicate()`` with.
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            tail = fh.read().decode(errors="replace")
    except OSError as exc:
        return f"(could not read {path}: {exc})"
    if not tail.strip():
        return f"(empty: {path})"
    return tail


@pytest.fixture(autouse=True)
def _dump_daemon_log_on_failure(request):
    """Print the per-test window of sandboxd's stderr+stdout on failure.

    Captures ``os.path.getsize`` of each log before the test runs and, on
    failure, emits exactly the bytes appended during the test body — not
    the last 100 lines of the whole-session log, which conflate output
    from earlier tests (and from the restarted daemon spawned by
    ``test_daemon_restart_recovery``, which deliberately writes to the
    same log paths).

    The daemon runs as the ``sandbox-test`` user via ``sudo -u sandbox-test``
    and writes its stdout/stderr to the per-session log files at
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

    Autouse no-op when the cross-user ``sandbox-test`` daemon is unavailable
    (``_SANDBOX_TEST_UID is None``, e.g. macOS-native ``test_lite_macos.py``
    running against an ambient operator daemon). There is no cross-user
    daemon log to dump, and requesting ``sandbox_daemon`` here would force
    its setup — which skips — onto every test in the directory. ``sandbox_daemon``
    is resolved lazily via ``request.getfixturevalue`` (not a fixture
    parameter) so the guard runs before any cross-user setup.
    """
    if _SANDBOX_TEST_UID is None:
        yield
        return
    sandbox_daemon = request.getfixturevalue("sandbox_daemon")
    offsets = {
        key: _capture_log_offset(sandbox_daemon[key])
        for _, key in (("stderr", "_stderr_log"), ("stdout", "_stdout_log"))
    }
    # The operator agent (macOS full backend) logs to its own file; capture
    # its offset too so the dump shows the agent's view of the same window.
    agent_offset = (
        _capture_log_offset(_AGENT_LOG_PATH) if _AGENT_LOG_PATH is not None else None
    )
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
    if _AGENT_LOG_PATH is not None and agent_offset is not None:
        text, eff_start, end = _read_log_window(_AGENT_LOG_PATH, agent_offset)
        if text.strip():
            print(
                f"\n=== sandbox-agent "
                f"(test window bytes [{eff_start}, {end}), "
                f"from {_AGENT_LOG_PATH}) ===\n"
                f"{text}\n"
                f"=== end sandbox-agent ===\n",
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
def _ensure_base_image(request, sandbox_binaries: SandboxBinaries):
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
    end up racing the 580 MiB download — exactly the failure mode the
    autouse-hoist was introduced to eliminate.

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

    Autouse no-op when the cross-user ``sandbox-test`` daemon is unavailable
    (``_SANDBOX_TEST_UID is None``, e.g. macOS-native ``test_lite_macos.py``
    running against an ambient operator daemon). The pre-warm drives the
    cross-user daemon and has no meaning without it; requesting
    ``sandbox_daemon`` here would force its setup — which skips — onto every
    test in the directory. ``sandbox_daemon`` is resolved lazily via
    ``request.getfixturevalue`` (not a fixture parameter) so the guard runs
    before any cross-user setup.
    """
    if _SANDBOX_TEST_UID is None:
        return
    sandbox_daemon = request.getfixturevalue("sandbox_daemon")
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
    #
    # On macOS the container (lite) backend runs inside the gateway Lima VM.
    # The lite image is pre-loaded via a staged tarball during ensure_ready(),
    # so there is no host-side Docker build to run — sandbox rebuild-image
    # --backend container would attempt to run `docker build` against the host
    # Docker socket (/var/run/docker.sock) which does not exist, and would fail.
    # Skip the container rebuild on macOS; the tarball-based load covers it.
    if sys.platform != "darwin":
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
    else:
        print(
            "[conftest] macOS: skipping container base image pre-warm "
            "(lite image loaded from staged tarball by the gateway VM)",
            file=sys.stderr,
        )
        # Verify the lite image is present in the gateway VM's Docker. The
        # daemon loads it from the staged tarball at startup, but if the
        # tarball was never staged (e.g. `make stage-lite-image` not run)
        # the first `sandbox create --lite` fails with an obscure "No such
        # image" error from inside the VM. Catch the absence here with a
        # clear message so the operator knows what to fix.
        # _SANDBOX_TEST_UID is guaranteed non-None here: the fixture returns
        # early at the top of this function when it is None.
        _gw_sock = (
            _SANDBOX_E2E_BASE_DIR
            / str(_SANDBOX_TEST_UID)
            / "lima"
            / "sandboxd-gateway"
            / "gateway-docker.sock"
        )
        if _gw_sock.exists():
            _inspect = subprocess.run(
                [
                    "docker",
                    "-H", f"unix://{_gw_sock}",
                    "image", "inspect", SANDBOX_LITE_IMAGE_TAG,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if _inspect.returncode != 0:
                pytest.fail(
                    f"macOS preflight: lite image {SANDBOX_LITE_IMAGE_TAG!r} is "
                    f"not present in the gateway VM's Docker daemon "
                    f"(socket: {_gw_sock}).\n"
                    f"Run: make lite-image && make stage-lite-image\n"
                    f"docker stderr: {_inspect.stderr.strip()}"
                )
            else:
                print(
                    f"[conftest] macOS: lite image {SANDBOX_LITE_IMAGE_TAG} "
                    f"confirmed present in gateway VM",
                    file=sys.stderr,
                )
        else:
            print(
                f"[conftest] macOS: gateway socket {_gw_sock} not yet present "
                f"(daemon not started); skipping lite image pre-flight check",
                file=sys.stderr,
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


# ---------------------------------------------------------------------------
# macOS full-backend guard
# ---------------------------------------------------------------------------
# Platform-axis marker gates
# ---------------------------------------------------------------------------
#
# Two orthogonal axes control test selection:
#
#   Backend axis  — ``@pytest.mark.lima`` / ``@pytest.mark.container``
#   Platform axis — ``@pytest.mark.linux_only`` / ``@pytest.mark.macos_only``
#
# No platform marker → the test runs on both platforms (the majority).
# ``linux_only`` → qemu-bridge-helper, /dev/kvm, route-helper netns, systemd,
#   cgroup v2, `sandbox-lima-helper`, host `/etc/sandboxd/users.conf`.
# ``macos_only`` → socket_vmnet pool lifecycle, gateway Lima instance lifecycle,
#   vmnet NIC discovery, per-operator agent check-in/broker, launchd control.
#
# When to reach for a platform marker, and when not to
# ----------------------------------------------------
# The bar is that the test *body* asserts on a host facility the other
# platform does not have, so the test could not pass there however well the
# product worked. Two shapes look similar and are not:
#
#   * A test that would pass on both platforms but is written against
#     Linux-only plumbing needs that plumbing generalised, not a marker.
#     Marking it silently removes coverage rather than describing reality.
#   * A test that fails on macOS because the *harness* points at something
#     absent — the host Docker daemon, say — is a harness bug. A marker
#     converts a fixable defect into a permanent exclusion.
#
# Marking is a claim about the platform, so state the evidence at the mark:
# name the assertion and the facility it needs. A marker whose reason is
# "fails on macOS" cannot be re-examined by the next reader.
#
# Both markers are enforced by ``_platform_axis_gate`` below and consumed as
# deselect filters by the platform-specific make targets; ``pytest_configure``
# refuses to start a run in which either is applied to no test at all.
#
# For ``macos_only`` tests the fixture also checks whether the per-operator
# sandboxd agent is loaded (Aqua/GUI mode), because the full Lima backend
# requires an operator-local agent brokered by launchd.  SSH-only sessions
# can still run lite (container) tests.
#
# Cross-user SSH/Background sessions bypass the Aqua gate by using the
# test-feature agent binary (AGENT_TEST_BIN, installed by `make install-agent-test`)
# launched by the _macos_operator_agent session-scoped fixture below.


# Platform markers that must actually be applied to something.
#
# Both are consumed as deselect filters by the platform-specific make
# targets (`-m "not linux_only"` on macOS, `-m "not macos_only"` on Linux).
# A marker that is declared, documented and filtered on but carried by zero
# tests deselects nothing, and nothing about that is visible in a run: the
# suite is simply green while the gate it advertises is inert. That is not
# hypothetical — `linux_only` sat in exactly that state, so the macOS entry
# point collected the whole Linux-authored matrix while appearing to exclude
# it.  This check makes the next occurrence fail at startup instead.
_PLATFORM_MARKERS = ("linux_only", "macos_only")


def pytest_configure(config):
    """Fail the run if a platform marker is applied to no test at all.

    Deliberately a source scan of ``test_*.py`` rather than a count over
    collected items: under ``-m "not linux_only"`` — the macOS entry point —
    every ``linux_only`` item is deselected, so a collected-item count is
    zero whether the marker is applied everywhere or nowhere. The scan is
    also stable under partial runs (``pytest test_lite.py``), which an
    item-based check is not.
    """
    e2e_dir = Path(__file__).resolve().parent
    unapplied = [
        marker
        for marker in _PLATFORM_MARKERS
        if not any(
            f"pytest.mark.{marker}" in path.read_text(errors="replace")
            for path in sorted(e2e_dir.glob("test_*.py"))
        )
    ]
    if unapplied:
        raise pytest.UsageError(
            "platform marker(s) declared and filtered on but applied to zero "
            f"tests: {', '.join(unapplied)}. A marker in this state silently "
            "deselects nothing — apply it to the tests it describes, or drop "
            "it from pyproject.toml and from the make targets' -m expressions."
        )


def _agent_test_bin_available() -> bool:
    """Return True when the test-feature agent binary is installed and executable."""
    return AGENT_TEST_BIN.exists() and os.access(AGENT_TEST_BIN, os.X_OK)


@pytest.fixture(scope="session")
def _macos_operator_agent(sandbox_daemon):
    """Launch the test-feature sandbox-agent as the operator on macOS.

    On macOS, the full (Lima) backend requires a per-operator agent connected
    to the daemon's broker socket.  In production this agent runs as a
    LaunchAgent in the operator's Aqua/GUI session.  In the cross-user e2e
    harness (SSH / Background session) we launch the test-feature binary
    directly as the operator (no sudo — we ARE the operator) with env-var
    seams that bypass the _sandboxd group check and point it at the test
    broker socket.

    Prerequisites (installed by `make setup-dev-env` / `make install-agent-test`):
    - AGENT_TEST_BIN (/usr/local/libexec/sandboxd-test/sandbox-agent) exists
    - The daemon is running (sandbox_daemon dependency)

    On non-macOS or when _SANDBOX_TEST_UID is None (no cross-user harness),
    this fixture is a no-op so it can be declared as a dependency without
    gating non-macOS tests.

    Yields the Popen process (or None when the fixture is a no-op).
    """
    if sys.platform != "darwin" or _SANDBOX_TEST_UID is None:
        yield None
        return

    if not _agent_test_bin_available():
        # Binary absent — `macos_only` + `lima` tests skip at
        # _platform_axis_gate rather than fail, unless the production
        # LaunchAgent is loaded (the gate's other accepted path).
        yield None
        return

    broker_socket = str(_SANDBOX_E2E_BASE_DIR / "broker.sock")
    daemon_uid = str(_SANDBOX_TEST_UID)
    # State root for LIMA_HOME construction: {state_root}/{daemon_uid}/{op_uid}/lima.
    # Use the same base tree as the e2e daemon so LIMA_HOME paths are consistent.
    state_root = "/var/lib/sandboxd"

    agent_env = os.environ.copy()
    # Test-env-override seams (sandbox-agent/test-env-override feature):
    #   skip _sandboxd group check → use _sandboxd-test (operator 501 is a member)
    agent_env["SANDBOX_AGENT_TEST_SANDBOX_GROUP"] = PLATFORM.daemon_test_user
    #   broker socket: point at the e2e daemon's broker, not /var/run/sandbox/broker.sock
    agent_env["SANDBOX_AGENT_TEST_BROKER_SOCKET"] = broker_socket
    #   daemon uid: the e2e daemon runs as _sandboxd-test (uid 309)
    agent_env["SANDBOX_AGENT_TEST_DAEMON_UID"] = daemon_uid
    #   state root: /var/lib/sandboxd (same as production; LIMA_HOME = state_root/309/501/lima)
    agent_env["SANDBOX_AGENT_TEST_STATE_ROOT"] = state_root
    # The non-feature-gated SANDBOX_BROKER_SOCKET override is also honoured
    # by the agent (checked before the test seam) — set it as a belt-and-suspenders
    # fallback for any future code path that reaches broker_socket_path() first.
    agent_env["SANDBOX_BROKER_SOCKET"] = broker_socket
    # Structured logging: surface agent info/warn lines in the agent log.
    agent_env.setdefault("RUST_LOG", "sandbox_agent=info")

    # The agent logs through tracing_subscriber::fmt() to *stdout* and emits
    # several lines per brokered guest stream. Its output must go to a file,
    # not a pipe: a pipe nobody reads fills at its 64 KiB capacity (measured
    # on this host) and the agent then blocks forever inside write(2) —
    # answering no further broker traffic while still holding its connection.
    # Two full macOS suite runs each wedged after the daemon brokered exactly
    # 109 guest streams, the same integer to the unit, which is a
    # fixed-capacity buffer filling rather than a timing or load effect. The
    # visible symptom differed between those runs (a 60 s heartbeat timeout
    # in one, a 30 s StreamReady deadline in the other) because both are
    # downstream of the same wedged writer.
    #
    # A file keeps the output — the agent's log explains Lima-backend
    # failures the daemon log can only report second-hand — and never blocks
    # the writer. It sits beside the daemon's logs so a failing run has both
    # in one place; ``_dump_daemon_log_on_failure`` prints the per-test window
    # of it next to the daemon's.
    global _AGENT_LOG_PATH
    agent_log = Path(sandbox_daemon["_stdout_log"]).parent / "sandbox-agent.log"
    agent_log_fh = open(agent_log, "w")
    _AGENT_LOG_PATH = agent_log
    print(f"[conftest] sandbox-agent log: {agent_log}", file=sys.stderr)

    # The agent takes no command-line arguments; all config is via env.
    proc = subprocess.Popen(
        [str(AGENT_TEST_BIN)],
        env=agent_env,
        stdout=agent_log_fh,
        stderr=subprocess.STDOUT,
    )

    # Wait up to 10 s for the agent to connect and send its CHECKIN frame.
    # The daemon logs "agent check-in admitted uid=<uid>" on success.
    _daemon_log = _SANDBOX_E2E_BASE_DIR / "sandboxd.log"
    deadline = time.monotonic() + 10.0
    agent_uid = str(os.getuid())
    checked_in = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            # Agent exited early — self-gate or connection error. Its output
            # is in the log file, not a pipe, so read the tail of that.
            agent_log_fh.close()
            raise RuntimeError(
                f"sandbox-agent exited before check-in (rc={proc.returncode}).\n"
                f"Agent log ({agent_log}):\n{_read_log_tail(agent_log)}"
            )
        if _daemon_log.exists():
            try:
                log_text = _daemon_log.read_text(errors="replace")
                if f"agent check-in admitted uid={agent_uid}" in log_text:
                    checked_in = True
                    break
            except OSError:
                pass
        time.sleep(0.25)

    if not checked_in:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        agent_log_fh.close()
        raise RuntimeError(
            f"sandbox-agent did not check in within 10 s "
            f"(uid={agent_uid}, broker={broker_socket}). "
            "Check the daemon log for broker rejection details.\n"
            f"Agent log ({agent_log}):\n{_read_log_tail(agent_log)}"
        )

    yield proc

    # Teardown: stop the agent gracefully.
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    agent_log_fh.close()


@pytest.fixture(autouse=True, scope="function")
def _platform_axis_gate(request, _macos_operator_agent):
    """Enforce the platform axis (linux_only / macos_only) per test.

    Tests with no platform marker are platform-agnostic and pass through
    unconditionally.  ``linux_only`` tests skip on macOS; ``macos_only``
    tests skip on Linux.  On macOS, ``macos_only`` tests that require
    the full Lima backend check that an operator agent is available —
    either the test-built agent launched by _macos_operator_agent, or
    the production agent loaded via launchctl (Aqua/GUI session).
    """
    has_linux_only = request.node.get_closest_marker("linux_only") is not None
    has_macos_only = request.node.get_closest_marker("macos_only") is not None

    if has_linux_only and sys.platform == "darwin":
        pytest.skip(
            "linux_only test; run on Linux. Its assertions need a host "
            "facility macOS does not have — qemu-bridge-helper, /dev/kvm, "
            "route-helper netns, systemd scopes, cgroup v2, "
            "sandbox-lima-helper, or /etc/sandboxd/users.conf. See the "
            "marker's own comment at the test for which one."
        )

    if has_macos_only and sys.platform != "darwin":
        pytest.skip(
            "macos_only test; run on an Apple-Silicon Mac with the full "
            "sandboxd backend (socket_vmnet + restrict=on)."
        )

    if has_macos_only and sys.platform == "darwin":
        # Check whether the per-operator agent is available.  Two acceptable paths:
        # (1) The test-feature agent is running (launched by _macos_operator_agent) —
        #     covers SSH/Background sessions on the dev host.
        # (2) The production agent is loaded via launchctl in an Aqua/GUI session.
        has_lima = request.node.get_closest_marker("lima") is not None
        if has_lima:
            agent_available = (
                # Path 1: test-feature agent is up and running.
                (_macos_operator_agent is not None and _macos_operator_agent.poll() is None)
                # Path 2: production agent loaded via launchd (Aqua session).
                or _launchctl_agent_loaded()
            )
            if not agent_available:
                pytest.skip(
                    "macOS per-operator sandboxd agent is not available. "
                    "Two ways to satisfy this requirement: "
                    "(1) run `make install-agent-test` and use the cross-user "
                    "e2e harness (SSH/Background session) — the _macos_operator_agent "
                    "fixture will launch the test-feature agent automatically; "
                    "(2) log in to the macOS GUI and run the test from a "
                    "Terminal.app/iTerm2 session so the production LaunchAgent "
                    "(io.sandboxd.agent) is active."
                )


def _launchctl_agent_loaded() -> bool:
    """Return True when the production io.sandboxd.agent is loaded via launchctl."""
    uid = os.getuid()
    try:
        result = subprocess.run(
            ["launchctl", "print", f"user/{uid}/io.sandboxd.agent"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
