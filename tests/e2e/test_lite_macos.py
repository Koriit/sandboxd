"""E2E tests for the macOS lite-mode container backend.

These tests cover the macOS-specific lite path where sandbox containers run
inside the ``sandboxd-gateway`` Lima VM over its forwarded Docker socket.

Architecture under test:
- Sandbox containers run inside the gateway Lima VM (not on the macOS host).
- Every ``docker`` call goes through the forwarded socket
  (``gateway-docker.sock``).
- The gateway container + nft pipeline provide egress interception identical
  to Linux from the container's perspective.
- The ``sandbox-route-helper --vm-gateway-mode`` installs the default route
  inside the sandbox container's netns from within the gateway VM.
- A session-count token is claimed from ``VmnetPool`` but no NIC slot is
  allocated (lite sessions have no socket_vmnet attachment).

These tests require:
- A running ``sandboxd-gateway`` Lima instance with Docker provisioned.
- The ``sandbox-route-helper`` binary installed and setcap'd in the gateway VM
  at ``/usr/local/libexec/sandboxd/sandbox-route-helper``.
- The lite container image (``sandboxd-lite:<version>``) loaded in the
  gateway VM's Docker daemon.
- ``make setup-dev-env`` run at least once on this host.

DO NOT RUN during CI without the gateway VM provisioned.
Invoke manually after gateway bring-up:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_lite_macos.py -v --timeout=600

Individual test estimated runtime: 30–90 s.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

import pytest

from conftest import PLATFORM, _SANDBOX_TEST_UID

# ---------------------------------------------------------------------------
# Platform guard: skip entire file on Linux.
# These tests target the macOS lite path and require the gateway Lima VM.
# ---------------------------------------------------------------------------
pytestmark = [
    pytest.mark.macos_only,
    pytest.mark.container,
    pytest.mark.skipif(
        os.uname().sysname != "Darwin",
        reason="macOS lite tests require the sandboxd-gateway Lima VM",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sandbox(*args, check: bool = True, capture: bool = True, **kwargs):
    """Run the ``sandbox`` CLI and return the CompletedProcess."""
    cmd = ["sandbox"] + list(args)
    if capture:
        return subprocess.run(
            cmd,
            check=check,
            capture_output=True,
            text=True,
            **kwargs,
        )
    return subprocess.run(cmd, check=check, **kwargs)


def _sandbox_json(*args, **kwargs):
    """Run ``sandbox`` and parse stdout as JSON."""
    result = _sandbox(*args, **kwargs)
    return json.loads(result.stdout)


def _inspect_one(session_name: str, **kwargs) -> dict:
    """Inspect a single session and return its object.

    ``sandbox inspect <name> [<name>...]`` prints a JSON ARRAY (one object
    per arg), so a single-session inspect must be indexed ``[0]``.
    """
    arr = _sandbox_json("inspect", session_name, **kwargs)
    return arr[0]


def _count_running() -> int:
    """Count Running sessions by parsing the ``sandbox ps`` human TABLE.

    There is no JSON-all-sessions command. ``sandbox ps`` prints a
    space-separated table with a header row:
        ID  NAME  STATE  BACKEND  AGENT  GATEWAY  CREATED
    In the TABLE the STATE column is Capitalized (``Running`` / ``Stopped``),
    unlike the inspect JSON's lowercase. Skip the header and count rows whose
    STATE column equals ``Running``.
    """
    result = _sandbox("ps")
    count = 0
    for line in result.stdout.splitlines():
        cols = line.split()
        if not cols:
            continue
        # Skip the header row.
        if cols[0] == "ID" or ("NAME" in cols and "STATE" in cols):
            continue
        # Columns: ID NAME STATE BACKEND AGENT GATEWAY CREATED
        if len(cols) >= 3 and cols[2] == "Running":
            count += 1
    return count


def _wait_for_running(session_name: str, timeout: int = 60) -> None:
    """Poll until the session reaches running state."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            arr = _sandbox_json("inspect", session_name)
            if arr and arr[0].get("state") == "running":
                return
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(2)
    raise TimeoutError(
        f"Session {session_name!r} did not reach running within {timeout}s"
    )


def _session_exists(session_name: str) -> bool:
    result = _sandbox("inspect", session_name, check=False)
    return result.returncode == 0


def _daemon_log_path(sandbox_daemon: dict) -> Path:
    """Return the path to the e2e daemon's tracing log on macOS.

    On macOS the harness launches the daemon with
    ``--log-file <base_dir>/sandboxd.log`` (see conftest's
    ``_macos_argv_extras``); all ``tracing`` output — including the
    ``warn!`` TCC-asymmetry line emitted during lite ``shared:`` create —
    lands there, NOT on the daemon's stdout/stderr. (The ``_stdout_log`` /
    ``_stderr_log`` files in ``sandbox_daemon`` only capture the pre-tracing
    ``eprintln!`` fallback path, so they do not contain the warning.)
    """
    return Path(sandbox_daemon["base_dir"]) / "sandboxd.log"


def _read_daemon_log(sandbox_daemon: dict) -> str:
    """Read the daemon tracing log, routing through the daemon test user.

    The daemon writes ``sandboxd.log`` as ``PLATFORM.daemon_test_user`` under
    its per-uid base dir; depending on the daemon's umask the file may not be
    group-readable by the operator. Read it via ``sudo -n -u <daemon_test_user>
    cat`` (pre-authorized NOPASSWD by ``make setup-dev-env``) so the read
    succeeds regardless of the file's group bits — the same cross-user read
    pattern ``test_golden_image._meta_read_text`` uses for daemon-owned files.

    Returns "" if the log does not exist yet (never-written).
    """
    log_path = _daemon_log_path(sandbox_daemon)
    result = subprocess.run(
        ["sudo", "-n", "-u", PLATFORM.daemon_test_user, "cat", str(log_path)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        # Missing file is expected before the daemon first writes; any other
        # failure (e.g. sudo mis-scoped) surfaces as empty text and the caller
        # asserts on the missing warning with a diagnostic dump.
        return ""
    return result.stdout


def _gateway_vm_sees_path(host_path: str) -> bool:
    """Return True if the daemon's gateway VM sees ``host_path`` via 9p.

    On macOS lite the sandbox container's Docker runs *inside* the daemon's
    ``sandboxd-gateway`` Lima VM, so a ``shared:`` bind source is resolved
    against the VM filesystem — specifically the read-write 9p mount of the
    lite shared root (``/tmp/sandbox-shared``) that ``generate_gateway_template``
    injects as a ``mounts:`` stanza (identity mount: host ``/tmp/sandbox-shared``
    → VM ``/tmp/sandbox-shared``). A host path created under that root is only
    visible in the VM when QEMU's virtfs 9p export is bound to the *current*
    host inode.

    There is a real macOS hazard here: macOS clears ``/private/tmp`` (``/tmp``
    is a symlink to it) on reboot and periodically, so if the gateway VM
    out-lived a ``/tmp/sandbox-shared`` recreation, QEMU holds a handle to the
    now-deleted boot-time inode and the 9p mount is *stale* — host-side changes
    (and even the directory's contents) are invisible in the VM, and a
    ``docker create --mount src=<under-root>`` fails with
    ``bind source path does not exist``. A gateway-VM restart rebinds the
    export to the live inode. This probe distinguishes a live export (test can
    proceed) from a stale one (test skips with a precise reason).

    The gateway VM lives under the *daemon's* own LIMA_HOME
    (``/var/lib/sandboxd/<daemon_uid>/<daemon_uid>/lima``), owned 0600/0700 by
    the daemon test user — the operator (this test process) cannot ``limactl
    shell`` it directly. We therefore reach it via ``sudo -n -u
    <daemon_test_user>`` (pre-authorized NOPASSWD by ``make setup-dev-env``),
    with ``LIMA_HOME`` and ``HOME`` set to the daemon's paths — the exact
    invocation the daemon itself uses for every gateway-VM control operation.
    """
    daemon_uid = _SANDBOX_TEST_UID
    daemon_home = f"/var/lib/sandboxd/{daemon_uid}"
    lima_home = f"/var/lib/sandboxd/{daemon_uid}/{daemon_uid}/lima"
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "-u",
            PLATFORM.daemon_test_user,
            "env",
            f"LIMA_HOME={lima_home}",
            f"HOME={daemon_home}",
            "limactl",
            "shell",
            "sandboxd-gateway",
            "--",
            "test",
            "-d",
            host_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _route_cli_to_e2e_daemon(sandbox_binaries, sandbox_daemon):
    """Point this module's bare ``sandbox`` calls at the e2e daemon socket.

    The helpers in this file (``_sandbox`` and friends) invoke the ``sandbox``
    CLI by bare name and without an explicit ``--socket`` flag. By default that
    resolves whatever ``sandbox`` is on ``PATH`` (usually nothing on a dev host)
    talking to the *operator's* default socket
    (``$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock`` or
    ``~/.local/share/sandboxd/sandboxd.sock``). The e2e harness, however, builds
    the CLI under ``sandboxd/target/debug/`` and runs the daemon as the
    cross-user ``_sandboxd-test`` system user with a socket under
    ``/var/lib/sandboxd/<daemon-test-uid>/sandboxd.sock`` (mode 0660, group
    ``_sandboxd-test``) — exactly the daemon the green ``test_lite.py`` /
    ``test_policy.py`` suites drive via the ``sandbox_cli`` fixture's
    ``--socket {sandbox_daemon["socket"]}`` against ``sandbox_binaries.sandbox``.

    Rather than rewrite every bare ``_sandbox`` call site, this autouse,
    module-scoped fixture brings the file into line with that working pattern:

    1. depends on ``sandbox_daemon`` so the cross-user daemon is launched (and
       torn down) by the standard conftest fixture — the same daemon the rest
       of the e2e suite uses;
    2. prepends the harness-built CLI's directory
       (``sandbox_binaries.sandbox``'s parent) to ``PATH`` so the bare
       ``sandbox`` invocations resolve the freshly-built binary, not a stray
       installed one; and
    3. exports ``SANDBOX_SOCKET`` into the process environment for the duration
       of this module so those invocations reach the e2e daemon. The CLI
       honours ``SANDBOX_SOCKET`` as the socket override (``--socket`` still
       takes precedence, but none of the helpers pass it).

    The previous values are restored on teardown so other modules are
    unaffected.
    """
    socket_path = sandbox_daemon["socket"]
    cli_dir = str(Path(sandbox_binaries.sandbox).resolve().parent)

    prev_socket = os.environ.get("SANDBOX_SOCKET")
    prev_path = os.environ.get("PATH", "")
    os.environ["SANDBOX_SOCKET"] = socket_path
    os.environ["PATH"] = os.pathsep.join([cli_dir, prev_path]) if prev_path else cli_dir
    try:
        yield
    finally:
        if prev_socket is None:
            os.environ.pop("SANDBOX_SOCKET", None)
        else:
            os.environ["SANDBOX_SOCKET"] = prev_socket
        os.environ["PATH"] = prev_path


@pytest.fixture()
def lite_session(request):
    """Create a lite session and tear it down after the test.

    Yields the session name. On teardown, stops and removes the session
    regardless of test outcome.
    """
    name = f"e2e-lite-macos-{int(time.time())}"
    created = False
    try:
        result = _sandbox("create", "--lite", "--name", name, capture=True)
        assert result.returncode == 0, (
            f"sandbox create --lite failed:\n{result.stderr}"
        )
        created = True
        _wait_for_running(name)
        yield name
    finally:
        if created and _session_exists(name):
            _sandbox("stop", name, check=False)
            _sandbox("rm", name, check=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLiteMacosCreate:
    """Session creation + basic lifecycle for the macOS lite path."""

    def test_create_lite_session_reaches_running(self, lite_session):
        """A lite session created on macOS must reach Running state.

        This exercises the full create flow:
        - session-count token claim (no NIC slot)
        - in-VM Docker bridge creation via forwarded socket
        - gateway container setup (deny-all + health + DNAT)
        - sandbox container create + start inside the gateway VM
        - in-VM route-helper invocation (--vm-gateway-mode)
        - state transition to Running
        """
        info = _inspect_one(lite_session)
        assert info["state"] == "running", (
            f"Expected running, got {info['state']!r}"
        )
        assert info["backend"] == "container", (
            f"Expected container backend, got {info['backend']!r}"
        )

    def test_lite_session_has_no_vmnet_slot(self, lite_session):
        """A lite session must not consume a NIC slot.

        Lite sessions claim a session-count token from VmnetPool but
        leave ``vmnet_slot`` as None — the in-VM Docker bridge replaces
        the socket_vmnet segment.
        """
        info = _inspect_one(lite_session)
        network = info.get("network", {})
        assert network.get("vmnet_slot") is None, (
            f"Lite session must not hold a vmnet_slot, got: {network!r}"
        )

    def test_lite_session_stop_and_restart(self, lite_session):
        """Lite sessions must survive stop → start cycle.

        On stop: gateway container + Docker network are removed, lite token
        is released.
        On start: a new bridge + gateway are created inside the VM.
        """
        _sandbox("stop", lite_session)
        # Wait for stopped.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            info = _inspect_one(lite_session)
            if info["state"] == "stopped":
                break
            time.sleep(2)
        else:
            pytest.fail("Session did not reach stopped within 30s")

        # Restart.
        _sandbox("start", lite_session)
        _wait_for_running(lite_session, timeout=90)
        info = _inspect_one(lite_session)
        assert info["state"] == "running"

    def test_lite_session_remove(self):
        """A lite session can be created and then fully removed.

        This exercises the rm path: gateway teardown + Docker network
        deletion + lite token release + store row removal.
        """
        name = f"e2e-lite-macos-rm-{int(time.time())}"
        _sandbox("create", "--lite", "--name", name)
        _wait_for_running(name)
        _sandbox("stop", name)
        _sandbox("rm", name)
        assert not _session_exists(name), (
            "Session row must be removed after sandbox rm"
        )


# curl exit codes that all mean "egress was blocked" on the lite path:
#   6  — could not resolve host (CoreDNS answered NXDOMAIN for a denied domain)
#   7  — failed to connect (route/nft refused the connection)
#   28 — operation timed out (packets dropped, no response within --max-time)
#   35 — TLS handshake failure (connection reached but was RST'd mid-handshake)
#   56 — failure receiving network data (connection RST after connect)
# A denied domain never resolves (NXDOMAIN) so 6 is the common case, but the
# block can also surface as any of the connect/timeout/reset signatures; we
# accept the whole set so the assertion is robust to which layer trips.
_BLOCK_CURL_EXITS = {6, 7, 28, 35, 56}


class TestLiteMacosEgressInterception:
    """Verify egress is gated through the gateway pipeline."""

    def test_denied_egress_is_blocked(self, lite_session):
        """Traffic to a denied host must be blocked.

        The default policy denies all egress. A ``curl`` to an arbitrary
        external host from inside the sandbox container must fail with a
        block signature (could-not-resolve / refused / timeout / reset).

        We assert on the curl exit code rather than a ``query_denied`` event
        in the CoreDNS log: enforcement is what matters and it fires via the
        NXDOMAIN-before-forward path, but the JSONL event capture proved
        unreliable to assert on (the event stream is a best-effort
        observability sink, not the enforcement mechanism).
        """
        result = _sandbox(
            "exec",
            lite_session,
            "--",
            "curl",
            "--max-time",
            "8",
            "--silent",
            "--show-error",
            "http://example.com",
            check=False,
        )
        assert result.returncode in _BLOCK_CURL_EXITS, (
            "Expected curl to fail with a block signature "
            f"(exit in {sorted(_BLOCK_CURL_EXITS)}) but got exit "
            f"{result.returncode}.\nstdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}"
        )

    def test_allowed_domain_egress_on_lite_macos(self, tmp_path):
        """An ALLOWED domain must resolve AND reach its target on lite macOS.

        This is the egress-*allow* half of the network-control promise on the
        lite path — the direction that regressed because the gateway VM's
        CoreDNS forwarded to Docker's embedded DNS at 127.0.0.11, whose own
        upstream (the VM's 127.0.0.53 systemd-resolved stub) is a dead end, so
        an allowed domain SERVFAILed on the forward even though the policy
        admitted it. With the upstream forwarder pointed at reachable public
        resolvers, an allowed domain resolves and its egress opens; a
        non-allowed host still blocks (fail-closed intact).

        Policy: allow example.com:80/tcp at level=transport — the exact shape
        that is green on Linux (``test_policy.py::test_level1_transport_tcp``).
        """
        name = f"e2e-lite-allow-{int(time.time())}"
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "example.com",
                    "port": 80,
                    "protocol": "tcp",
                    "level": "transport",
                }
            ],
        }
        policy_path = tmp_path / "allow-example.json"
        policy_path.write_text(json.dumps(policy))

        created = False
        try:
            result = _sandbox(
                "create",
                "--lite",
                "--name",
                name,
                "--policy",
                str(policy_path),
                capture=True,
            )
            assert result.returncode == 0, (
                f"sandbox create --lite --policy failed:\n{result.stderr}"
            )
            created = True
            _wait_for_running(name)

            # The gate allow-list propagates asynchronously: after the policy
            # is applied, the first few queries for the allowed domain can
            # still miss until CoreDNS has the domain and the gate has admitted
            # the resolved IPs. This is a real (separate) propagation-timing
            # effect independent of the upstream-forwarder fix, so poll the
            # first nslookup for up to ~30s before asserting.
            nslookup = None
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                nslookup = _sandbox(
                    "exec", name, "--", "nslookup", "example.com", check=False
                )
                if nslookup.returncode == 0:
                    break
                time.sleep(3)
            assert nslookup is not None and nslookup.returncode == 0, (
                "Allowed domain example.com failed to resolve within 30s "
                "(egress-allow broken).\n"
                f"exit: {nslookup.returncode if nslookup else 'n/a'}\n"
                f"stdout: {nslookup.stdout if nslookup else ''!r}\n"
                f"stderr: {nslookup.stderr if nslookup else ''!r}"
            )

            # ALLOW: curl to the allowed domain must succeed (TCP passthrough).
            curl_allowed = _sandbox(
                "exec",
                name,
                "--",
                "curl",
                "--max-time",
                "30",
                "--silent",
                "--show-error",
                "http://example.com",
                check=False,
            )
            assert curl_allowed.returncode == 0, (
                "curl to the ALLOWED example.com must succeed (exit 0).\n"
                f"exit: {curl_allowed.returncode}\n"
                f"stdout: {curl_allowed.stdout!r}\nstderr: {curl_allowed.stderr!r}"
            )
            assert "Example Domain" in curl_allowed.stdout, (
                "Response body from the allowed example.com must contain "
                f"'Example Domain'.\nstdout: {curl_allowed.stdout!r}"
            )

            # DENY (fail-closed still holds): a NON-allowed host must be
            # blocked even though a sibling domain is allowed.
            curl_denied = _sandbox(
                "exec",
                name,
                "--",
                "curl",
                "--max-time",
                "8",
                "--silent",
                "--show-error",
                "http://blocked-example-xyz.com",
                check=False,
            )
            assert curl_denied.returncode in _BLOCK_CURL_EXITS, (
                "A non-allowed host must stay blocked (fail-closed) even with "
                "an allow rule for a sibling domain. Expected curl exit in "
                f"{sorted(_BLOCK_CURL_EXITS)} but got {curl_denied.returncode}.\n"
                f"stdout: {curl_denied.stdout!r}\nstderr: {curl_denied.stderr!r}"
            )
        finally:
            if created and _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)

    def test_ssh_access_works_over_forwarded_socket(self, lite_session):
        """SSH into the lite session must work without a login-session agent.

        This is the headline lite-on-macOS promise: an SSH-only (no GUI, no
        per-operator LaunchAgent) operator can use lite sessions. The CLI
        proxy path uses the forwarded Docker socket for the socat transport
        instead of a limactl shell into a per-operator VM.
        """
        result = _sandbox(
            "exec",
            lite_session,
            "--",
            "echo",
            "hello-from-lite-macos",
        )
        assert result.returncode == 0, (
            f"sandbox exec failed:\n{result.stderr}"
        )
        assert "hello-from-lite-macos" in result.stdout


class TestLiteMacosPoolAccounting:
    """Verify pool accounting: session-count token claimed, no NIC slot."""

    def test_mixed_lima_and_lite_under_session_cap(self):
        """A mix of Lima and lite sessions must both count against the cap.

        This test creates one lite session and verifies the session count
        increases, then removes it and verifies the count decreases.

        Live pool-cap enforcement (exhaustion) is not tested here because it
        would require creating max_macos_sessions concurrent sessions — too
        slow for E2E. The hermetic unit tests in network.rs cover exhaustion.
        """
        name = f"e2e-lite-pool-{int(time.time())}"
        try:
            # Before create: record current running-session count.
            before_count = _count_running()

            _sandbox("create", "--lite", "--name", name)
            _wait_for_running(name)

            after_count = _count_running()
            assert after_count == before_count + 1, (
                f"Expected {before_count + 1} running sessions, got {after_count}"
            )

        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)


class TestLiteMacosWorkspaceSetup:
    """Repo-clone and boot-command create-time setup for the lite macOS path.

    Both ``--repo`` and ``--boot-cmd`` run inside the sandbox container via
    the backend-agnostic ``GuestConnector`` after the runtime starts. On the
    lite macOS path that connector reaches the container through the gateway
    VM's forwarded Docker socket (``docker exec … socat``), so these tests
    prove the setup steps run over the forwarded-socket transport.
    """

    def test_repo_clone_on_lite_macos(self, tmp_path):
        """``--repo`` clones a git repository into the lite container workspace.

        Mirrors the Linux/cross-backend ``test_workspace.py::test_clone_repo``:
        create with ``--repo <url>`` plus a policy that admits the clone host,
        then assert the tree landed with a ``.git`` directory and a working
        ``git log``. The daemon hard-codes the clone destination to
        ``/home/sandbox/workspace/`` (see the container create handler in
        ``sandboxd/src/main.rs``), so we assert there directly rather than via
        ``guest_home(backend)``.

        The clone runs *during* create, so its source must already exist
        before create — an in-container ``file://`` path is not available at
        that point. We therefore clone the same public repo the Linux test
        uses (``octocat/Hello-World``) and gate it on an allow policy for the
        clone host (``github.com:443``). The lite egress-*allow* direction is
        already proven independently by
        ``test_allowed_domain_egress_on_lite_macos``, so a clone failure here
        points at the repo-clone dispatch, not the allow path.
        """
        name = f"e2e-lite-clone-{int(time.time())}"
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "github.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "transport",
                }
            ],
        }
        policy_path = tmp_path / "allow-github.json"
        policy_path.write_text(json.dumps(policy))

        created = False
        try:
            result = _sandbox(
                "create",
                "--lite",
                "--name",
                name,
                "--policy",
                str(policy_path),
                "--repo",
                "https://github.com/octocat/Hello-World.git",
                capture=True,
            )
            assert result.returncode == 0, (
                "sandbox create --lite --repo failed — the clone runs during "
                "create, so a non-zero exit means the guest `git clone` (over "
                "the forwarded Docker socket) or its egress-allow policy "
                f"regressed.\nstdout: {result.stdout!r}\nstderr: {result.stderr!r}"
            )
            created = True
            _wait_for_running(name)

            # The daemon clones into /home/sandbox/workspace/. Assert .git
            # landed there (the definitive "clone happened" signal).
            git_dir = _sandbox(
                "exec",
                name,
                "--",
                "test",
                "-d",
                "/home/sandbox/workspace/.git",
                check=False,
            )
            assert git_dir.returncode == 0, (
                "Expected /home/sandbox/workspace/.git to exist after "
                f"--repo clone, but `test -d` returned {git_dir.returncode}.\n"
                f"stdout: {git_dir.stdout!r}\nstderr: {git_dir.stderr!r}"
            )

            # And it must be a valid repo with at least one commit — mirrors
            # the `git log --oneline -1` assertion in the Linux test.
            git_log = _sandbox(
                "exec",
                name,
                "--",
                "git",
                "-C",
                "/home/sandbox/workspace/",
                "log",
                "--oneline",
                "-1",
                check=False,
            )
            assert git_log.returncode == 0, (
                "git log in the cloned workspace failed (clone incomplete or "
                f"not a repo).\nstdout: {git_log.stdout!r}\n"
                f"stderr: {git_log.stderr!r}"
            )
        finally:
            if created and _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)

    def test_boot_cmd_on_lite_macos(self, tmp_path):
        """``--boot-cmd`` runs a command inside the lite container at create.

        The daemon executes ``bash -c <cmd>`` in the container via the
        ``GuestConnector`` right after the runtime starts (see the ``--boot-cmd``
        block in the container create handler in ``sandboxd/src/main.rs``). A
        non-zero boot-command exit marks the whole session ``Error`` and aborts
        create, so create succeeding *is* the primary contract; we additionally
        assert an observable side effect — the boot command writes a sentinel
        file — which a follow-up ``sandbox exec`` reads back.

        There is no dedicated Linux e2e boot-cmd test to mirror line-for-line
        (the workspace suite documents boot-cmd in its module docstring but the
        behaviour is pinned by the Rust integration tests, e.g.
        ``integration_create_session_container``, which set ``boot_cmd``). This
        mirrors that integration coverage at the e2e/CLI surface using the
        confirmed ``--boot-cmd`` flag (``boot_cmd`` in
        ``sandbox-cli/src/main.rs``, kebab-cased by clap).
        """
        sentinel = "/home/sandbox/boot-cmd-ran.txt"
        marker = f"boot-cmd-ran-{int(time.time())}"
        name = f"e2e-lite-boot-{int(time.time())}"

        created = False
        try:
            result = _sandbox(
                "create",
                "--lite",
                "--name",
                name,
                "--boot-cmd",
                f"echo -n '{marker}' > {sentinel}",
                capture=True,
            )
            assert result.returncode == 0, (
                "sandbox create --lite --boot-cmd failed — an explicit "
                "boot-cmd that exits non-zero marks the session Error and "
                "aborts create, so a non-zero create exit means the boot "
                "command did not run (or failed) inside the container.\n"
                f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
            )
            created = True
            _wait_for_running(name)

            # Observable side effect: the sentinel the boot command wrote must
            # be present with the exact marker contents. This fails if the
            # boot command silently no-op'd (never ran) even though create
            # returned 0.
            cat = _sandbox(
                "exec",
                name,
                "--",
                "cat",
                sentinel,
                check=False,
            )
            assert cat.returncode == 0, (
                f"Expected the boot-cmd sentinel {sentinel} to exist, but "
                f"`cat` returned {cat.returncode} (boot command did not run).\n"
                f"stdout: {cat.stdout!r}\nstderr: {cat.stderr!r}"
            )
            assert marker in cat.stdout, (
                "Boot-cmd sentinel exists but its contents do not match — "
                f"expected {marker!r} in the file.\nstdout: {cat.stdout!r}"
            )
        finally:
            if created and _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)


class TestLiteMacosWorkspace:
    """Workspace mode tests for the macOS lite path."""

    @pytest.mark.skip(
        reason=(
            "macOS lite local: workspace without an explicit guest path is a known "
            "edge case. The host-path-echo default (guest_path == host_path) fails "
            "when the echoed path (e.g. /private/var/folders/... or /private/tmp) "
            "cannot be materialised inside the lite container: the container root fs "
            "is read-only, so `docker exec mkdir -p /private/...` exits non-zero. "
            "The daemon now surfaces this as an actionable error that names the "
            "guest path it tried to create, states that the container root fs is "
            "read-only, and points the operator at the explicit-guest-path form "
            "local:<host>:<guest>. This is an intentional, documented limitation "
            "of the host-path-echo default on the lite backend — not a latent bug "
            "to fix. The test body below was written for the success path and is "
            "kept as a reference for when an explicit-guest-path test is added."
        )
    )
    def test_local_workspace_mode(self, tmp_path):
        """``local:`` workspace mode on the lite macOS path — success path reference.

        The host-path-echo default (``local:<host>`` with no explicit guest) fails
        on the lite backend when the echoed path is outside a writable mount (the
        container root fs is read-only). The daemon surfaces an actionable error
        naming the guest path it tried and pointing at ``local:<host>:<guest>``.

        This test body was written for the success path and is preserved as a
        reference. A separate test exercising ``local:<host>:<guest>`` (explicit
        guest under the sandbox home) would be the correct positive-path coverage.
        """
        workspace = tmp_path / "project"
        workspace.mkdir()
        (workspace / "hello.txt").write_text("hello-lite-local")

        guest_file = f"{workspace}/hello.txt"

        name = f"e2e-lite-local-{int(time.time())}"
        try:
            _sandbox(
                "create",
                "--lite",
                "--name",
                name,
                "--workspace",
                f"local:{workspace}",
            )
            _wait_for_running(name)

            result = _sandbox("exec", name, "--", "cat", guest_file)
            assert "hello-lite-local" in result.stdout
        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)

    def test_shared_workspace_tcc_warning(self, sandbox_daemon, tmp_path):
        """``shared:`` workspace on lite emits a TCC-asymmetry warning AND is
        accepted when the source is under the configured shared root.

        On macOS lite the sandbox container's Docker runs *inside* the daemon's
        ``sandboxd-gateway`` Lima VM, so a ``shared:`` bind source resolves
        against the VM filesystem — specifically the read-write 9p mount of the
        lite shared root (default ``/tmp/sandbox-shared``, see
        ``sandbox-core/src/lite_macos.rs`` and the ``mounts:`` stanza
        ``generate_gateway_template`` injects in ``gateway_lima.rs``). The mount
        is an identity mount: host ``/tmp/sandbox-shared/<x>`` is visible in the
        VM at the same absolute path. So the source must (a) live under
        ``/tmp/sandbox-shared`` on the HOST — validated by ``validate_shared_path``
        in the create handler — and (b) be surfaced to the VM by a *live* 9p
        export.

        The gateway VM reads the shared path as ``_sandboxd`` (the gateway VM
        user), not the operator, so the daemon warns operators about the TCC
        asymmetry at create time. For a source *under* the configured shared
        root the daemon logs an informational ``warn!`` and proceeds — it does
        NOT reject the path (rejection is reserved for sources outside the root).

        This test asserts BOTH halves of that contract:

        1. ``sandbox create`` returns 0 (accepted), and the session reaches
           Running; and
        2. the daemon tracing log contains the TCC-asymmetry warning line the
           create handler emits.

        The warning goes to the daemon tracing log, not the CLI output, so we
        read ``<base_dir>/sandboxd.log`` (via the daemon test user). Because we
        assert on ``returncode == 0`` explicitly, this test can no longer pass
        silently when create fails — a create failure fails the first
        assertion, and a missing warning fails the second.

        The distinctive substring asserted is a stable, em-dash-free slice of
        the source ``warn!`` message in ``sandboxd/src/main.rs``:
        "access runs as _sandboxd (gateway VM user)".

        Live-export guard: macOS clears ``/private/tmp`` (``/tmp`` symlinks to
        it) on reboot / periodically, so if the daemon's gateway VM out-lived a
        ``/tmp/sandbox-shared`` recreation, QEMU's virtfs 9p export is bound to
        a now-deleted inode and host-created sources are invisible in the VM —
        ``docker create --mount src=<under-root>`` then fails with
        ``bind source path does not exist``. That is an environment/VM-lifecycle
        state (fixed by restarting the gateway VM), NOT a product regression, so
        we probe the export first and ``skip`` with a precise reason when it is
        stale rather than fail spuriously. When the export is live the strong
        assertions above still hold and a genuine create/warning regression
        fails loudly.
        """
        # The source must live under the configured lite shared root
        # (default /tmp/sandbox-shared) or the daemon rejects it before the
        # informational warning path — so this is a hard prerequisite, not an
        # environment-dependent maybe. `make setup-dev-env` establishes this
        # root (0755) before the gateway VM is provisioned.
        shared_root = "/tmp/sandbox-shared"
        os.makedirs(shared_root, exist_ok=True)
        workspace = os.path.join(shared_root, f"test-{int(time.time())}")
        os.makedirs(workspace, exist_ok=True)

        # Verify the daemon's gateway VM actually sees the source via its 9p
        # mount. If the export is stale (see the live-export guard note in the
        # docstring), skip with a precise, actionable reason — the source is
        # correctly provisioned on the host but the VM cannot resolve the bind.
        if not _gateway_vm_sees_path(workspace):
            pytest.skip(
                "lite shared: source is provisioned on the host under "
                f"{shared_root} but the gateway VM's 9p export cannot see it "
                f"({workspace!r} is absent inside the VM). This is a stale QEMU "
                "virtfs export: macOS cleared /private/tmp (/tmp -> /private/tmp) "
                "after the daemon's sandboxd-gateway VM booted, so QEMU holds a "
                "handle to the deleted boot-time /tmp/sandbox-shared inode. "
                "docker-create in the VM would fail with 'bind source path does "
                "not exist'. Fix: restart the gateway VM (it rebinds the export "
                "to the live inode) — e.g. re-run make setup-dev-env after "
                "ensuring /tmp/sandbox-shared exists, then bounce the daemon so "
                "ensure_ready() restarts sandboxd-gateway."
            )

        # Distinctive, stable slice of the TCC ``warn!`` message emitted by the
        # container create handler for lite shared: sessions under the root.
        tcc_warning_needle = "access runs as _sandboxd (gateway VM user)"

        name = f"e2e-lite-shared-{int(time.time())}"
        try:
            result = _sandbox(
                "create",
                "--lite",
                "--name",
                name,
                "--workspace",
                f"shared:{workspace}",
                check=False,
            )
            assert result.returncode == 0, (
                "sandbox create --lite --workspace shared:<under-root> must be "
                "ACCEPTED (the source is under the configured shared root and "
                "the gateway VM's 9p export sees it), but create failed with "
                f"exit {result.returncode}.\n"
                f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
            )
            _wait_for_running(name, timeout=60)
            info = _inspect_one(name)
            assert info["state"] == "running", (
                f"Expected running after accepted shared: create, got "
                f"{info['state']!r}"
            )

            # The TCC-asymmetry warning must have been logged during create.
            log_text = _read_daemon_log(sandbox_daemon)
            assert tcc_warning_needle in log_text, (
                "Expected the lite shared: TCC-asymmetry warning "
                f"({tcc_warning_needle!r}) in the daemon log at "
                f"{_daemon_log_path(sandbox_daemon)}, but it was absent. "
                "The create handler must warn that lite shared: access runs "
                "as _sandboxd, not the operator.\n"
                f"(daemon log length: {len(log_text)} bytes)"
            )
        finally:
            if _session_exists(name):
                _sandbox("stop", name, check=False)
                _sandbox("rm", name, check=False)
            import shutil as _shutil
            _shutil.rmtree(workspace, ignore_errors=True)
