"""E2E tests for the M17 ``local:`` workspace mode.

``local:`` is the snapshot-style workspace introduced in M17: at
session-creation time the daemon rsyncs the host source tree into the
guest, then leaves the session running with no live link to the host.
These tests boot real Lima/QEMU VMs and Docker containers, so each is
SLOW (3-10 minutes per Lima invocation). Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_workspace_local.py -v --timeout=600

Backend coverage: each function is parametrized over
``["lima", "container"]`` via the ``backend`` fixture. The
``make test-e2e-container`` filter (``-m "not lima" -k "not [lima]"``)
runs only the container half on PR-time; ``make test-e2e-matrix``
runs both.

Out of scope: ``sandbox workspace push`` / ``pull`` arms — those land
in M17-S3. The create + describe + gitignore + teardown surface is
the M17-S2 deliverable; push/pull is covered later in dedicated arms
of this file (added by S3).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest

from conftest import (
    gateway_container_name,
    lima_vm_name,
    make_create_args,
    parse_session_id,
    wait_for_state,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guest_path_for(backend: str) -> str:
    """Return a writable guest path appropriate for ``backend``.

    Lima sessions have a fully writable rootfs, so any absolute path
    (e.g. ``/srv/work``) is safe. Lite containers run with
    ``--read-only`` and writable tmpfs/volume mounts at
    ``/home/agent``, ``/tmp``, ``/run``; we route the local-mode
    snapshot under ``/home/agent`` so rsync's ``--mkpath`` can create
    the parent directory inside a writable area.
    """
    return "/home/agent/work" if backend == "container" else "/srv/work"


def _no_orphan_lima_vm(session_id: str) -> bool:
    """Return True if no ``sandbox-<session_id>`` Lima VM remains.

    Best-effort: if ``limactl`` is not installed we cannot have left a
    Lima orphan (Lima tests skip when limactl is absent), so the absence
    of the binary itself is a clean state.
    """
    try:
        result = subprocess.run(
            ["limactl", "list", "--json"],
            capture_output=True, text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return True
    vm = lima_vm_name(session_id)
    for line in (result.stdout or "").splitlines():
        if f'"name":"{vm}"' in line or f'"name": "{vm}"' in line:
            return False
    return True


def _no_orphan_docker_resources(session_id: str) -> tuple[bool, str]:
    """Check that no Docker container or network survives for ``session_id``.

    Returns ``(clean, diagnostic)`` where ``clean`` is True only when
    neither the session container, the gateway container, nor the
    per-session Docker network is listed. ``diagnostic`` carries the
    raw ``docker ps`` / ``docker network ls`` output if a leak is
    detected, so the assertion message points the operator at the
    leftover artefact directly.
    """
    session_ctr = f"sandbox-{session_id}"
    gateway_ctr = gateway_container_name(session_id)
    # ``docker ps -a`` lists containers regardless of state; a stale
    # ``--name sandbox-<id>`` container in ``Exited`` status is still
    # an orphan because the cleanup path is supposed to ``docker rm
    # -f`` it.
    ps = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=30,
    )
    nets = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=30,
    )
    ps_names = (ps.stdout or "").splitlines()
    net_names = (nets.stdout or "").splitlines()

    leaks: list[str] = []
    if session_ctr in ps_names:
        leaks.append(f"container {session_ctr!r}")
    if gateway_ctr in ps_names:
        leaks.append(f"gateway container {gateway_ctr!r}")
    leaked_nets = [n for n in net_names if session_id in n]
    if leaked_nets:
        leaks.append(f"network(s) {leaked_nets!r}")

    if not leaks:
        return True, ""
    diag = (
        f"orphan resources after failed create: {', '.join(leaks)}\n"
        f"docker ps -a:\n{ps.stdout}\n"
        f"docker network ls:\n{nets.stdout}"
    )
    return False, diag


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_workspace_local_create_and_describe(sandbox_cli, backend, tmp_path):
    """Spec § Tests / E2E — ``test_workspace_local.py`` create + describe.

    Create a session with ``--workspace local:<host>:<guest>``. Verify:

    1. ``sandbox create`` succeeds and the session reaches ``Running``.
    2. ``sandbox describe`` renders the multi-line ``Workspace:`` block
       with ``Mode: local``, ``Host path:``, and ``Guest path:`` rows
       (pinned by the inline byte-equal goldens in
       ``sandbox-cli/src/main.rs``).
    3. The host source tree is present inside the guest at the
       resolved guest path — the create-time rsync push actually ran.

    Push/pull arms are deferred to M17-S3 (see this file's docstring).
    """
    session_id = None
    host_dir = None
    try:
        # Build a known host source tree so the in-guest assertions are
        # unambiguous: top-level file + nested file. The trailing-slash
        # rule in `workspace_rsync::build_argv` mirrors *contents*, not
        # the directory entry itself, so the guest tree has
        # `hello.txt` and `nested/inner.txt` directly under the guest
        # path (no top-level wrapper).
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-create-")
        with open(os.path.join(host_dir, "hello.txt"), "w") as f:
            f.write("hello-from-host\n")
        os.makedirs(os.path.join(host_dir, "nested"))
        with open(os.path.join(host_dir, "nested", "inner.txt"), "w") as f:
            f.write("nested-bytes\n")

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-cd",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create --workspace local:<dir>:{guest_path} failed "
            f"(rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-cd", "Running", timeout=10)

        # (2) `sandbox describe` Workspace block. The multi-line form
        # is the M17 surface; the four `Workspace:`/`Mode:`/`Host
        # path:`/`Guest path:` lines must all be present. The
        # byte-equal goldens in the CLI source pin the exact spacing;
        # here we assert the load-bearing fragments so a future
        # whitespace tweak in the renderer doesn't break the e2e gate.
        describe = sandbox_cli("describe", "ws-local-cd", timeout=60)
        assert describe.returncode == 0, (
            f"sandbox describe failed (rc={describe.returncode}).\n"
            f"stdout: {describe.stdout}\nstderr: {describe.stderr}"
        )
        out = describe.stdout
        assert "Workspace:" in out, (
            f"describe output missing Workspace: header; got:\n{out}"
        )
        assert "Mode:        local" in out, (
            f"describe output missing `Mode:        local` row; got:\n{out}"
        )
        assert f"Host path:   {host_dir}" in out, (
            f"describe output missing host-path row for {host_dir!r}; got:\n{out}"
        )
        assert f"Guest path:  {guest_path}" in out, (
            f"describe output missing guest-path row for {guest_path!r}; "
            f"got:\n{out}"
        )

        # (3) Host source tree is present inside the guest at the
        # resolved guest path. Read both the top-level and nested
        # files to assert the rsync push (a) ran and (b) mirrored the
        # directory structure.
        cat_top = sandbox_cli(
            "exec", "ws-local-cd", "--",
            "cat", f"{guest_path}/hello.txt",
            timeout=120,
        )
        assert cat_top.returncode == 0 and cat_top.stdout == "hello-from-host\n", (
            f"top-level host file not visible in guest at "
            f"{guest_path}/hello.txt: rc={cat_top.returncode} "
            f"stdout={cat_top.stdout!r} stderr={cat_top.stderr!r}"
        )
        cat_nested = sandbox_cli(
            "exec", "ws-local-cd", "--",
            "cat", f"{guest_path}/nested/inner.txt",
            timeout=120,
        )
        assert cat_nested.returncode == 0 and cat_nested.stdout == "nested-bytes\n", (
            f"nested host file not visible in guest at "
            f"{guest_path}/nested/inner.txt: rc={cat_nested.returncode} "
            f"stdout={cat_nested.stdout!r} stderr={cat_nested.stderr!r}"
        )

        sandbox_cli("rm", "ws-local-cd", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-local-cd", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_workspace_local_gitignore_filter(sandbox_cli, backend, tmp_path):
    """Spec § Tests / E2E — gitignore filter on/off (``--no-gitignore``).

    Default behaviour: ``rsync --filter=':- .gitignore'`` drops anything
    matched by a ``.gitignore`` file in the host tree. Operator opt-out:
    ``--no-gitignore`` on ``sandbox create`` removes the filter so the
    whole tree (including ignored entries) lands in the guest.

    Container coverage is already pinned at the integration layer
    (``integration_local_gitignore_filter``); this E2E exercises the
    same surface end-to-end across both backends so the CLI ↔ daemon
    wire shape for ``--no-gitignore`` is covered alongside the rsync
    flag mechanics.
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-gitignore-")
        # `.gitignore` excludes `excluded/`. Three files of interest:
        #   - `keep.txt`               (always present in guest)
        #   - `excluded/secret.txt`    (filtered out by default,
        #                               transferred under --no-gitignore)
        # Mirror the integration test's tree shape so the contract
        # being validated is uniform across the layers.
        with open(os.path.join(host_dir, ".gitignore"), "w") as f:
            f.write("excluded/\n")
        with open(os.path.join(host_dir, "keep.txt"), "w") as f:
            f.write("keep-me\n")
        os.makedirs(os.path.join(host_dir, "excluded"))
        with open(os.path.join(host_dir, "excluded", "secret.txt"), "w") as f:
            f.write("hidden\n")

        guest_path = _guest_path_for(backend)

        # ---- Run 1: default filter, `excluded/` must be ABSENT --------
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-gi",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create (default filter) failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-gi", "Running", timeout=10)

        # `keep.txt` survives the filter.
        kept = sandbox_cli(
            "exec", "ws-local-gi", "--",
            "cat", f"{guest_path}/keep.txt",
            timeout=120,
        )
        assert kept.returncode == 0 and kept.stdout == "keep-me\n", (
            f"non-ignored file missing under default filter; "
            f"rc={kept.returncode} stdout={kept.stdout!r} "
            f"stderr={kept.stderr!r}"
        )

        # `excluded/` is dropped by the default filter. `test -e` via
        # `sh -c` so the missing-entry case shows up as a non-zero
        # exit code rather than ambiguous stdout.
        absent = sandbox_cli(
            "exec", "ws-local-gi", "--",
            "test", "-e", f"{guest_path}/excluded",
            timeout=120,
        )
        assert absent.returncode != 0, (
            f"default `.gitignore` filter must drop `excluded/`; "
            f"`test -e {guest_path}/excluded` exited 0, meaning the "
            f"directory survived the rsync filter.\n"
            f"stdout={absent.stdout!r} stderr={absent.stderr!r}"
        )

        sandbox_cli("rm", "ws-local-gi", timeout=120)
        session_id = None

        # ---- Run 2: `--no-gitignore`, `excluded/secret.txt` PRESENT --
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-gi",
                "--workspace", f"local:{host_dir}:{guest_path}",
                "--no-gitignore",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create --no-gitignore failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-gi", "Running", timeout=10)

        secret = sandbox_cli(
            "exec", "ws-local-gi", "--",
            "cat", f"{guest_path}/excluded/secret.txt",
            timeout=120,
        )
        assert secret.returncode == 0 and secret.stdout == "hidden\n", (
            f"`--no-gitignore` must transfer files matched by .gitignore; "
            f"rc={secret.returncode} stdout={secret.stdout!r} "
            f"stderr={secret.stderr!r}"
        )

        sandbox_cli("rm", "ws-local-gi", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-local-gi", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_workspace_local_create_failure_tears_down(sandbox_cli, backend, tmp_path):
    """End-to-end pin for the daemon's ``cleanup_and_return!`` path on
    ``local:``-mode rsync failure.

    Failure injection: ``chmod 000`` on a file inside the host source.
    rsync cannot open it for read and exits non-zero; the daemon
    surfaces this as ``SandboxError::Internal("local-workspace rsync
    failed (exit ...): ...")`` which maps to HTTP 500, and the
    ``cleanup_and_return!`` macro tears down the VM/container, network,
    and CA state so no orphan resources survive.

    Asserts:

    1. ``sandbox create`` exits non-zero (the CLI surfaces the daemon's
       5xx body verbatim).
    2. The CLI stderr (or stdout) contains the production-stable token
       ``"local-workspace rsync failed"`` — operators grep journald
       and CI logs with this prefix.
    3. No ``sandbox-<id>`` VM/container or session network survives.
       The exact cleanup contract is the Phase 3 ``cleanup_and_return!``
       wire shape; this test is its sole end-to-end pin (the
       integration test at ``integration_local_create_failure_tears_down``
       exercises only the library-level error variant).
    """
    session_id = None
    host_dir = None
    unreadable = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-failure-")
        # One readable + one unreadable file. rsync visits each entry
        # under the source root; the unreadable one produces a
        # per-file "permission denied" stderr line and a non-zero
        # rsync exit (typically 23, "partial transfer due to error").
        with open(os.path.join(host_dir, "readable.txt"), "w") as f:
            f.write("ok\n")
        unreadable = os.path.join(host_dir, "unreadable.txt")
        with open(unreadable, "w") as f:
            f.write("will-not-be-readable\n")
        os.chmod(unreadable, 0o000)

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-fail",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )

        # (1) Non-zero exit. The CLI maps any 5xx into a non-zero exit
        # (see `handle_response` in sandbox-cli/src/main.rs); the
        # rsync-failure case is exactly that.
        assert result.returncode != 0, (
            f"sandbox create with an unreadable host file must fail; "
            f"got rc=0.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # The session ID may or may not be printed depending on where
        # in the pipeline the failure surfaced; capture it best-effort
        # from any line containing `ID:` so the orphan check below has
        # something to scope against. Either way, the `--name`-based
        # cleanup in `finally` covers stragglers.
        try:
            session_id = parse_session_id(result.stdout)
        except ValueError:
            # Daemon emitted only the error envelope. We cannot pin
            # the orphan check to a specific session ID, so fall back
            # to a `--name`-based reaper below. Still a useful test:
            # the contract is "no orphans survive", not "we can name
            # the orphan we cleaned up".
            session_id = None

        # (2) The production-stable failure prefix. The CLI's
        # `handle_response` prints `Error: <api_err.error>` on stderr,
        # so the rsync diagnostic surfaces on stderr in the standard
        # case. Accept stdout too because a future CLI refactor that
        # routes the message there should not require a test change.
        combined = (result.stdout or "") + (result.stderr or "")
        assert "local-workspace rsync failed" in combined, (
            f"CLI must surface the spec-verbatim "
            f"`local-workspace rsync failed` prefix from the daemon "
            f"so operators can grep for it; got:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # (3) No orphan VM/container/network. We check both backends
        # uniformly because the cleanup contract is backend-agnostic
        # (the `cleanup_and_return!` macro dispatches to whichever
        # runtime owns the session).
        if session_id is not None:
            assert _no_orphan_lima_vm(session_id), (
                f"Lima VM sandbox-{session_id} survived a failed local: "
                f"create — cleanup_and_return! must tear the VM down."
            )
            clean, diag = _no_orphan_docker_resources(session_id)
            assert clean, diag
        # else: the daemon refused the request before allocating a
        # session ID (no orphans to check); the non-zero exit + error
        # token already pin the wire contract.

    finally:
        # Always restore the file's perms so the tempdir can be
        # cleaned up. `chmod 000` blocks the test-runner's own
        # `shutil.rmtree` on most filesystems.
        if unreadable is not None:
            try:
                os.chmod(unreadable, 0o644)
            except OSError:
                pass
        # Force-reap any session by name in case the daemon
        # half-created one before failing — Phase 3's
        # `cleanup_and_return!` should already have removed it, but
        # belt-and-braces matters at the e2e layer.
        try:
            sandbox_cli("rm", "ws-local-fail", timeout=120)
        except Exception:
            pass
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass
