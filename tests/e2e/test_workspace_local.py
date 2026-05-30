"""E2E tests for the ``local:`` workspace mode.

``local:`` is a snapshot-style workspace: at session-creation time the
daemon rsyncs the host source tree into the guest, then leaves the
session running with no live link to the host.
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

The push/pull arms (``test_workspace_local_push_propagates_host_edit``
et al.) exercise the operator-driven sync surface
(``sandbox workspace push`` / ``pull``). The container backend is
exercised exhaustively; selected push/pull arms parametrize over
``["lima", "container"]`` while the dry-run / dest-override /
no-gitignore variants run on the container backend only to keep the
matrix bounded.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest

from conftest import (
    LIMA_VM_HOME,
    gateway_container_name,
    lima_vm_name,
    limactl_cmd,
    make_create_args,
    parse_session_id,
    wait_for_state,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guest_path_for(backend: str) -> str:
    """Return a writable guest path appropriate for ``backend``.

    The on-create rsync push runs over the shell transport as
    ``agent`` (uid 1000), so the destination's parent must be
    writable by that uid. On both backends ``LIMA_VM_HOME`` (``/home/agent``)
    is ``agent``-owned, so ``/home/agent/work`` works uniformly. Other
    paths like ``/srv/work`` look attractive on Lima because the
    rootfs is fully writable, but only by ``root`` — rsync's
    ``--mkpath`` would need to ``mkdir`` under root-owned ``/srv``
    and fails with ``Permission denied (13)``.
    """
    return f"{LIMA_VM_HOME}/work"


def _no_orphan_lima_vm(session_id: str) -> bool:
    """Return True if no ``sandbox-<session_id>`` Lima VM remains.

    Best-effort: if ``limactl`` is not installed we cannot have left a
    Lima orphan (Lima tests skip when limactl is absent), so the absence
    of the binary itself is a clean state.

    Uses ``limactl_cmd()`` so the correct LIMA_HOME (``OP_LIMA_HOME``) is
    queried under the cross-user harness — bare ``limactl`` would query
    ``~/.lima/`` and report no orphan even when one exists.
    """
    try:
        result = subprocess.run(
            limactl_cmd("list", "--json"),
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
    """

    Create a session with ``--workspace local:<host>:<guest>``. Verify:

    1. ``sandbox create`` succeeds and the session reaches ``Running``.
    2. ``sandbox describe`` renders the multi-line ``Workspace:`` block
       with ``Mode: local``, ``Host path:``, and ``Guest path:`` rows
       (pinned by the inline byte-equal goldens in
       ``sandbox-cli/src/main.rs``).
    3. The host source tree is present inside the guest at the
       resolved guest path — the create-time rsync push actually ran.

    Push/pull arms are covered by separate tests (see this file's docstring).
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

        # (2) `sandbox describe` Workspace block. The four
        # `Workspace:`/`Mode:`/`Host path:`/`Guest path:` lines must
        # all be present in the multi-line form. The byte-equal
        # goldens in the CLI source pin the exact spacing; here we
        # assert the load-bearing fragments so a future whitespace
        # tweak in the renderer doesn't break the e2e gate.
        describe = sandbox_cli("describe", "ws-local-cd", timeout=60)
        assert describe.returncode == 0, (
            f"sandbox describe failed (rc={describe.returncode}).\n"
            f"stdout: {describe.stdout}\nstderr: {describe.stderr}"
        )
        out = describe.stdout
        assert "Workspace:" in out, (
            f"describe output missing Workspace: header; got:\n{out}"
        )
        assert "Mode:       local" in out, (
            f"describe output missing `Mode:       local` row; got:\n{out}"
        )
        assert f"Host path:  {host_dir}" in out, (
            f"describe output missing host-path row for {host_dir!r}; got:\n{out}"
        )
        assert f"Guest path: {guest_path}" in out, (
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
    """

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
            f"CLI must surface the design-verbatim "
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


# ---------------------------------------------------------------------------
# Push/pull arms — operator-driven sync after session create.
# ---------------------------------------------------------------------------

def _guest_write(backend: str, session_id: str, guest_path: str, body: str) -> None:
    """Write ``body`` into ``guest_path`` from inside the guest.

    Uses the backend's native exec transport — ``limactl shell`` for
    Lima, ``docker exec`` for the container backend. We avoid
    ``sandbox exec`` here because the workspace-lock state machine
    deliberately gates push/pull on a daemon-side mutex, and using the
    CLI to seed test fixtures keeps the test orthogonal to that gate.

    The body is piped to the guest via stdin (``tee >file``) so the
    bytes round-trip verbatim — no shell-quoting or backslash-escape
    interpretation. Trailing newlines in ``body`` are preserved.
    """
    if backend == "container":
        ctr = f"sandbox-{session_id}"
        argv = ["docker", "exec", "-i", ctr, "sh", "-c",
                f"cat > {guest_path}"]
    else:
        vm = lima_vm_name(session_id)
        argv = limactl_cmd("shell", vm, "sh", "-c",
                           f"cat > {guest_path}")
    proc = subprocess.run(
        argv, input=body, text=True,
        capture_output=True, timeout=60,
    )
    assert proc.returncode == 0, (
        f"failed to write {guest_path} in guest ({backend}): "
        f"rc={proc.returncode} stderr={proc.stderr!r}"
    )


@pytest.mark.timeout(600)
def test_workspace_local_push_propagates_host_edit(sandbox_cli, backend, tmp_path):
    """

    Create a ``local:`` session (which runs the initial create-time
    push). Edit a file on the host *after* the create-time push has
    mirrored the initial tree. Run ``sandbox workspace push -f
    <session>`` and assert the edit is visible inside the guest.

    Container coverage is the primary signal; Lima parametrization is
    best-effort and gated by host KVM/qemu-bridge-helper prereqs (the
    ``lima`` marker is set on the parametrize id by the harness).
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-push-host-")
        with open(os.path.join(host_dir, "edited.txt"), "w") as f:
            f.write("initial-bytes\n")

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-push-host",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-push-host", "Running", timeout=10)

        # Sanity: create-time push mirrored the initial bytes.
        seed = sandbox_cli(
            "exec", "ws-local-push-host", "--",
            "cat", f"{guest_path}/edited.txt", timeout=60,
        )
        assert seed.returncode == 0 and seed.stdout == "initial-bytes\n", (
            f"create-time push must seed `edited.txt`; got rc={seed.returncode} "
            f"stdout={seed.stdout!r} stderr={seed.stderr!r}"
        )

        # Edit the host file. The push must mirror this into the guest.
        with open(os.path.join(host_dir, "edited.txt"), "w") as f:
            f.write("host-edit-after-create\n")

        push = sandbox_cli(
            "workspace", "push", "-f", "ws-local-push-host",
            timeout=300,
        )
        assert push.returncode == 0, (
            f"sandbox workspace push -f failed (rc={push.returncode}).\n"
            f"stdout: {push.stdout}\nstderr: {push.stderr}"
        )

        post = sandbox_cli(
            "exec", "ws-local-push-host", "--",
            "cat", f"{guest_path}/edited.txt", timeout=60,
        )
        assert post.returncode == 0 and post.stdout == "host-edit-after-create\n", (
            f"host edit must propagate to guest after `workspace push -f`; "
            f"got rc={post.returncode} stdout={post.stdout!r} stderr={post.stderr!r}"
        )

        sandbox_cli("rm", "ws-local-push-host", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-local-push-host", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_workspace_local_pull_propagates_guest_edit(sandbox_cli, backend, tmp_path):
    """

    Create a ``local:`` session. Edit a file *inside the guest* (via
    the backend's native exec — ``docker exec`` / ``limactl shell``).
    Run ``sandbox workspace pull -f <session>`` and assert the edit is
    visible on the host at the recorded ``host_path``.

    Both backends parametrize; Lima is best-effort per the harness's
    ``lima`` marker / prereq check.
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-pull-host-")
        with open(os.path.join(host_dir, "from-guest.txt"), "w") as f:
            f.write("host-original\n")

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-pull-guest",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-pull-guest", "Running", timeout=10)

        # Edit the file from inside the guest. Use the backend's native
        # exec transport to keep the seed write orthogonal to the
        # daemon-side workspace-lock surface.
        _guest_write(
            backend, session_id, f"{guest_path}/from-guest.txt",
            "guest-edited\n",
        )

        pull = sandbox_cli(
            "workspace", "pull", "-f", "ws-local-pull-guest",
            timeout=300,
        )
        assert pull.returncode == 0, (
            f"sandbox workspace pull -f failed (rc={pull.returncode}).\n"
            f"stdout: {pull.stdout}\nstderr: {pull.stderr}"
        )

        with open(os.path.join(host_dir, "from-guest.txt")) as f:
            host_contents = f.read()
        assert host_contents == "guest-edited\n", (
            f"guest edit must appear on host after `workspace pull -f`; "
            f"host file contents: {host_contents!r}"
        )

        sandbox_cli("rm", "ws-local-pull-guest", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-local-pull-guest", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.container
@pytest.mark.timeout(600)
def test_workspace_local_push_dry_run(sandbox_cli, tmp_path):
    """

    Edit a host file. Run ``sandbox workspace push -n <session>`` and
    assert:

    1. The CLI exits 0 (dry-run is not a failure mode).
    2. The guest's view of the file is unchanged — dry-run mutates
       nothing.

    The CLI's rsync invocation does not pass ``-v``, so rsync's
    archive-mode dry-run is silent by default (no "would-transfer"
    file list on stdout); the load-bearing contract is that the
    guest tree is untouched.

    Container backend is enough to pin the dry-run contract; the
    planner is backend-uniform.
    """
    backend = "container"
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-push-dryrun-")
        with open(os.path.join(host_dir, "watched.txt"), "w") as f:
            f.write("pre-edit\n")

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-push-dry",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-push-dry", "Running", timeout=10)

        # Edit the host file *after* the create-time push so dry-run
        # has a real diff to report (otherwise rsync prints nothing).
        with open(os.path.join(host_dir, "watched.txt"), "w") as f:
            f.write("post-edit-but-not-pushed\n")

        dry = sandbox_cli(
            "workspace", "push", "-n", "ws-local-push-dry",
            timeout=120,
        )
        assert dry.returncode == 0, (
            f"sandbox workspace push -n must exit 0; "
            f"rc={dry.returncode}\nstdout: {dry.stdout}\nstderr: {dry.stderr}"
        )

        # The guest must still see the pre-edit contents — dry-run is
        # side-effect-free.
        post = sandbox_cli(
            "exec", "ws-local-push-dry", "--",
            "cat", f"{guest_path}/watched.txt", timeout=60,
        )
        assert post.returncode == 0 and post.stdout == "pre-edit\n", (
            f"dry-run must not mutate the guest; expected `pre-edit` in guest "
            f"after `push -n`, got rc={post.returncode} stdout={post.stdout!r}"
        )

        sandbox_cli("rm", "ws-local-push-dry", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-local-push-dry", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.container
@pytest.mark.timeout(600)
def test_workspace_local_pull_dest_override(sandbox_cli, tmp_path):
    """

    Create a ``local:`` session. Edit a guest file. Run ``sandbox
    workspace pull -f --dest <alt> <session>``. Assert:

    1. The edit appears at the ``--dest`` location.
    2. The original ``host_path`` is unchanged (the pull is routed
       elsewhere, not mirrored back to its create-time source).

    Container backend is enough — the override is CLI-side argv
    construction and backend-uniform.
    """
    backend = "container"
    session_id = None
    host_dir = None
    alt_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-pull-dest-src-")
        with open(os.path.join(host_dir, "rerouted.txt"), "w") as f:
            f.write("host-original\n")

        # `--dest` must name a non-file path (existing dir or
        # to-be-created dir). Provide an existing, empty dir to keep
        # the test orthogonal to the `create_dir_all(dirname(dest))`
        # branch — that branch is unit-tested.
        alt_dir = tempfile.mkdtemp(prefix="sandbox-local-pull-dest-alt-")

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-pull-dest",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-pull-dest", "Running", timeout=10)

        # Edit from inside the guest.
        _guest_write(
            backend, session_id, f"{guest_path}/rerouted.txt",
            "from-guest-rerouted\n",
        )

        pull = sandbox_cli(
            "workspace", "pull", "-f", "--dest", alt_dir,
            "ws-local-pull-dest",
            timeout=300,
        )
        assert pull.returncode == 0, (
            f"sandbox workspace pull --dest failed (rc={pull.returncode}).\n"
            f"stdout: {pull.stdout}\nstderr: {pull.stderr}"
        )

        # The guest edit landed at the override path.
        with open(os.path.join(alt_dir, "rerouted.txt")) as f:
            alt_contents = f.read()
        assert alt_contents == "from-guest-rerouted\n", (
            f"`--dest` must route the pull to the override path; "
            f"alt_dir contents: {alt_contents!r}"
        )

        # The original host_path is untouched — pull routed elsewhere.
        with open(os.path.join(host_dir, "rerouted.txt")) as f:
            orig_contents = f.read()
        assert orig_contents == "host-original\n", (
            f"`--dest` must leave the recorded host_path unchanged; "
            f"original host file: {orig_contents!r}"
        )

        sandbox_cli("rm", "ws-local-pull-dest", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-local-pull-dest", timeout=120)
        for d in (host_dir, alt_dir):
            if d is not None:
                try:
                    shutil.rmtree(d)
                except OSError:
                    pass


@pytest.mark.container
@pytest.mark.timeout(600)
def test_workspace_local_push_no_gitignore(sandbox_cli, tmp_path):
    """

    Create a session with a ``.gitignore`` that ignores ``excluded/``.
    The create-time filter drops ``excluded/`` from the guest. Run
    ``sandbox workspace push -f --no-gitignore <session>``. Assert the
    file lands in the guest — the post-create push filter is dropped.

    Container backend is enough — the planner contract is
    backend-uniform.
    """
    backend = "container"
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-local-push-nogi-")
        with open(os.path.join(host_dir, ".gitignore"), "w") as f:
            f.write("excluded/\n")
        os.makedirs(os.path.join(host_dir, "excluded"))
        with open(os.path.join(host_dir, "excluded", "file.txt"), "w") as f:
            f.write("formerly-ignored\n")

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-local-push-nogi",
                "--workspace", f"local:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-local-push-nogi", "Running", timeout=10)

        # Sanity: create-time filter dropped `excluded/`. If this
        # baseline fails the rest of the assertion is moot.
        baseline = sandbox_cli(
            "exec", "ws-local-push-nogi", "--",
            "test", "-e", f"{guest_path}/excluded",
            timeout=60,
        )
        assert baseline.returncode != 0, (
            f"baseline: create-time `.gitignore` filter must drop "
            f"`excluded/`; saw exit 0 from `test -e`."
        )

        push = sandbox_cli(
            "workspace", "push", "-f", "--no-gitignore",
            "ws-local-push-nogi",
            timeout=300,
        )
        assert push.returncode == 0, (
            f"sandbox workspace push -f --no-gitignore failed "
            f"(rc={push.returncode}).\n"
            f"stdout: {push.stdout}\nstderr: {push.stderr}"
        )

        post = sandbox_cli(
            "exec", "ws-local-push-nogi", "--",
            "cat", f"{guest_path}/excluded/file.txt",
            timeout=60,
        )
        assert post.returncode == 0 and post.stdout == "formerly-ignored\n", (
            f"`--no-gitignore` push must transfer files matched by "
            f".gitignore; rc={post.returncode} stdout={post.stdout!r} "
            f"stderr={post.stderr!r}"
        )

        sandbox_cli("rm", "ws-local-push-nogi", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-local-push-nogi", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass
