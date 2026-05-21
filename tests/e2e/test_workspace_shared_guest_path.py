"""E2E tests for the M17 ``shared:<host>:<guest>`` operator-supplied
guest-path branch.

M17-S1 promoted the historical fixed ``/home/agent/workspace`` mount
point into an operator-controllable guest path: ``--workspace
shared:<host>:<guest>`` lands the host directory at the chosen
``<guest>`` inside the session rather than the legacy default. The
runtime-layer integration tests already pin the bind-mount mechanics
on the container backend (``integration_shared_guest_path_container``);
the Lima half — which requires a real 9p mount and a booted VM — lives
here, alongside a parametrized container variant so the test name
covers both backends uniformly.

Boots real Lima VMs and Docker containers; expect 3-10 minutes per
parametrized invocation. Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_workspace_shared_guest_path.py -v --timeout=600

Backend coverage: parametrized over ``["lima", "container"]`` via the
``backend`` fixture. The guest path differs per backend because the
lite container backend is ``--read-only`` with writable areas at
``/home/agent``, ``/tmp``, ``/run`` only, while Lima sessions have a
fully writable rootfs. Both arms exercise the same wire surface — the
operator-supplied ``:<guest>`` token traversing CLI → daemon → backend
bind-mount.
"""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest

from conftest import (
    make_create_args,
    parse_session_id,
    wait_for_state,
)


def _guest_path_for(backend: str) -> str:
    """Return a writable guest path appropriate for ``backend``.

    Container backend: ``/home/agent/work`` so the 9p/bind target lands
    inside the lite image's writable-volume area. Lima backend:
    ``/srv/work`` to exercise an out-of-``/home/agent`` mount and
    confirm Lima's 9p materialisation honours operator paths anywhere
    on the rootfs.
    """
    return "/home/agent/work" if backend == "container" else "/srv/work"


@pytest.mark.timeout(600)
def test_workspace_shared_explicit_guest_path(sandbox_cli, backend, tmp_path):
    """Spec § Tests / E2E — ``test_workspace_shared_guest_path.py``.

    Create a session with ``--workspace shared:<host>:<guest>``. Verify:

    1. The mount appears at the operator-supplied ``<guest>`` path
       inside the session.
    2. A host-side file is visible in the guest at the same relative
       path (host → guest).
    3. A guest-side write is visible on the host (guest → host),
       pinning the bidirectional mount contract that ``shared:``
       guarantees.

    The lima backend's 9p mount and the container backend's docker
    bind-mount both honour the operator-supplied ``<guest>`` argument
    — this test pins that across both ends of the matrix.
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-shared-guest-")
        # Seed the host directory so the bind target is populated
        # *before* the session boots. This pins the "host file visible
        # at <guest> inside session" branch independently of any
        # subsequent host writes.
        with open(os.path.join(host_dir, "from_host.txt"), "w") as f:
            f.write("host-bytes\n")

        guest_path = _guest_path_for(backend)
        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-shared-gp",
                "--workspace", f"shared:{host_dir}:{guest_path}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create --workspace shared:<host>:{guest_path} failed "
            f"(rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-shared-gp", "Running", timeout=10)

        # (1) Host file is visible at the operator-supplied guest path.
        cat_seed = sandbox_cli(
            "exec", "ws-shared-gp", "--",
            "cat", f"{guest_path}/from_host.txt",
            timeout=120,
        )
        assert cat_seed.returncode == 0 and cat_seed.stdout == "host-bytes\n", (
            f"the operator-supplied :<guest_path> must mount the host "
            f"directory at exactly {guest_path} inside the session — "
            f"expected to read 'host-bytes' from "
            f"{guest_path}/from_host.txt\n"
            f"rc={cat_seed.returncode} stdout={cat_seed.stdout!r} "
            f"stderr={cat_seed.stderr!r}"
        )

        # (2) Host → guest, live: write a *new* host file after the
        # session is Running, assert it shows up. This proves the
        # mount is live, not a snapshot — distinguishes shared: from
        # local: at the e2e surface.
        host_file = os.path.join(host_dir, "late.txt")
        with open(host_file, "w") as f:
            f.write("appeared-after-boot\n")

        cat_late = sandbox_cli(
            "exec", "ws-shared-gp", "--",
            "cat", f"{guest_path}/late.txt",
            timeout=120,
        )
        assert cat_late.returncode == 0 and cat_late.stdout == "appeared-after-boot\n", (
            f"host-side post-boot writes must appear in the guest under "
            f"the shared-guest-path mount; bind/9p must be live, not a "
            f"snapshot.\n"
            f"rc={cat_late.returncode} stdout={cat_late.stdout!r} "
            f"stderr={cat_late.stderr!r}"
        )

        # (3) Guest → host: write from inside the session, assert the
        # file appears on the host at the bind source. Use bash -c so
        # the redirection happens inside the guest, not in the local
        # shell.
        exec_write = sandbox_cli(
            "exec", "ws-shared-gp", "--",
            "bash", "-c",
            f"echo -n 'guest-bytes' > {guest_path}/from_guest.txt",
            timeout=120,
        )
        assert exec_write.returncode == 0, (
            f"guest-side write into shared mount failed; "
            f"rc={exec_write.returncode} stdout={exec_write.stdout!r} "
            f"stderr={exec_write.stderr!r}"
        )

        host_side = os.path.join(host_dir, "from_guest.txt")
        assert os.path.exists(host_side), (
            f"guest-side writes must appear on the host at the bind "
            f"source — `shared:` is bidirectional by construction. "
            f"Expected file at {host_side!r}; host directory listing: "
            f"{os.listdir(host_dir)}"
        )
        with open(host_side) as f:
            assert f.read() == "guest-bytes", (
                f"host-visible contents of guest-side write mismatch at "
                f"{host_side}"
            )

        sandbox_cli("rm", "ws-shared-gp", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-shared-gp", timeout=120)
        if host_dir is not None:
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass
