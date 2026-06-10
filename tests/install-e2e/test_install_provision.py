"""Provision-phase coverage: install.sh WITH provisioning (container backend).

This test exercises the provision phase end-to-end — specifically ``run_provision``
and the ``ui_animator_start`` call inside it — which is intentionally excluded from
every other install-e2e test (all of which pass ``--no-provision``).

The container backend builds the lite image inside the VM using Docker (no nested
KVM required).  The Lima backend is also attempted but is expected to fail or be
skipped on the e2e hosts (no nested KVM); ``run_provision`` is non-fatal on per-
backend failure so the overall install still exits 0.

Regression guard (RICH_UI=1 pty hang): the installer-hardening batch introduced a
FIFO+tee stderr capture in ``setup_stderr_log``.  The UI animator, spawned AFTER
``exec 2> FIFO``, inherited the FIFO write-end.  ``cleanup_tmpdir`` closed only the
parent's write-end via ``exec 2>/dev/tty`` then ``wait "$_stderr_tee_pid"``; because
the animator still held the write-end, tee never saw EOF and the wait deadlocked.
The fix replaces the FIFO+tee with a plain ``exec 2>> "$INSTALL_LOG"`` (regular-file
append, never blocks regardless of how many processes hold fd 2 open).

``test_install_with_provision_rich_ui`` guards this regression by running install.sh
under ``script -qec ... /dev/null`` so that stdout is a pty and ``RICH_UI=1``
activates the animator.  The test is bounded with a strict timeout so a hang fails
fast rather than hanging the suite indefinitely.

The tests are intentionally limited to ubuntu-22.04 (the primary CI target) to keep
wall-clock time manageable — the provision step adds ~3-5 min for the container
build on top of the normal install.
"""

from __future__ import annotations

import pytest

from conftest import (
    assert_doctor_passes,
    assert_full_install_landed,
    copy_tarball_to_vm,
    stage_sigstore_trust_material_in_vm,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
    _sh_quote,
)


def _install_sh_cmd_with_provision(tarball_in_vm, *, vm, sigstore_stack):
    """Build the install.sh invocation WITH provisioning (no --no-provision).

    Mirrors ``install_sh_cmd`` but omits the ``--no-provision`` flag so that
    ``run_provision`` actually executes.  Everything else (--from, --version,
    --yes, --no-color, sigstore trust material) is identical to the standard
    harness.
    """
    ver = version_from_tarball(tarball_in_vm)
    trust_env = stage_sigstore_trust_material_in_vm(vm, sigstore_stack)
    env_prefix = " ".join(f"{k}={_sh_quote(v)}" for k, v in trust_env.items()) + " "
    return " ".join([
        f"sudo {env_prefix}bash /tmp/install.sh",
        f"--from {tarball_in_vm}",
        f"--version {ver}",
        "--yes",
        "--no-color",
        # NOTE: --no-provision is intentionally ABSENT — this is what makes
        # the test exercise the provision phase.
    ])


def _install_sh_cmd_with_provision_rich_ui(tarball_in_vm, *, vm, sigstore_stack):
    """Build the install.sh invocation WITH provisioning AND a pty (RICH_UI=1).

    Wraps the install command in ``script -qec ... /dev/null`` so that stdout is
    a pseudo-tty, which makes ``ui_detect_tty`` set ``RICH_UI=1`` and spawn the
    background animator during ``run_provision``.

    ``--no-color`` is intentionally ABSENT so that ``NO_COLOR=0`` and the full
    rich-UI path activates.  ``--yes`` skips the interactive confirm-plan gate.

    The outer ``timeout`` guard is belt-and-suspenders: if the install hangs
    (deadlock in cleanup_tmpdir), ``timeout`` kills it after 30 s and returns
    exit 124, which the test asserts is not 124 with an explanatory message.
    """
    ver = version_from_tarball(tarball_in_vm)
    trust_env = stage_sigstore_trust_material_in_vm(vm, sigstore_stack)
    env_prefix = " ".join(f"{k}={_sh_quote(v)}" for k, v in trust_env.items()) + " "
    inner_cmd = " ".join([
        f"sudo {env_prefix}bash /tmp/install.sh",
        f"--from {tarball_in_vm}",
        f"--version {ver}",
        "--yes",
        # NOTE: --no-color and --no-provision are both intentionally ABSENT:
        # --no-color  : required so RICH_UI=1 and the animator spawns.
        # --no-provision: absent so run_provision (and the animator) execute.
    ])
    # Wrap in script(1) to allocate a pty for stdout.  script -qec runs CMD
    # under a pty and writes the transcript to /dev/null (we only care about
    # the exit code, and install.sh logs everything to /var/log/sandbox-install.log).
    # The outer timeout caps cleanup_tmpdir in case the hang regresses.
    return f"timeout 1800 script -qec {_sh_quote(inner_cmd)} /dev/null"


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
@pytest.mark.timeout(1800)
def test_install_with_provision_container_backend(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """install.sh WITH provisioning exits 0 and builds the container backend image.

    Exercises the provision phase (``run_provision``) and the ``ui_animator_start``
    call inside it.  The container backend (Docker, no nested KVM) must succeed.
    The Lima backend is expected to fail on these hosts (no nested KVM) but that
    failure is non-fatal per ``run_provision``'s design: the overall install exits 0
    and emits retry guidance.

    Steps:
    1. Fresh VM + install.sh run WITHOUT --no-provision.
    2. Assert install.sh exits 0.
    3. Assert full install landed (binaries, caps, systemd unit, sandbox user).
    4. Assert daemon is active and doctor passes.
    5. Assert the sandboxd-lite container image is present in the Docker store,
       proving the container provision step executed and succeeded.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    cmd = _install_sh_cmd_with_provision(
        tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack,
    )

    # Provision adds ~3-5 min on top of the normal install.
    r = vm.shell(cmd, timeout=900)
    assert r.returncode == 0, (
        f"install.sh WITH provisioning failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\n"
        f"stderr:\n{r.stderr}"
    )

    # Standard post-install checks.
    assert_full_install_landed(vm)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)
    assert_doctor_passes(vm)

    # The container backend provision step must have built the lite image.
    # The image tag pattern is ``sandboxd-lite:<daemon-version>``; we probe
    # by repository name since the exact version string lives in the tarball.
    r_img = vm.shell(
        "sudo -u sandbox docker image ls --format '{{.Repository}}:{{.Tag}}'"
        " | grep sandboxd-lite",
        timeout=30,
    )
    assert r_img.returncode == 0 and "sandboxd-lite" in r_img.stdout, (
        "sandboxd-lite image not found after install WITH provision — "
        "the container provision step may have silently failed.\n"
        f"docker image ls output:\n{r_img.stdout}"
    )

    # Verify the provision step was actually logged (not silently skipped).
    log_r = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    )
    assert "step=provision action=rebuild-image backend=container status=ok" in log_r.stdout, (
        "Install log does not contain a successful container provision entry.\n"
        f"Log tail:\n{log_r.stdout[-3000:]}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
@pytest.mark.timeout(2100)
def test_install_with_provision_rich_ui(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """install.sh WITH provisioning under a pty (RICH_UI=1) exits 0 without hanging.

    Regression guard for the cleanup_tmpdir deadlock: the installer-hardening batch
    routed fd 2 through a FIFO+tee background process; the UI animator (forked after
    the redirect) inherited the write-end of the FIFO.  cleanup_tmpdir closed only the
    parent's write-end and then waited for tee; because the animator still held a
    write-end open, tee never saw EOF and the wait deadlocked indefinitely.

    This test allocates a pty for install.sh's stdout (via ``script -qec``) so that
    ``RICH_UI=1`` activates and the animator actually spawns during ``run_provision``.
    An outer ``timeout`` in the install command and ``@pytest.mark.timeout`` on the
    test both bound the hang so the suite fails fast rather than blocking forever.

    The test must HANG (and time out) on the unfixed installer and PASS (exit 0,
    complete within the timeout) with the fix.

    Steps:
    1. Fresh VM + install.sh run under a pty WITHOUT --no-color or --no-provision.
    2. Assert install.sh exits 0 (not 124 which would indicate a timeout/hang).
    3. Assert full install landed (binaries, caps, systemd unit, sandbox user).
    4. Assert daemon is active and doctor passes.
    5. Assert the sandboxd-lite container image is present (container backend built).
    6. Assert install log contains a successful provision entry (not silently skipped).
    7. Assert install log contains the rich=yes entry confirming RICH_UI=1 was active.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    cmd = _install_sh_cmd_with_provision_rich_ui(
        tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack,
    )

    # Provision + rich UI adds ~3-5 min on top of the normal install.
    # The inner shell-level timeout is 1800 s; add 300 s headroom for the
    # limactl shell round-trip overhead.
    r = vm.shell(cmd, timeout=2100)

    assert r.returncode != 124, (
        "install.sh TIMED OUT under pty (RICH_UI=1) — cleanup_tmpdir deadlock "
        "regression: the animator likely held the FIFO write-end open and "
        "tee never received EOF.\n"
        f"stdout:\n{r.stdout}\n"
        f"stderr:\n{r.stderr}"
    )
    assert r.returncode == 0, (
        f"install.sh WITH provisioning + pty failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\n"
        f"stderr:\n{r.stderr}"
    )

    # Standard post-install checks.
    assert_full_install_landed(vm)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)
    assert_doctor_passes(vm)

    # Container provision must have succeeded.
    r_img = vm.shell(
        "sudo -u sandbox docker image ls --format '{{.Repository}}:{{.Tag}}'"
        " | grep sandboxd-lite",
        timeout=30,
    )
    assert r_img.returncode == 0 and "sandboxd-lite" in r_img.stdout, (
        "sandboxd-lite image not found after install WITH provision (pty) — "
        "the container provision step may have silently failed.\n"
        f"docker image ls output:\n{r_img.stdout}"
    )

    log_r = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    )
    assert "step=provision action=rebuild-image backend=container status=ok" in log_r.stdout, (
        "Install log does not contain a successful container provision entry.\n"
        f"Log tail:\n{log_r.stdout[-3000:]}"
    )

    # Confirm RICH_UI=1 was actually active during this run.  Without this check
    # the test would pass even if script(1) failed to allocate a pty and fell
    # back to non-tty mode.
    assert "rich=yes" in log_r.stdout, (
        "Install log does not contain rich=yes — RICH_UI=1 was not active.\n"
        "The pty allocation (script -qec) may have failed silently, or "
        "ui_detect_tty gated out of rich mode for another reason.\n"
        f"Log tail:\n{log_r.stdout[-3000:]}"
    )
