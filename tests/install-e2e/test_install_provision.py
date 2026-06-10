"""Provision-phase coverage: install.sh WITH provisioning (container backend).

This test exercises the provision phase end-to-end — specifically ``run_provision``
and the ``ui_animator_start`` call inside it — which is intentionally excluded from
every other install-e2e test (all of which pass ``--no-provision``).

The container backend builds the lite image inside the VM using Docker (no nested
KVM required).  The Lima backend is also attempted but is expected to fail or be
skipped on the e2e hosts (no nested KVM); ``run_provision`` is non-fatal on per-
backend failure so the overall install still exits 0.

Regression guard: before the ``ui_animator_start "${1:-}"`` fix in ``ui.sh``,
calling ``ui_animator_start`` with no argument caused ``sh: 1: parameter not set``
(dash set -u) and an exit-2 abort under ``curl | sh`` (RICH_UI=1, stdout is a tty).
This test must FAIL on the unfixed installer and PASS with the fix.

The test is intentionally limited to ubuntu-22.04 (the primary CI target) to keep
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
