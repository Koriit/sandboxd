"""Uninstall coverage — clean, purge, and double-run cases.

Spec §§ 6.3, 8.5. Three cases:

- ``test_uninstall_after_install_clean`` — install, then uninstall (no
  --purge), assert state dir kept, user kept.
- ``test_uninstall_with_purge_removes_user_and_state`` — install, then
  uninstall --purge --yes, assert sandbox user gone, /var/lib/sandbox/
  gone, gateway docker image rm'd.
- ``test_uninstall_double_run_idempotent`` — install, uninstall,
  uninstall again; second run is no-op.
"""

from __future__ import annotations

import pytest

from conftest import copy_tarball_to_vm, install_sh_cmd, parse_install_log_actions


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_uninstall_after_install_clean(
    distro_template, vm_factory, release_tarball_x86_64
):
    """No-purge uninstall leaves state dir intact."""
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    r = vm.shell(
        "sudo bash /tmp/uninstall.sh --yes --no-color --force",
        timeout=300,
    )
    assert r.returncode == 0, f"uninstall failed:\n{r.stdout}\n{r.stderr}"

    # Binaries / unit gone, state and user kept.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode != 0
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode != 0
    assert vm.shell("sudo test -d /var/lib/sandbox").returncode == 0
    assert vm.shell("id sandbox").returncode == 0


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_uninstall_with_purge_removes_user_and_state(
    distro_template, vm_factory, release_tarball_x86_64
):
    """--purge --yes removes /var/lib/sandbox/, sandbox user, and gateway image."""
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    r = vm.shell(
        "sudo bash /tmp/uninstall.sh --yes --purge --no-color --force",
        timeout=300,
    )
    assert r.returncode == 0, f"purge uninstall failed:\n{r.stdout}\n{r.stderr}"

    # Everything is gone.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode != 0
    assert vm.shell("sudo test -d /var/lib/sandbox").returncode != 0, (
        "purge did not remove /var/lib/sandbox/"
    )
    # getent passwd sandbox returns empty.
    r = vm.shell("getent passwd sandbox")
    assert r.returncode != 0 or not r.stdout.strip(), (
        "sandbox user still present after --purge"
    )
    # Gateway docker image gone.
    r = vm.shell("docker image inspect sandbox-gateway:0.1.0")
    assert r.returncode != 0, "gateway image still present after --purge"


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_uninstall_double_run_idempotent(
    distro_template, vm_factory, release_tarball_x86_64
):
    """Second uninstall is a no-op (every step logs skip)."""
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    # First uninstall.
    r = vm.shell(
        "sudo bash /tmp/uninstall.sh --yes --no-color --force",
        timeout=300,
    )
    assert r.returncode == 0, f"first uninstall failed:\n{r.stdout}\n{r.stderr}"

    # Truncate log so the second pass is what we read back.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Second uninstall.
    r = vm.shell(
        "sudo bash /tmp/uninstall.sh --yes --no-color --force",
        timeout=300,
    )
    assert r.returncode == 0, f"second uninstall failed:\n{r.stdout}\n{r.stderr}"

    log2 = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True,
    ).stdout
    actions = parse_install_log_actions(log2)

    # Allow-list inversion: every action on the second pass MUST be
    # in this set. A forbidden-list lets new mutating actions (e.g.
    # ``disable``, ``stop``, ``remove_file`` — which uninstall.sh
    # already emits) slip through if not enumerated; allow-listing
    # fails closed when new step types are added.
    allowed_actions = {"skip"}
    for step, step_actions in actions.items():
        for a in step_actions:
            assert a in allowed_actions, (
                f"second uninstall emitted disallowed action: "
                f"step={step} action={a} (allowed: {allowed_actions})\n"
                f"Log:\n{log2}"
            )
