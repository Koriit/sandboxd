"""Uninstall coverage — clean, purge, and double-run cases.

- ``test_uninstall_after_install_clean`` — install, then uninstall (no
  --purge), assert per-uid state dir kept, user kept.
- ``test_uninstall_with_purge_removes_user_and_state`` — install, then
  uninstall --purge --yes, assert sandbox user gone, per-uid state dir
  gone, gateway docker image rm'd.
- ``test_uninstall_double_run_idempotent`` — install, uninstall,
  uninstall again; second run is no-op.
"""

from __future__ import annotations

import pytest

from conftest import copy_tarball_to_vm, install_sh_cmd, parse_install_log_actions


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_uninstall_after_install_clean(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """No-purge uninstall leaves state dir intact."""
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"

    r = vm.shell(
        "sudo bash /tmp/uninstall.sh --yes --no-color --force",
        timeout=300,
    )
    assert r.returncode == 0, f"uninstall failed:\n{r.stdout}\n{r.stderr}"

    # Binaries / unit gone, per-uid state dir and user kept.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode != 0
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode != 0
    # Per-uid state dir must still be present (no --purge).
    assert vm.shell(
        "SUID=$(id -u sandbox); sudo test -d /var/lib/sandboxd/$SUID"
    ).returncode == 0, "per-uid state dir should be kept without --purge"
    assert vm.shell("id sandbox").returncode == 0


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_uninstall_with_purge_removes_user_and_state(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """--purge --yes removes the per-uid state dir, sandbox user, and gateway image."""
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
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
    # After the user is gone we cannot resolve its uid; check by looking for
    # any subdirectory of /var/lib/sandboxd that was the prod state.
    # The sandbox user uid was resolved before userdel by uninstall.sh —
    # verify the whole /var/lib/sandboxd tree is empty (no prod subtree left).
    r = vm.shell(
        "sudo test -d /var/lib/sandboxd && sudo ls /var/lib/sandboxd 2>/dev/null || true"
    )
    # If /var/lib/sandboxd still exists it must be empty (rmdir failed = not empty).
    # An empty dir is acceptable; a dir with contents is a bug.
    remaining = r.stdout.strip()
    assert not remaining, (
        f"purge left contents in /var/lib/sandboxd: {remaining!r}"
    )
    # Legacy dir also gone.
    assert vm.shell("sudo test -d /var/lib/sandbox").returncode != 0, (
        "purge did not remove legacy /var/lib/sandbox/"
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
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Second uninstall is a no-op (every step logs skip)."""
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
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
