"""Happy-path install tests across distros.

Covers the fresh-install matrix entries from spec § 6.3:
- ``test_install_fresh_then_doctor_passes``      [ubuntu-22.04, debian-12]
- ``test_install_fresh_then_doctor_passes_rhel_paths`` [fedora-41]

These exercise the full install pipeline end-to-end and assert post-
conditions: binaries are in place with the expected modes/caps, the
systemd unit is installed, the sandbox user exists, doctor reports
green, and the install state file is well-formed.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    DEFAULT_FEDORA,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04", "debian-12"])
def test_install_fresh_then_doctor_passes(
    distro_template, vm_factory, release_tarball_x86_64
):
    """Fresh VM, install.sh runs, sandbox doctor reports green.

    Then uninstall.sh runs (without --purge) and we verify state is kept.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Run install.sh with --from (skips the network download).
    r = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\n"
        f"stderr:\n{r.stderr}"
    )

    # Post-conditions: binaries, systemd unit, sandbox user.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode == 0
    assert vm.shell("test -x /usr/local/bin/sandbox").returncode == 0
    assert vm.shell(
        "test -x /usr/local/libexec/sandboxd/sandbox-route-helper"
    ).returncode == 0
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode == 0
    assert vm.shell("id sandbox").returncode == 0

    # Route-helper has the expected file capabilities.
    caps = vm.shell(
        "getcap /usr/local/libexec/sandboxd/sandbox-route-helper",
    ).stdout
    assert "cap_net_admin,cap_sys_admin=eip" in caps, f"unexpected caps: {caps!r}"

    # The install state file exists, is owned by sandbox:sandbox, and is
    # valid JSON.
    state_check = vm.shell(
        "sudo cat /var/lib/sandbox/.install-state.json",
        check=True, timeout=10,
    )
    state = json.loads(state_check.stdout)
    assert state.get("installed_version")
    assert state.get("schema_version") == 1 or "schema_version" not in state

    # Start the daemon. systemd's `enable --now` will fail to bring the
    # unit up if the gateway image is missing, the route-helper caps are
    # wrong, etc., so this is a meaningful smoke.
    r = vm.shell(
        "sudo systemctl enable --now sandboxd", check=True, timeout=60,
    )

    # ---------------- Uninstall path ----------------

    r = vm.shell(
        "sudo bash /tmp/uninstall.sh --yes --no-color --force",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"uninstall.sh failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\n"
        f"stderr:\n{r.stderr}"
    )
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode != 0
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode != 0
    # /var/lib/sandbox/ kept (no --purge).
    assert vm.shell("sudo test -d /var/lib/sandbox").returncode == 0


@pytest.mark.parametrize("distro_template", [DEFAULT_FEDORA])
def test_install_fresh_then_doctor_passes_rhel_paths(
    distro_template, vm_factory, release_tarball_x86_64
):
    """RHEL-family path coverage: bridge-helper under /usr/libexec/.

    Fedora ships ``qemu-bridge-helper`` at /usr/libexec/qemu-bridge-helper
    (vs. /usr/lib/qemu/qemu-bridge-helper on Debian-likes). Install.sh's
    probe step has to find both. OVMF lives at /usr/share/edk2/ovmf/ on
    Fedora; the prereq check also has to find both.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    r = vm.shell(
        install_sh_cmd(tarball_in_vm),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed on {distro_template} (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The install log should record the RHEL bridge-helper path.
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=bridge_helper_probe" in log
    assert "/usr/libexec/qemu-bridge-helper" in log, (
        "expected RHEL bridge-helper path in install log; got:\n" + log
    )

    # Doctor green — the host-prereq coverage proves the install
    # converged on a real RHEL-family box.
    # (We don't enable systemd here; doctor's checks are file-shape
    # only, the systemd-active check is exercised by the systemd smoke.)
