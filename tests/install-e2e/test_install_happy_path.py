"""Happy-path install tests across distros.

Covers the fresh-install matrix entries from.3:
- ``test_install_fresh_then_doctor_passes``      [ubuntu-22.04, debian-12]
- ``test_install_fresh_then_doctor_passes_rhel_paths`` [fedora-41]

These exercise the full install pipeline end-to-end and assert post-
conditions: binaries are in place with the expected modes/caps, the
systemd unit is installed, the sandbox user exists, doctor reports
green, and the install state file is well-formed.
"""

from __future__ import annotations

import pytest

from conftest import (
    assert_doctor_passes,
    assert_full_install_landed,
    copy_tarball_to_vm,
    install_sh_cmd,
    wait_for_socket,
    wait_for_systemd_active,
    DEFAULT_FEDORA,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04", "debian-12"])
def test_install_fresh_then_doctor_passes(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Fresh VM, install.sh runs, sandbox doctor reports green.

    Then uninstall.sh runs (without --purge) and we verify state is kept.

    Exercises the real cosign verify-blob path against the locally-signed
    tarball: install.sh runs unmodified; the SANDBOX_INSTALL_TEST_* env
    vars (set by ``install_sh_cmd`` when passed a ``sigstore_stack``
    handle) redirect cosign's trust material at the local stack.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Run install.sh with --from (skips the network download).
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\n"
        f"stderr:\n{r.stderr}"
    )

    # Post-conditions: binaries, caps, systemd unit, sandbox user,
    # well-formed install-state. Shared with the RHEL-paths variant.
    assert_full_install_landed(vm)

    # Bring the daemon up. `enable --now` fails if the gateway image is
    # missing, the route-helper caps are wrong, etc., so this is a
    # meaningful smoke before doctor runs.
    vm.shell(
        "sudo systemctl enable --now sandboxd", check=True, timeout=60,
    )
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Doctor must report 0 failed checks — the test name promises green.
    # `assert_doctor_passes` enforces both the exit code AND the
    # "checks passed, 0 failed" output token per.2.
    assert_doctor_passes(vm)

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
    # Per-uid state dir kept (no --purge).
    assert vm.shell(
        "SUID=$(id -u sandbox); sudo test -d /var/lib/sandboxd/$SUID"
    ).returncode == 0, "per-uid state dir should be kept without --purge"


@pytest.mark.parametrize("distro_template", [DEFAULT_FEDORA])
def test_install_fresh_then_doctor_passes_rhel_paths(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """RHEL-family path coverage: bridge-helper under /usr/libexec/.

    Fedora ships ``qemu-bridge-helper`` at /usr/libexec/qemu-bridge-helper
    (vs. /usr/lib/qemu/qemu-bridge-helper on Debian-likes). Install.sh's
    probe step has to find both. OVMF lives at /usr/share/edk2/ovmf/ on
    Fedora; the prereq check also has to find both.

    Asserts the same filesystem post-conditions as the Debian-family
    variant (binaries, caps, state file, sandbox user) plus that the
    bridge-helper probe resolved to the Fedora-layout path AND that the
    running daemon reports doctor-green — the test name promises green
    on RHEL paths; previously only log-content was checked, allowing an
    install that emitted the right log but landed nothing to pass.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed on {distro_template} (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The install log records the RHEL bridge-helper path.
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=bridge_helper_probe" in log
    assert "/usr/libexec/qemu-bridge-helper" in log, (
        "expected RHEL bridge-helper path in install log; got:\n" + log
    )

    # The probe resolved to the real Fedora-layout binary — verify the
    # file actually exists at that path (a log line alone could be
    # written by a broken probe that never resolved).
    assert vm.shell(
        "test -x /usr/libexec/qemu-bridge-helper",
    ).returncode == 0, "Fedora qemu-bridge-helper not found at /usr/libexec/"

    # Shared filesystem-state asserts (binaries, caps, state, user).
    assert_full_install_landed(vm)

    # Doctor green on RHEL paths too. Same enable + wait + doctor as the
    # Debian-family variant.
    vm.shell(
        "sudo systemctl enable --now sandboxd", check=True, timeout=60,
    )
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)
    assert_doctor_passes(vm)
