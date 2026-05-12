"""`sandbox update` completes with all network egress blocked — Spec 5 §§ 6.3, 9.1.

Operator scenario: a host with no internet access (e.g. enterprise
network with strict egress policy). They've fetched the release
tarball + sigstore bundle out of band; ``sandbox update --from
<tarball>`` should complete without any outbound network call.

Network access points the flow could touch (Spec 5 § 12):
  * GitHub Releases API — opt-out via ``--from``.
  * GitHub Releases tarball CDN — opt-out via ``--from``.
  * Sigstore Rekor / cosign verify — wired in a later milestone but
    documented as opt-out via ``--cosign-bundle``.

This test boots a VM, installs the daemon, blocks every outbound
connection (iptables REJECT on OUTPUT), then runs ``sandbox update
--from <bumped> --yes`` and asserts the run completes.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    make_bumped_tarball,
    retag_gateway_image_in_vm,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
)


def _bump_patch(version):
    parts = version.split(".")
    if len(parts) != 3:
        raise AssertionError(f"unexpected version shape: {version}")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_air_gapped(
    distro_template, vm_factory, release_tarball_x86_64, tmp_path
):
    """Install the daemon, drop egress, run `sandbox update --from`.

    Assertions:
      * Update exits 0.
      * install_state's installed_version is the bumped target.
      * The daemon is reachable on its UDS afterwards.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    # Initial install with network available.
    r = vm.shell(install_sh_cmd(base_tarball), timeout=600)
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Pre-stage the bumped tarball (still requires network for tar
    # operations in pinned mode? No — the build is host-side; copy is
    # already done by `copy_tarball_to_vm` BEFORE egress drop).
    bumped_ver = _bump_patch(base_ver)
    bumped = make_bumped_tarball(release_tarball_x86_64, bumped_ver,
                                 dst_dir=tmp_path)
    bumped_in_vm = copy_tarball_to_vm(vm, bumped)
    retag_gateway_image_in_vm(
        vm,
        from_tag=f"sandbox-gateway:{base_ver}",
        to_tag=f"sandbox-gateway:{bumped_ver}",
    )

    # Warm up iptables.
    vm.shell(
        "set -eux; "
        "export DEBIAN_FRONTEND=noninteractive; "
        "sudo apt-get install -y --no-install-recommends iptables; "
        "sudo iptables -w 30 -L OUTPUT >/dev/null",
        check=True, timeout=180,
    )
    # Block egress (keep ESTABLISHED so limactl shell survives).
    vm.shell(
        "set -eux; "
        "sudo iptables -w 30 -A OUTPUT -m conntrack "
        "    --ctstate ESTABLISHED,RELATED -j ACCEPT; "
        "sudo iptables -w 30 -A OUTPUT -o lo -j ACCEPT; "
        "sudo iptables -w 30 -A OUTPUT -j REJECT",
        check=True, timeout=120,
    )
    # Confirm egress is blocked.
    probe = vm.shell(
        "curl -fsS --max-time 5 https://github.com/ -o /dev/null && "
        "echo unexpectedly_online || echo offline_as_expected",
        timeout=30,
    )
    assert "offline_as_expected" in probe.stdout, (
        f"egress not blocked: {probe.stdout!r}"
    )

    # The real test: sandbox update completes despite egress block.
    r = vm.shell(
        f"sudo sandbox update --from {bumped_in_vm} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"air-gapped update failed:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # State updated.
    state = json.loads(
        vm.shell(
            "sudo cat /var/lib/sandbox/.install-state.json",
            check=True, timeout=10,
        ).stdout
    )
    assert state["installed_version"] == bumped_ver, (
        f"install-state mismatch: {state!r}"
    )

    # Daemon back up.
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)
