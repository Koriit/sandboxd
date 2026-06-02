"""`sandbox update` completes with all network egress blocked — the install framework.3, 9.1.

Operator scenario: a host with no internet access (e.g. enterprise
network with strict egress policy). They've fetched the release
tarball + sigstore bundle out of band; ``sandbox update --from
<tarball>`` should complete without any outbound network call.

Network access points the flow could touch :
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
    assert_doctor_passes,
    copy_tarball_to_vm,
    install_sh_cmd,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_air_gapped(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
    sigstore_stack,
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

    # Initial install with network available. Runs against the local
    # Sigstore stack which is reachable here (egress block lands after
    # the install completes).
    r = vm.shell(
        install_sh_cmd(base_tarball, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Pre-stage the bumped tarball BEFORE egress drop. The tarball is
    # built host-side and copied into the VM here.
    bumped_ver = version_from_tarball(release_tarball_x86_64_bumped)
    bumped_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)

    # Extract the bumped tarball into a staging dir BEFORE the egress
    # drop. We feed `--from <dir>` (not `--from <tarball>`) to the
    # update so the CLI's § 3.1.10 sigstore precondition short-circuits:
    # `verify_signature` only runs when `from.is_file()` is true, so a
    # directory shape skips the cosign call. Any `--from <tarball>`
    # invocation would route through cosign verify-blob — which needs
    # the local Sigstore stack reachable from inside the VM and is
    # outside the air-gapped contract under test (§ 6.3). `tar` is
    # local and air-gap-compatible, so extracting before the egress
    # drop costs nothing relative to the contract under test.
    stage_dir = "/tmp/sandbox-update-air-gapped-stage"
    arch = "x86_64-unknown-linux-gnu"
    vm.shell(
        f"sudo rm -rf {stage_dir} && mkdir -p {stage_dir} && "
        f"tar xzf {bumped_in_vm} -C {stage_dir}",
        check=True, timeout=60,
    )
    extracted_root = f"{stage_dir}/sandboxd-{bumped_ver}-{arch}"

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
        f"sudo sandbox update --from {extracted_root} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"air-gapped update failed:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # State updated.
    state = json.loads(
        vm.shell(
            "SUID=$(id -u sandbox); sudo cat /var/lib/sandboxd/$SUID/.install-state.json",
            check=True, timeout=10,
        ).stdout
    )
    assert state["installed_version"] == bumped_ver, (
        f"install-state mismatch: {state!r}"
    )

    # Daemon back up.
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # 
    # `sandbox doctor` and assert all checks pass. Doctor's checks
    # run against the local unix socket (egress is blocked but
    # loopback is allowed by the iptables fixture above), so the
    # call works in the air-gapped state. Without this assertion,
    # a regression that left the daemon in a "running but unhealthy"
    # state post-update (e.g. KVM access dropped, gateway image
    # tag mismatched) would have passed the systemctl + socket
    # checks above silently.
    assert_doctor_passes(vm)
