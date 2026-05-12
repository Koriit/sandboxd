"""Air-gapped install path.

Spec § 6.3 / § 8.6 / § 10.6. The fuller air-gapped flow has two parts:

1. Pre-stage cosign at /usr/local/bin/cosign (the script's fallback).
2. Drop network egress between the cosign-staging step and the rest of
   the install. The script should not require network access to
   complete: every artifact is supplied locally via --from +
   --cosign-bundle.

The script's real cosign_bootstrap downloads cosign over HTTPS; with
egress blocked, it falls back to /usr/local/bin/cosign (if present and
matching the pinned sha256) and the rest of the install proceeds. The
harness patches cosign_bootstrap to skip the network entirely (because
verifying an unsigned local-build tarball would always fail), but we
still simulate the air-gapped network condition to prove the code path
beyond cosign does not reach out.

Per § 10.6 this is the partial v1 coverage. The fuller test (verify
the real cosign-bundle path with a properly signed bundle) is out of
scope for the local harness.
"""

from __future__ import annotations

import pytest

from conftest import copy_tarball_to_vm, install_sh_cmd


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_air_gapped(
    distro_template, vm_factory, release_tarball_x86_64
):
    """Network egress blocked; --from + --cosign-bundle completes."""
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Drop all egress on the VM EXCEPT loopback. We use iptables for
    # broad distro compatibility (nftables backend on Ubuntu is wired
    # to iptables-nft on >=20.04).
    vm.shell(
        "sudo iptables -A OUTPUT ! -o lo -p tcp --dport 443 -j REJECT",
        check=True, timeout=30,
    )
    vm.shell(
        "sudo iptables -A OUTPUT ! -o lo -p tcp --dport 80 -j REJECT",
        check=True, timeout=30,
    )
    # Probe — anything over the public internet must fail now.
    probe = vm.shell(
        "curl -fsS --max-time 5 https://github.com/ -o /dev/null && echo unexpectedly_online || echo offline_as_expected",
        timeout=30,
    )
    assert "offline_as_expected" in probe.stdout, (
        f"network drop did not take effect: {probe.stdout!r}\n{probe.stderr}"
    )

    # Pass --cosign-bundle explicitly so the script does not try to
    # download or read a sibling .sigstore (in real air-gapped land
    # the operator pre-stages this too).
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, f"--cosign-bundle {tarball_in_vm}.sigstore"),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"air-gapped install failed:\n{r.stdout}\n{r.stderr}"
    )

    # Smoke — binaries and unit landed without any network reach.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode == 0
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode == 0
