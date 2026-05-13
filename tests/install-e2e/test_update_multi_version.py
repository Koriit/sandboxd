"""Spec 5 § 9.1 tests that require a multi-version tarball harness.

These tests depend on a v' tarball whose binaries' compiled-in
`CARGO_PKG_VERSION` differs from the v tarball's. The
``release_tarball_x86_64_bumped`` fixture (see ``conftest.py``)
builds such a tarball by sed-rewriting every crate's
``Cargo.toml`` version, running ``cargo build --workspace
--release``, assembling the tarball, and restoring the originals
via an EXIT trap inside ``build-local-tarball.sh``. The bumped
artifact is cached at
``tests/install-e2e/dist/sandboxd-<bumped-version>-<arch>.tar.gz``
and re-used across runs when its mtime is newer than every
``*.rs`` file in the workspace.

The bumped binary's ``/version`` endpoint reports the bumped
version literally, so ``test_update_fresh_install_to_next_version``
can assert "daemon at v' after the upgrade" against the genuine
binary output.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_fresh_install_to_next_version(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
):
    """Daemon reports v' after `sandbox update --from <bumped tarball>`.

    The base tarball ships v (CARGO_PKG_VERSION = workspace version);
    the bumped tarball ships v' (workspace version + 1 patch level)
    built from sed-rewritten Cargo.toml files. After the upgrade:

    * ``/version`` returns v' (the binary's compiled-in version);
    * ``.install-state.json``'s ``installed_version`` is v' (written
      by the update flow from the MANIFEST, which the build wrote with
      the bumped version too).

    Together these pin the multi-version-aware fields of Spec 5 § 9.1's
    fresh-install-to-next-version contract.
    """
    vm = vm_factory(distro_template)

    # Stage the base (v) tarball and install it.
    base_tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball_in_vm)

    r = vm.shell(install_sh_cmd(base_tarball_in_vm), timeout=600)
    assert r.returncode == 0, f"base install failed:\n{r.stdout}\n{r.stderr}"
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Sanity: pre-update daemon /version reports v.
    pre = vm.shell(
        "sudo curl -fsSL --unix-socket /run/sandbox/sandboxd.sock "
        "http://localhost/version | jq -r .version",
        check=True,
    ).stdout.strip()
    assert pre == base_ver, (
        f"pre-update daemon /version mismatch: got {pre}, expected {base_ver}"
    )

    # Stage the bumped (v') tarball and run `sandbox update --from <dir>`.
    #
    # Feed the staged-directory shape (`--from <dir>`), not the tarball:
    # the CLI's § 3.1.10 sigstore precondition only fires when
    # `from.is_file()` is true, so a directory short-circuits the
    # cosign call. The test harness has no host-side cosign binary at
    # the canonical path (`_COSIGN_BOOTSTRAP_REPLACEMENT` in conftest.py
    # patches install.sh's bootstrap to a no-op), so a `--from <tarball>`
    # invocation would fail before reaching the multi-version contract
    # under test (Spec 5 § 9.1).
    bumped_tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)
    bumped_ver = version_from_tarball(bumped_tarball_in_vm)
    assert bumped_ver != base_ver, (
        f"bumped fixture produced the same version as base: {bumped_ver}; "
        "the multi-version contract requires distinct versions"
    )
    stage_dir = "/tmp/sandbox-update-multi-version-stage"
    arch = "x86_64-unknown-linux-gnu"
    vm.shell(
        f"sudo rm -rf {stage_dir} && mkdir -p {stage_dir} && "
        f"tar xzf {bumped_tarball_in_vm} -C {stage_dir}",
        check=True, timeout=60,
    )
    extracted_root = f"{stage_dir}/sandboxd-{bumped_ver}-{arch}"

    r = vm.shell(
        f"sudo sandbox update --from {extracted_root} --yes",
        timeout=600,
    )
    assert r.returncode == 0, (
        f"sandbox update failed:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # `update` restarts the daemon at § 3.2.26; the unit may still be
    # `activating` when the CLI returns. Wait for `active`.
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # 1. Daemon /version reports v'. The binary's CARGO_PKG_VERSION is
    # baked in at build time — this only passes against a real v'
    # binary (i.e., the multi-version harness was honoured).
    post = vm.shell(
        "sudo curl -fsSL --unix-socket /run/sandbox/sandboxd.sock "
        "http://localhost/version | jq -r .version",
        check=True,
    ).stdout.strip()
    assert post == bumped_ver, (
        f"post-update daemon /version mismatch: got {post}, expected {bumped_ver}.\n"
        f"If the values look identical to base_ver, the bumped tarball was "
        f"the same binary as base (multi-version harness skipped)."
    )

    # 2. Install-state advanced to v'. Spec 5 § 3.2.29.
    state = json.loads(
        vm.shell(
            "sudo cat /var/lib/sandbox/.install-state.json",
            check=True, timeout=10,
        ).stdout
    )
    assert state["installed_version"] == bumped_ver, (
        f"install-state did not advance to {bumped_ver}: {state!r}"
    )
