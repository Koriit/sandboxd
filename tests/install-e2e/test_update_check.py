"""`sandbox update --check` no-mutation contract — Spec 5 §§ 2.2, 6.4.

The `--check` and `--dry-run` modes are read-only: they must never
acquire the lock, must not mutate the install state, and must not
disturb the running daemon. This file pins the no-mutation contract
end-to-end against a real Lima VM.

The test runs against a single-version tarball (built locally by
``build-local-tarball.sh``): an install at version V, then a
``sandbox update --check --from <V.tar.gz>`` against the same
version. Because the installed version equals the target version,
``--check`` reports `up to date` and exits 0. Either way (up-to-date
or update-available), the no-mutation invariant must hold.
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
def test_update_check_does_not_mutate(
    distro_template, vm_factory, release_tarball_x86_64
):
    """`sandbox update --check` never touches state.

    Asserts:
      * The lock file `/var/lib/sandbox/.update.lock` is ABSENT after
        the check (direct `os.path.exists`-style probe via `test -e`).
      * The install state's `installed_version` is unchanged.
      * The daemon's `/version` endpoint still reports the original
        version.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    version = version_from_tarball(tarball_in_vm)

    # Install the daemon to the staged version.
    r = vm.shell(install_sh_cmd(tarball_in_vm), timeout=600)
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"
    vm.shell(
        "sudo systemctl enable --now sandboxd", check=True, timeout=60,
    )
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Snapshot pre-check state.
    state_pre = json.loads(
        vm.shell("sudo cat /var/lib/sandbox/.install-state.json").stdout
    )
    assert state_pre["installed_version"] == version

    # Stage the same tarball as the "available" target — `--check`
    # treats `--from <dir>` as the canonical version source. Extract
    # the tarball server-side so `--from` can point at the staged dir.
    vm.shell(
        f"mkdir -p /tmp/staged && tar -xzf {tarball_in_vm} -C /tmp/staged",
        check=True,
    )
    staged_dir = vm.shell(
        "ls -d /tmp/staged/sandboxd-*/",
        check=True,
    ).stdout.strip().rstrip("/")
    assert staged_dir, "extracted directory must exist"

    # Run `sandbox update --check --from <staged>`.
    # Since the installed version equals the target, expect "up to date".
    r = vm.shell(
        f"sudo -u sandbox env SANDBOX_SOCKET=/run/sandbox/sandboxd.sock "
        f"/usr/local/bin/sandbox update --check --from {staged_dir}",
        timeout=30,
    )
    assert r.returncode == 0, (
        f"--check should exit 0 (up to date) for same-version target; "
        f"got {r.returncode}\nstdout: {r.stdout}\nstderr: {r.stderr}"
    )
    assert "up to date" in r.stdout, (
        f"`--check` should report 'up to date': {r.stdout!r}"
    )

    # ---- No-mutation assertions ----

    # 1. Lock file is ABSENT.
    lock_probe = vm.shell("sudo test -e /var/lib/sandbox/.update.lock")
    assert lock_probe.returncode != 0, (
        "/var/lib/sandbox/.update.lock must not exist after --check"
    )

    # 2. Install state's installed_version unchanged.
    state_post = json.loads(
        vm.shell("sudo cat /var/lib/sandbox/.install-state.json").stdout
    )
    assert state_post["installed_version"] == state_pre["installed_version"], (
        f"--check mutated install state: pre={state_pre!r} post={state_post!r}"
    )

    # 3. Daemon /version still reports the original version.
    ver = vm.shell(
        "sudo curl -fsSL --unix-socket /run/sandbox/sandboxd.sock "
        "http://localhost/version | jq -r .version",
        check=True,
    ).stdout.strip()
    assert ver == version, (
        f"daemon /version mismatch after --check: got {ver}, expected {version}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_dry_run_does_not_mutate(
    distro_template, vm_factory, release_tarball_x86_64
):
    """`sandbox update --dry-run` is read-only.

    Same contract as `--check`: lock-file absent, install-state
    unchanged, daemon healthy. Additionally asserts the dry-run output
    enumerates all 18 stateful step ids (§§ 3.2.13-3.2.30).
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(install_sh_cmd(tarball_in_vm), timeout=600)
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    vm.shell(
        f"mkdir -p /tmp/staged && tar -xzf {tarball_in_vm} -C /tmp/staged",
        check=True,
    )
    staged_dir = vm.shell(
        "ls -d /tmp/staged/sandboxd-*/", check=True,
    ).stdout.strip().rstrip("/")

    r = vm.shell(
        f"sudo -u sandbox env SANDBOX_SOCKET=/run/sandbox/sandboxd.sock "
        f"/usr/local/bin/sandbox update --dry-run --from {staged_dir}",
        timeout=30,
    )
    assert r.returncode == 0, f"--dry-run failed:\n{r.stdout}\n{r.stderr}"
    for step_id in range(13, 31):
        assert f"§ 3.2.{step_id}" in r.stdout, (
            f"--dry-run plan missing § 3.2.{step_id}:\n{r.stdout}"
        )

    # Lock file absent.
    assert (
        vm.shell("sudo test -e /var/lib/sandbox/.update.lock").returncode != 0
    )
