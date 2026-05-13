"""`sandbox update` backup-set retention — Spec 5 §§ 3.2.25, 5.2.

The retention policy keeps the 2 most recent ``completed_ok: true``
sets; sets with ``completed_ok: false`` are preserved forensically and
never auto-pruned.

This test installs base v, then runs three updates v → v.1 → v.2 →
v.3. After the third update, exactly 2 successful sets remain (the
v.1→v.2 and v.2→v.3 transitions); the v→v.1 set is pruned.

The three bumped tarballs are genuine v.1, v.2, v.3 binaries built
by the ``release_tarball_x86_64_bumped_chain`` fixture — each link
sed-rewrites every crate's Cargo.toml to the link's target version
and runs ``cargo build --workspace --release``. ``verify_version``
inside ``sandbox update`` requires the post-restart ``/version`` to
match the MANIFEST version or the run aborts, so a MANIFEST-only
fake bump won't satisfy this test.
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
def test_update_backup_retention_prunes_oldest(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped_chain,
):
    """Three consecutive updates leave 2 successful backup sets on disk.

    Spec 5 § 5.2 keep=2 retention. After the 3rd update, the oldest
    successful set (the v→v.1 transition) is pruned.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    # Install base.
    r = vm.shell(install_sh_cmd(base_tarball), timeout=600)
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Stage 3 genuine bumped tarballs (v.1, v.2, v.3) from the chain
    # fixture. Each link is a real bumped binary whose /version
    # endpoint reports the bumped version, satisfying verify_version.
    assert len(release_tarball_x86_64_bumped_chain) >= 3, (
        f"chain fixture must produce >= 3 bumped tarballs for the "
        f"retention test, got {len(release_tarball_x86_64_bumped_chain)}"
    )
    tarballs = release_tarball_x86_64_bumped_chain[:3]
    vers = [version_from_tarball(t) for t in tarballs]
    in_vm = [copy_tarball_to_vm(vm, t, dst="/tmp") for t in tarballs]

    # Run the three updates in order. Each must succeed and produce a
    # new backup set in `/var/lib/sandbox/backups/`.
    expected_to_versions_after_each = [
        # After update 1: 1 successful set {base -> v1}.
        [(base_ver, vers[0])],
        # After update 2: 2 successful sets.
        [(base_ver, vers[0]), (vers[0], vers[1])],
        # After update 3: 2 successful sets (the oldest is pruned).
        [(vers[0], vers[1]), (vers[1], vers[2])],
    ]
    for idx, tarball_in_vm in enumerate(in_vm):
        r = vm.shell(
            f"sudo sandbox update --from {tarball_in_vm} --yes",
            timeout=300,
        )
        assert r.returncode == 0, (
            f"update {idx + 1} failed:\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )
        # Enumerate backup sets with completed_ok=true and verify the
        # expected (from_version, to_version) pairs. `jq -s .` slurps
        # the manifest files into a single JSON array, sidestepping the
        # delimiter-parsing fragility of a `cat + echo ,` loop (when
        # `cat` doesn't emit a trailing newline the boundary between
        # manifests is `},{` rather than `}\n,\n{`, defeating any
        # split-on-newline-comma-newline approach).
        manifests = vm.shell(
            "sudo sh -c 'jq -s . /var/lib/sandbox/backups/*/manifest.json'",
            check=True, timeout=20,
        ).stdout
        parsed = json.loads(manifests)
        ok_pairs = sorted(
            (m["from_version"], m["to_version"])
            for m in parsed
            if m.get("completed_ok") is True
        )
        expected = sorted(expected_to_versions_after_each[idx])
        assert ok_pairs == expected, (
            f"after update {idx + 1}: expected backup sets {expected}, "
            f"got {ok_pairs}\nraw:\n{manifests}"
        )
