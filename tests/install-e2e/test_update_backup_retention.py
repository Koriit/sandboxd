"""`sandbox update` backup-set retention — Spec 5 §§ 3.2.25, 5.2.

The retention policy keeps the 2 most recent ``completed_ok: true``
sets; sets with ``completed_ok: false`` are preserved forensically and
never auto-pruned.

This test installs base v, then runs three updates v → v.1 → v.2 →
v.3. After the third update, exactly 2 successful sets remain (the
v.1→v.2 and v.2→v.3 transitions); the v→v.1 set is pruned.

Single-version-tarball caveat: the bumped tarballs ship the same
binaries (only MANIFEST.version differs), so the daemon's ``/version``
endpoint reports the base version throughout. The test asserts the
*observable retention behavior* via the on-disk backup-set count and
the manifests' ``to_version`` strings.
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


def _bump_to(version, new_patch):
    parts = version.split(".")
    parts[-1] = str(new_patch)
    return ".".join(parts)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_backup_retention_prunes_oldest(
    distro_template, vm_factory, release_tarball_x86_64, tmp_path
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

    # Build 3 bumped tarballs.
    parts = base_ver.split(".")
    base_patch = int(parts[-1])
    vers = [
        _bump_to(base_ver, base_patch + 1),
        _bump_to(base_ver, base_patch + 2),
        _bump_to(base_ver, base_patch + 3),
    ]
    tarballs = [
        make_bumped_tarball(release_tarball_x86_64, v, dst_dir=tmp_path)
        for v in vers
    ]
    in_vm = [copy_tarball_to_vm(vm, t, dst="/tmp") for t in tarballs]
    # Pre-tag the gateway image for every version in the chain.
    for v in vers:
        retag_gateway_image_in_vm(
            vm,
            from_tag=f"sandbox-gateway:{base_ver}",
            to_tag=f"sandbox-gateway:{v}",
        )

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
        # expected (from_version, to_version) pairs.
        manifests = vm.shell(
            "sudo sh -c 'for d in /var/lib/sandbox/backups/*/; do "
            "  cat \"$d/manifest.json\"; echo ,; "
            "done'",
            check=True, timeout=20,
        ).stdout
        # The output is a sequence of JSON docs separated by commas;
        # parse them by splitting on the trailing comma + newline.
        manifest_blobs = [
            blob.strip() for blob in manifests.split("\n,\n") if blob.strip()
        ]
        # The final blob has a trailing `,` from the loop — strip it.
        manifest_blobs = [b.rstrip(",").strip() for b in manifest_blobs if b.rstrip(",").strip()]
        parsed = []
        for blob in manifest_blobs:
            try:
                parsed.append(json.loads(blob))
            except json.JSONDecodeError:
                continue
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
