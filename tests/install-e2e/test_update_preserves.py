"""`sandbox update` preserves operator-owned files — Spec 5 §§ 4.5, 9.1.

Two preservation contracts are exercised end-to-end:

* ``test_update_preserves_systemd_drop_in`` — the operator drops in
  ``/etc/systemd/system/sandboxd.service.d/override.conf`` to tweak the
  unit; the update flow MUST leave it bit-for-bit unchanged. § 3.2.23
  installs the unit but explicitly does not touch ``*.service.d``
  directories.

* ``test_update_preserves_customized_users_conf`` — the operator edits
  ``/etc/sandboxd/users.conf`` to add a custom subnet line; the
  update's config-migration step must roll the schema forward without
  dropping the custom line (Spec 1 § 5.5 Input C → Output C').

  CAVEAT: with the single-version tarball harness no real migration
  fires (the registry has only V001 which install.sh's `users.conf`
  template already lands at). This test pins the *observable*
  invariant — the file is identical pre and post update.
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
    wait_for_systemd_active,
)


def _bump_patch(version):
    parts = version.split(".")
    if len(parts) != 3:
        raise AssertionError(f"unexpected version shape: {version}")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def _sh_quote(s):
    return "'" + s.replace("'", r"'\''") + "'"


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_preserves_systemd_drop_in(
    distro_template, vm_factory, release_tarball_x86_64, tmp_path
):
    """A systemd drop-in survives the update bit-for-bit.

    The drop-in is content the operator wrote — Spec 5 § 4.5 commits
    to never touching ``*.service.d``. ``§ 3.2.23 install systemd
    unit`` writes only ``sandboxd.service`` (the unit itself); the
    drop-in directory is operator territory.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    r = vm.shell(install_sh_cmd(base_tarball), timeout=600)
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    # Operator drops in an override (raises the unit's nofile limit).
    drop_in_path = "/etc/systemd/system/sandboxd.service.d/override.conf"
    drop_in_content = (
        "[Service]\n"
        "# operator-owned override — must survive sandbox update\n"
        "LimitNOFILE=65536\n"
        "Environment=SANDBOX_TEST_MARKER=operator-owned\n"
    )
    vm.shell(
        f"sudo install -d -m 0755 -o root -g root "
        f"/etc/systemd/system/sandboxd.service.d && "
        f"echo {_sh_quote(drop_in_content)} | "
        f"sudo tee {drop_in_path} >/dev/null && "
        f"sudo chmod 0644 {drop_in_path}",
        check=True, timeout=15,
    )
    pre_sha = vm.shell(
        f"sudo sha256sum {drop_in_path} | awk '{{print $1}}'",
        check=True, timeout=10,
    ).stdout.strip()
    assert len(pre_sha) == 64

    # Run a synthesised update (bumped MANIFEST version).
    bumped_ver = _bump_patch(base_ver)
    bumped = make_bumped_tarball(release_tarball_x86_64, bumped_ver,
                                 dst_dir=tmp_path)
    bumped_in_vm = copy_tarball_to_vm(vm, bumped)
    retag_gateway_image_in_vm(
        vm,
        from_tag=f"sandbox-gateway:{base_ver}",
        to_tag=f"sandbox-gateway:{bumped_ver}",
    )
    r = vm.shell(
        f"sudo sandbox update --from {bumped_in_vm} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"update failed:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Drop-in survives unchanged.
    assert vm.shell(f"sudo test -f {drop_in_path}").returncode == 0, (
        "drop-in disappeared during update"
    )
    post_sha = vm.shell(
        f"sudo sha256sum {drop_in_path} | awk '{{print $1}}'",
        check=True, timeout=10,
    ).stdout.strip()
    assert pre_sha == post_sha, (
        f"drop-in mutated by update: pre={pre_sha} post={post_sha}"
    )
    # Marker survives — proves the file content is intact, not just
    # an empty placeholder.
    assert vm.shell(
        f"sudo grep -q 'SANDBOX_TEST_MARKER=operator-owned' {drop_in_path}",
    ).returncode == 0


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_preserves_customized_users_conf(
    distro_template, vm_factory, release_tarball_x86_64, tmp_path
):
    """A custom subnet added to users.conf survives the update.

    The post-update file contains the operator's custom line. Spec 1
    § 5.5 + Spec 5 § 4.5: the config-migration framework rewrites
    structurally (schema_version stamp + canonical key order) but
    preserves operator-added entries.

    Single-version-tarball caveat: with no actual schema migration
    pending, the framework's apply chain is a no-op and the file is
    bit-for-bit identical. The real Spec 1 § 5.5 contract — V0 file
    with operator subnet → V1 file with stamp + subnet preserved —
    is exercised by ``migration_v001_round_trip`` (unit test) and
    ``integration_config_migration_applies_v001_to_legacy_file``. This
    test pins the OBSERVABLE invariant at the E2E level.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    r = vm.shell(install_sh_cmd(base_tarball), timeout=600)
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    # Snapshot the freshly-installed users.conf, then append a custom
    # subnet entry that an operator might have added.
    original = vm.shell(
        "sudo cat /etc/sandboxd/users.conf", check=True, timeout=10,
    ).stdout
    parsed = json.loads(original)
    # The schema's `subnets` array is operator-tunable per Spec 1
    # § 5.5; injecting an extra row mirrors the brainstorm case
    # ("operator-added subnet").
    parsed.setdefault("subnets", []).append({
        "comment": "operator-added subnet — must survive update",
        "cidr": "192.168.99.0/24",
        "allow_users": ["sandbox"],
    })
    customized = json.dumps(parsed, indent=2)
    vm.shell(
        f"echo {_sh_quote(customized)} | "
        f"sudo tee /etc/sandboxd/users.conf >/dev/null && "
        f"sudo chmod 0644 /etc/sandboxd/users.conf && "
        f"sudo chown root:root /etc/sandboxd/users.conf",
        check=True, timeout=10,
    )

    # Run the synthesised update.
    bumped_ver = _bump_patch(base_ver)
    bumped = make_bumped_tarball(release_tarball_x86_64, bumped_ver,
                                 dst_dir=tmp_path)
    bumped_in_vm = copy_tarball_to_vm(vm, bumped)
    retag_gateway_image_in_vm(
        vm,
        from_tag=f"sandbox-gateway:{base_ver}",
        to_tag=f"sandbox-gateway:{bumped_ver}",
    )
    r = vm.shell(
        f"sudo sandbox update --from {bumped_in_vm} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"update failed:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The custom subnet survives.
    post = json.loads(
        vm.shell(
            "sudo cat /etc/sandboxd/users.conf", check=True, timeout=10,
        ).stdout
    )
    cidrs = [s.get("cidr") for s in post.get("subnets", [])]
    assert "192.168.99.0/24" in cidrs, (
        f"custom subnet dropped during update; post subnets: {post!r}"
    )
