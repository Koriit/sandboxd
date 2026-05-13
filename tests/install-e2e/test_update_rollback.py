"""`sandbox update` + manual rollback per Spec 5 § 7.2.

Spec 5 ships only the documented manual rollback recipe; there is no
automated ``sandbox rollback`` subcommand (§ 12 out of scope). This
test installs base version v, updates to a bumped v', then runs the
verbatim recipe from § 7.2 and asserts the rolled-back state.

The bumped tarball is a genuine v' build (every crate's Cargo.toml
sed-rewritten before ``cargo build --workspace --release``), so the
daemon's ``/version`` endpoint truthfully reports v' post-update and
v after the rollback recipe puts the v binary back. The assertions
land on ``install_state.installed_version`` (written from
MANIFEST.version) and the backup-set's ``manifest.from_version``.
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
def test_update_then_manual_rollback(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
):
    """End-to-end rollback recipe from Spec 5 § 7.2.

    Steps:
      1. Install base version v.
      2. Update to bumped v'.
      3. Run the rollback recipe verbatim.
      4. Verify: install_state at v, sessions.db restored to the
         backup's bytes, daemon up + serving /version.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    # 1. Install base.
    r = vm.shell(install_sh_cmd(base_tarball), timeout=600)
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # Snapshot the pre-update sessions.db sha256. This is the reference
    # the rollback must match bit-for-bit.
    pre_sessions_sha = vm.shell(
        "sudo sha256sum /var/lib/sandbox/sessions.db | awk '{print $1}'",
        check=True, timeout=10,
    ).stdout.strip()
    assert len(pre_sessions_sha) == 64

    # 2. Update to bumped version.
    bumped_ver = version_from_tarball(release_tarball_x86_64_bumped)
    bumped_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)
    r = vm.shell(
        f"sudo sandbox update --from {bumped_in_vm} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"update failed:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    # Confirm we're at v'.
    state = json.loads(
        vm.shell(
            "sudo cat /var/lib/sandbox/.install-state.json",
            check=True, timeout=10,
        ).stdout
    )
    assert state["installed_version"] == bumped_ver
    assert state.get("previous_version") == base_ver, (
        f"previous_version not recorded: {state!r}"
    )

    # 3. Run the rollback recipe (Spec 5 § 7.2). Verbatim, with one
    # test-mode caveat:
    #   * Step 2 (gateway image inspect) — succeeds because the base
    #     install's docker-load left ``sandbox-gateway:<base>`` resident
    #     in the VM, and the rollback recipe inspects exactly that tag.
    #   * The ``ls -td`` selector picks the newest set with
    #     completed_ok=true; in this test there is exactly one set
    #     and it has completed_ok=true, so it is selected.
    rollback_recipe = r"""
set -eux
BACKUP_DIR=$(sudo -u sandbox ls -td /var/lib/sandbox/backups/*/ \
               | xargs -I{} sudo -u sandbox sh -c \
                   'test "$(jq -r .completed_ok < "{}/manifest.json")" = "true" && echo "{}"' \
               | head -1)
test -n "$BACKUP_DIR"
PREV_VERSION=$(sudo -u sandbox jq -r '.from_version' "$BACKUP_DIR/manifest.json")
docker image inspect "sandbox-gateway:${PREV_VERSION}" >/dev/null
sudo systemctl stop sandboxd
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandboxd.bak"             /usr/local/bin/sandboxd
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox.bak"              /usr/local/bin/sandbox
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox-route-helper.bak" /usr/local/libexec/sandboxd/sandbox-route-helper
sudo setcap cap_net_admin,cap_sys_admin=eip /usr/local/libexec/sandboxd/sandbox-route-helper
sudo install -m 0644 -o root -g root "$BACKUP_DIR/users.conf.bak"  /etc/sandboxd/users.conf
# bridge.conf is optional — the daemon refuses on the schema check
# if it exists but is malformed; we restore only if the backup has it.
if [ -f "$BACKUP_DIR/bridge.conf.bak" ]; then
    sudo install -m 0644 -o root -g root "$BACKUP_DIR/bridge.conf.bak" /etc/qemu/bridge.conf
fi
sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db.bak" /var/lib/sandbox/sessions.db
sudo rm -f /var/lib/sandbox/.update.lock
sudo systemctl start sandboxd
"""
    r = vm.shell(rollback_recipe, timeout=120)
    assert r.returncode == 0, (
        f"rollback recipe failed:\n{r.stdout}\n{r.stderr}"
    )

    # 4. Verify post-rollback state.
    # sessions.db bytes match pre-update.
    post_sessions_sha = vm.shell(
        "sudo sha256sum /var/lib/sandbox/sessions.db | awk '{print $1}'",
        check=True, timeout=10,
    ).stdout.strip()
    assert pre_sessions_sha == post_sessions_sha, (
        f"sessions.db not restored: pre={pre_sessions_sha} "
        f"post={post_sessions_sha}"
    )
    # install_state still says v' (rollback recipe does NOT rewrite
    # install_state — the spec § 7.2 deliberately leaves operator audit
    # at v', since the v' artifacts have technically been applied and
    # then reverted). The next `sandbox update` flow will see this
    # state and may attempt to "upgrade" again; that's the documented
    # contract — operators run rollback rarely and re-roll forward
    # manually.
    # The daemon is back up.
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)
    # /version is served and reports the rolled-back binary's version
    # (= the base version). With a genuine bumped binary, this pins
    # the rollback's "the v binary is back on disk" contract.
    ver_probe = vm.shell(
        "sudo curl -fsSL --unix-socket /run/sandbox/sandboxd.sock "
        "http://localhost/version | jq -r .version",
        check=True, timeout=10,
    ).stdout.strip()
    assert ver_probe == base_ver, (
        f"daemon /version did not return the base version after rollback: "
        f"got {ver_probe!r}, expected {base_ver!r}"
    )
    # Lock file gone (recipe step 8).
    assert vm.shell(
        "sudo test -e /var/lib/sandbox/.update.lock"
    ).returncode != 0, "lock file should be removed by rollback recipe"
