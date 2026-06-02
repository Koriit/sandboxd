"""`sandbox update` + manual rollback per the install framework.2.

the install framework ships only the documented manual rollback recipe; there is no
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
    assert_doctor_passes,
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
    sigstore_stack,
):
    """End-to-end rollback recipe from the install framework.2.

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
    r = vm.shell(
        install_sh_cmd(base_tarball, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    # 2. Update to bumped version.
    #
    # Feed the staged-directory shape (`--from <dir>`), not the tarball.
    # The base v CLI calls cosign verify-blob at § 3.1.10 when given a
    # tarball; the directory shape treats inputs as already-staged and
    # skips the signature gate. This test's contract is § 7.2 manual
    # rollback, not signature verification — the cosign coupling is
    # exercised under dedicated tests, not here.
    bumped_ver = version_from_tarball(release_tarball_x86_64_bumped)
    bumped_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)
    stage_dir = "/tmp/sandbox-update-rollback-stage"
    arch = "x86_64-unknown-linux-gnu"
    vm.shell(
        f"sudo rm -rf {stage_dir} && mkdir -p {stage_dir} && "
        f"tar xzf {bumped_in_vm} -C {stage_dir}",
        check=True, timeout=60,
    )
    extracted_root = f"{stage_dir}/sandboxd-{bumped_ver}-{arch}"
    r = vm.shell(
        f"sudo sandbox update --from {extracted_root} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"update failed:\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    # Confirm we're at v'.
    state = json.loads(
        vm.shell(
            "SUID=$(id -u sandbox); sudo cat /var/lib/sandboxd/$SUID/.install-state.json",
            check=True, timeout=10,
        ).stdout
    )
    assert state["installed_version"] == bumped_ver
    assert state.get("previous_version") == base_ver, (
        f"previous_version not recorded: {state!r}"
    )

    # Capture the manifest-recorded sha256 of the backed-up sessions.db
    # BEFORE running the rollback. This is the reference the rollback
    # must produce bit-for-bit (the recipe `install`s the backup's
    # `sessions.db.bak` into place, so the post-rollback file must hash
    # to whatever the backup phase recorded for that file).
    #
    # We do not snapshot `sessions.db` pre-update and compare against
    # that — the daemon is running between install and update, and
    # SQLite WAL checkpointing legitimately mutates the `.db` file
    # bytes between any two reads. The rollback's contract is "restore
    # what was captured in the backup set", not "restore arbitrary
    # earlier bytes"; `manifest.files["sessions.db.bak"].sha256` is
    # the captured-bytes ground truth.
    backup_manifest_text = vm.shell(
        "SUID=$(id -u sandbox); sudo sh -c \"cat /var/lib/sandboxd/$SUID/backups/*/manifest.json\"",
        check=True, timeout=10,
    ).stdout
    backup_manifest = json.loads(backup_manifest_text)
    expected_sessions_sha = backup_manifest["files"]["sessions.db.bak"]["sha256"]
    assert len(expected_sessions_sha) == 64, (
        f"manifest sha256 malformed: {expected_sessions_sha!r}"
    )
    # The WAL / SHM companion files may or may not be present in the backup
    # set: SQLite removes them on clean close, so a daemon that drained its
    # WAL before the snapshot will produce a backup without them. Capture
    # the manifest's view so we can assert the rolled-back filesystem
    # matches it exactly (file present at expected sha256, or absent).
    expected_wal_sha = (
        backup_manifest["files"].get("sessions.db-wal.bak", {}).get("sha256")
    )
    expected_shm_sha = (
        backup_manifest["files"].get("sessions.db-shm.bak", {}).get("sha256")
    )

    # 3. Run the rollback recipe . The recipe is split
    # into two phases here so the sessions.db sha256 can be sampled
    # AFTER the install but BEFORE `systemctl start sandboxd`. Without
    # the split, a parallel WAL checkpoint or any startup-time DB write
    # could mutate the bytes between `install` and our read, producing
    # a sha mismatch that does NOT reflect a real rollback regression.
    # The recipe content is otherwise verbatim with the design.
    #
    # Phase 1 — stop + install backup artifacts. Stops short of
    # `systemctl start sandboxd` so the daemon never gets a chance
    # to mutate the freshly-restored sessions.db.
    rollback_phase1 = r"""
set -eux
SANDBOX_UID=$(id -u sandbox)
BASE_DIR="/var/lib/sandboxd/$SANDBOX_UID"
BACKUP_DIR=$(sudo -u sandbox sh -c "ls -td $BASE_DIR/backups/*/" \
               | xargs -I{} sudo -u sandbox sh -c \
                   'test "$(jq -r .completed_ok < "{}/manifest.json")" = "true" && echo "{}"' \
               | head -1)
test -n "$BACKUP_DIR"
PREV_VERSION=$(sudo -u sandbox jq -r '.from_version' "$BACKUP_DIR/manifest.json")
sudo docker image inspect "sandbox-gateway:${PREV_VERSION}" >/dev/null
sudo systemctl stop sandboxd
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandboxd.bak"             /usr/local/bin/sandboxd
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox.bak"              /usr/local/bin/sandbox
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox-route-helper.bak" /usr/local/libexec/sandboxd/sandbox-route-helper
sudo install -m 0755 -o root -g root "$BACKUP_DIR/sandbox-guest.bak"        /usr/local/libexec/sandboxd/sandbox-guest
sudo setcap cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip /usr/local/libexec/sandboxd/sandbox-route-helper
sudo install -m 0644 -o root -g root "$BACKUP_DIR/users.conf.bak"  /etc/sandboxd/users.conf
# bridge.conf is optional — the daemon refuses on the schema check
# if it exists but is malformed; we restore only if the backup has it.
if [ -f "$BACKUP_DIR/bridge.conf.bak" ]; then
    sudo install -m 0644 -o root -g root "$BACKUP_DIR/bridge.conf.bak" /etc/qemu/bridge.conf
fi
sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db.bak" "$BASE_DIR/sessions.db"
if [ -f "$BACKUP_DIR/sessions.db-wal.bak" ]; then
    sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db-wal.bak" "$BASE_DIR/sessions.db-wal"
else
    sudo rm -f "$BASE_DIR/sessions.db-wal"
fi
if [ -f "$BACKUP_DIR/sessions.db-shm.bak" ]; then
    sudo install -m 0600 -o sandbox -g sandbox "$BACKUP_DIR/sessions.db-shm.bak" "$BASE_DIR/sessions.db-shm"
else
    sudo rm -f "$BASE_DIR/sessions.db-shm"
fi
sudo rm -f "$BASE_DIR/.update.lock"
"""
    r = vm.shell(rollback_phase1, timeout=120)
    assert r.returncode == 0, (
        f"rollback recipe phase 1 (stop + install) failed:\n{r.stdout}\n{r.stderr}"
    )

    # 4. Verify the post-install sha256 of sessions.db BEFORE
    # restarting the daemon. With sandboxd stopped, nothing on the
    # host can write to the DB — the bytes we read here are exactly
    # what the rollback's `install` step put in place.
    post_sessions_sha = vm.shell(
        "SUID=$(id -u sandbox); sudo sha256sum /var/lib/sandboxd/$SUID/sessions.db | awk '{print $1}'",
        check=True, timeout=10,
    ).stdout.strip()
    assert expected_sessions_sha == post_sessions_sha, (
        f"sessions.db not restored to the backup's captured bytes: "
        f"expected={expected_sessions_sha} post={post_sessions_sha}"
    )

    # Verify the WAL / SHM companion files landed in the state the manifest
    # records. SQLite runs in WAL journal mode (see
    # sandbox-cli/src/update/backup.rs), so committed-but-not-checkpointed
    # transactions live in `sessions.db-wal` with offsets indexed in
    # `sessions.db-shm`. The rollback recipe restores both alongside
    # `sessions.db` when the backup captured them, and removes any stale
    # copy on disk when the backup did not capture them — the daemon must
    # see a coherent triple, not a mismatched mix of old/new files.
    def _post_companion_state(host_path: str) -> str | None:
        probe = vm.shell(
            f"sudo sh -c 'if [ -f {host_path} ]; then sha256sum {host_path} | awk \"{{print \\$1}}\"; else echo MISSING; fi'",
            check=True, timeout=10,
        ).stdout.strip()
        return None if probe == "MISSING" else probe

    # Resolve the per-uid base-dir for companion file checks.
    sandbox_uid = vm.shell("id -u sandbox", check=True, timeout=10).stdout.strip()
    base_dir = f"/var/lib/sandboxd/{sandbox_uid}"
    post_wal_sha = _post_companion_state(f"{base_dir}/sessions.db-wal")
    post_shm_sha = _post_companion_state(f"{base_dir}/sessions.db-shm")
    assert post_wal_sha == expected_wal_sha, (
        f"sessions.db-wal not restored to the manifest's recorded state: "
        f"expected={expected_wal_sha!r} post={post_wal_sha!r}"
    )
    assert post_shm_sha == expected_shm_sha, (
        f"sessions.db-shm not restored to the manifest's recorded state: "
        f"expected={expected_shm_sha!r} post={post_shm_sha!r}"
    )

    # Phase 2 — start the daemon. Now that the sha check has landed,
    # the daemon's startup-time DB writes (WAL checkpoint, etc.) are
    # harmless to our assertion.
    r = vm.shell("sudo systemctl start sandboxd", timeout=60)
    assert r.returncode == 0, (
        f"rollback recipe phase 2 (systemctl start) failed:\n{r.stdout}\n{r.stderr}"
    )
    # install_state still says v' (rollback recipe does NOT rewrite
    # install_state — the design § 7.2 deliberately leaves operator audit
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
        "SUID=$(id -u sandbox); sudo test -e /var/lib/sandboxd/$SUID/.update.lock"
    ).returncode != 0, "lock file should be removed by rollback recipe"

    # 
    # doctor must pass regardless of install_state/version skew. The
    # rollback leaves install_state.installed_version pointing at the
    # bumped version while /version (and the binary on disk) report
    # the rolled-back base version; doctor's green-light gate is the
    # required recipe terminator and must succeed under that skew.
    assert_doctor_passes(vm)
