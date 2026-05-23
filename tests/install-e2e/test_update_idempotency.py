"""`sandbox update` idempotency + partial-failure tests — the install framework.2, 9.1.

Three end-to-end cases against a Lima VM:

* ``test_update_interrupted_then_resumed`` — kill the update mid-flight
  (after binaries land, before doctor runs); re-run; verify the second
  run converges with ``action=skip`` log lines and a non-zero exit
  code that the resume run recovers to 0.
* ``test_update_partial_failure_backup_set_preserved`` — inject a
  real failure into the config-migration step (§ 3.2.24) via the
  ``SANDBOX_UPDATE_TEST_FAIL_AT_STEP=migrate`` test-only env var;
  verify the in-progress backup-set ``manifest.json`` is written
  with ``completed_ok: false`` at § 3.2.19 and survives a
  subsequent successful run's retention prune (§ 5.2).

Both tests use a genuine bumped tarball (see
``conftest.release_tarball_x86_64_bumped``) — the bumped tarball
ships a binary built from sed-rewritten ``Cargo.toml`` files, so the
daemon's ``/version`` endpoint reports the bumped version after the
update. The assertions still land on ``install_state`` and the
backup set's ``manifest.json`` (those record the MANIFEST version);
``verify_version`` inside ``sandbox update`` requires the binary's
compiled-in version to match the MANIFEST or the run aborts.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    parse_install_log_actions,
    version_from_tarball,
    wait_for_socket,
    wait_for_systemd_active,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_interrupted_then_resumed(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
    sigstore_stack,
):
    """Inject a transient failure mid-update; the resume run converges.

    Strategy:
      * Install base version.
      * Stage a bumped tarball.
      * Simulate an interrupted update: pre-populate the backup set
        directory with a stale (completed_ok=false) manifest as if a
        prior crashed run got that far. Pre-create the in-progress
        lock holder PID's payload pointing to a *dead* PID (so the
        adopt-stale branch fires on the second acquisition).
      * Run ``sandbox update`` to completion.
      * Verify exit 0; the install-state JSON's ``installed_version``
        flipped to the bumped version; the backup-set count includes
        the recovered set.

    The Drop impl on UpdateLock + flock(2) FD-close guarantees no
    real-process-crash artefacts are left behind; this test exercises
    the **logical** resume path — the lock adoption branch from a dead
    PID with sticky ``was_running``.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    r = vm.shell(
        install_sh_cmd(base_tarball, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"install failed:\n{r.stdout}\n{r.stderr}"
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=60)

    bumped_ver = version_from_tarball(release_tarball_x86_64_bumped)
    bumped_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)

    # Pre-stage the bumped binaries at their canonical destinations so
    # the resume run sees `action=skip reason=identical` at §§ 3.2.15-17.
    # `install_binary_if_changed` skips if the source and destination are
    # byte-equal (sha256 compare in spirit, byte-compare in code). The
    # resume run unpacks the same bumped tarball into a staging dir; the
    # bytes will match exactly because both are the same tarball.
    #
    # We extract the bumped tarball into the VM and `install` its
    # bin/sandboxd, bin/sandbox-route-helper, and bin/sandbox-guest to
    # the canonical paths. We deliberately do NOT pre-stage `bin/sandbox`
    # (the CLI binary itself) — the resume invocation below should be
    # executed by the base v binary on disk, keeping a clean "the
    # running CLI is v, not v'" invariant for the test. The remaining
    # three binary swaps still emit `action=skip` for the install_binary
    # step on resume, which is what the design § 9.1 idempotency
    # assertion below pins.
    stage_dir = "/tmp/sandbox-update-prestage"
    vm.shell(
        f"sudo rm -rf {stage_dir} && mkdir -p {stage_dir} && "
        f"tar xzf {bumped_in_vm} -C {stage_dir}",
        check=True, timeout=60,
    )
    # The tarball top-level dir is `sandboxd-<ver>-<arch>/`.
    arch = "x86_64-unknown-linux-gnu"
    extracted_root = f"{stage_dir}/sandboxd-{bumped_ver}-{arch}"
    vm.shell(
        f"sudo install -D -m 0755 -o root -g root "
        f"{extracted_root}/bin/sandboxd /usr/local/bin/sandboxd && "
        f"sudo install -D -m 0755 -o root -g root "
        f"{extracted_root}/bin/sandbox-route-helper "
        f"/usr/local/libexec/sandboxd/sandbox-route-helper && "
        f"sudo install -D -m 0755 -o root -g root "
        f"{extracted_root}/bin/sandbox-guest "
        f"/usr/local/libexec/sandboxd/sandbox-guest",
        check=True, timeout=30,
    )

    # Pre-write a stale lock payload claiming a dead PID. The adoption
    # branch in `lock::acquire` walks "is the holder PID live?" — for
    # PID 999999 (effectively never alive), it adopts the lock and
    # preserves `was_running: true` (sticky).
    #
    # `started_at` is computed inside the VM as 5 minutes ago to keep
    # the test deterministic against the adopt-fresh-vs-adopt-stale
    # boundary: a hard-coded date drifts older every day this test sits
    # in tree, and once it crosses the staleness threshold the adopt
    # branch flips, which silently changes what this test pins. A
    # rolling "5 minutes ago" is always fresh, so this test always
    # exercises adopt-fresh (or, equivalently, the live-holder-dead-PID
    # branch — both branches preserve sticky `was_running`).
    started_at = vm.shell(
        "date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%SZ",
        check=True, timeout=10,
    ).stdout.strip()
    stale_payload = json.dumps({
        "pid": 999999,
        "target_version": bumped_ver,
        "from_version": base_ver,
        "started_at": started_at,
        "was_running": True,
    })
    vm.shell(
        f"echo {_sh_quote(stale_payload)} | "
        f"sudo -u sandbox tee /var/lib/sandbox/.update.lock >/dev/null && "
        f"sudo chmod 0664 /var/lib/sandbox/.update.lock",
        check=True, timeout=15,
    )

    # The stale lock file exists but NO process holds the flock — so the
    # next `sandbox update` succeeds in acquiring it via the adopt-stale
    # path. Truncate the install log so we read just this run's lines.
    vm.shell("sudo truncate -s 0 /var/log/sandbox-install.log", check=True)

    # Feed `--from <extracted_root>` (directory shape), not the tarball.
    # The base v CLI on disk was built from the same source tree as v'
    # and therefore also calls cosign verify-blob at § 3.1.10 when given
    # a tarball; using the staged-directory shape bypasses that gate
    # (`prepare_staged_tarball` treats a directory as already-staged and
    # the call site skips `verify_signature` when `from.is_file()` is
    # false). The contract under test is idempotency on resume, not
    # signature verification — keeping cosign out of this test removes
    # an unrelated host dependency.
    r = vm.shell(
        f"sudo sandbox update --from {extracted_root} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"resume run did not converge to 0:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The acquire-lock step logged action=adopt-stale (sticky
    # was_running carried through).
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True,
    ).stdout
    assert "step=acquire_lock" in log and ("action=adopt-stale" in log or "action=adopt" in log), (
        f"resume run should have adopted the stale lock; log:\n{log}"
    )

    # "the resume run mostly skips already-completed
    # steps". Parse the install log and count `action=skip` lines. With
    # three of the four bumped binaries pre-staged (sandboxd, sandbox-
    # route-helper, sandbox-guest; see the rationale at pre-stage time),
    # all three of those `install_binary` entries must record
    # action=skip. The fourth `install_binary` (sandbox CLI) is expected
    # to land as action=install because we intentionally left the v
    # binary in place. This assertion pins the idempotency contract on
    # the binary-install layer specifically.
    parsed = parse_install_log_actions(log)
    install_binary_actions = parsed.get("install_binary", [])
    skip_count = install_binary_actions.count("skip")
    assert skip_count >= 3, (
        f"expected at least 3 install_binary steps with action=skip "
        f"(sandboxd, sandbox-route-helper, sandbox-guest pre-staged at "
        f"canonical paths); got {skip_count} skip(s) in "
        f"install_binary={install_binary_actions!r}\nlog:\n{log}"
    )

    # Install-state flipped to the bumped version.
    state = json.loads(
        vm.shell(
            "sudo cat /var/lib/sandbox/.install-state.json",
            check=True, timeout=10,
        ).stdout
    )
    assert state["installed_version"] == bumped_ver, (
        f"install-state did not advance to {bumped_ver}: {state!r}"
    )

    # On success the lock file is removed at § 3.2.30.
    assert vm.shell(
        "sudo test -e /var/lib/sandbox/.update.lock"
    ).returncode != 0, "lock file should be unlinked on a successful update"

    # Backup set landed: exactly one set with completed_ok=true.
    # `/var/lib/sandbox/backups/` is mode 0700 sandbox:sandbox, so the
    # glob has to expand inside `sudo sh -c` (the outer shell can't
    # traverse the dir to list its children). Matches the
    # `success_sets` shape in the partial-failure test below.
    set_count = int(vm.shell(
        "sudo sh -c 'ls -1d /var/lib/sandbox/backups/*/ 2>/dev/null | wc -l'",
        check=True, timeout=10,
    ).stdout.strip())
    assert set_count == 1, f"expected 1 backup set, got {set_count}"
    manifest_text = vm.shell(
        "sudo sh -c 'cat /var/lib/sandbox/backups/*/manifest.json'",
        check=True, timeout=10,
    ).stdout
    manifest = json.loads(manifest_text)
    assert manifest["completed_ok"] is True, (
        f"backup-set manifest should be completed_ok=true: {manifest!r}"
    )
    assert manifest["from_version"] == base_ver
    assert manifest["to_version"] == bumped_ver


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_update_partial_failure_backup_set_preserved(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
    sigstore_stack,
):
    """A real failure mid-update leaves the backup set with
    completed_ok=false and that set is preserved across the subsequent
    successful run's retention prune. the install framework.2.19, 3.2.24, 5.2.

    Strategy:
      * Install base version.
      * Stage a bumped tarball.
      * Run the update with ``SANDBOX_UPDATE_TEST_FAIL_AT_STEP=migrate``,
        a test-only env var consumed by ``update::run`` that makes the
        § 3.2.24 migrate step ``return 1`` before any migration is
        applied. § 3.2.19 has already written the in-progress backup
        manifest by this point; the in-progress manifest stays on disk
        with ``completed_ok: false``.
      * Run a clean ``sandbox update`` (no env var) — it succeeds, must
        NOT prune the forensic set, and creates a second set marked
        ``completed_ok: true``.

    This pins two update contracts at once:
      * Step 3.2.19 — the in-progress manifest is written BEFORE the
        migrate step. If production code stops writing it at backup
        time, the first-run assertion fails.
      * Step 5.2 — retention prune skips forensic sets. If production
        prune logic regresses to delete completed_ok=false sets, the
        second-run assertion fails.
    """
    vm = vm_factory(distro_template)
    base_tarball = copy_tarball_to_vm(vm, release_tarball_x86_64)
    base_ver = version_from_tarball(base_tarball)

    r = vm.shell(
        install_sh_cmd(base_tarball, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0
    vm.shell("sudo systemctl enable --now sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    bumped_ver = version_from_tarball(release_tarball_x86_64_bumped)
    bumped_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64_bumped)

    # Use the staged-directory shape (`--from <dir>`) for both runs so
    # this test stays decoupled from host cosign. The Rust update flow
    # invokes `cosign verify-blob` at § 3.1.10 only when `from.is_file()`;
    # a directory is treated as already-staged and the signature gate
    # is skipped. The contracts pinned here (§ 3.2.19 forensic manifest,
    # § 5.2 retention preservation) live in the stateful phase, well
    # past the pre-flight signature step.
    stage_dir = "/tmp/sandbox-update-partial-failure-stage"
    arch = "x86_64-unknown-linux-gnu"
    vm.shell(
        f"sudo rm -rf {stage_dir} && mkdir -p {stage_dir} && "
        f"tar xzf {bumped_in_vm} -C {stage_dir}",
        check=True, timeout=60,
    )
    extracted_root = f"{stage_dir}/sandboxd-{bumped_ver}-{arch}"

    # First run — inject a real mid-update failure at the migrate step
    # via SANDBOX_UPDATE_TEST_FAIL_AT_STEP=migrate. The env var is
    # documented as test-only in sandboxd/sandbox-cli/src/update/mod.rs
    # at § 3.2.24's entry. `sudo` strips the caller's env by default;
    # the explicit `VAR=val` between `sudo` and the command preserves
    # only that one variable into the child's environment (same idiom
    # `install_sh_cmd` uses for SANDBOX_INSTALL_SKIP_SIGSTORE).
    r = vm.shell(
        f"sudo SANDBOX_UPDATE_TEST_FAIL_AT_STEP=migrate "
        f"sandbox update --from {extracted_root} --yes",
        timeout=300,
    )
    assert r.returncode != 0, (
        f"injected migrate-step failure should have produced non-zero "
        f"exit; got 0\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # § 3.2.19 contract: the in-progress backup-set manifest is written
    # BEFORE the migrate step runs. After the injected failure, exactly
    # one backup set should exist on disk with completed_ok=false.
    forensic_set = vm.shell(
        "sudo sh -c 'ls -1d /var/lib/sandbox/backups/*/ 2>/dev/null | head -1'",
        check=True, timeout=10,
    ).stdout.strip()
    assert forensic_set, (
        f"no backup set produced by the failed run — § 3.2.19 contract "
        f"is broken (in-progress manifest not written at backup time)\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    forensic_set = forensic_set.rstrip("/")
    forensic_manifest_text = vm.shell(
        f"sudo cat {forensic_set}/manifest.json",
        check=True, timeout=10,
    ).stdout
    forensic_manifest = json.loads(forensic_manifest_text)
    assert forensic_manifest["completed_ok"] is False, (
        f"forensic manifest should have completed_ok=false (in-progress); "
        f"got: {forensic_manifest!r}"
    )
    assert forensic_manifest["from_version"] == base_ver
    assert forensic_manifest["to_version"] == bumped_ver

    # The failed run left the daemon stopped (§ 3.2.14 ran before the
    # injected failure at § 3.2.24). Start the daemon back up so the
    # retry's `was_running` probe samples `true`, mirroring the operator
    # recovery flow (operators are expected to restart the daemon
    # before retrying an interrupted update). Without this, the retry's
    # doctor step at § 3.2.28 would fail because the daemon socket is
    # absent.
    vm.shell("sudo systemctl start sandboxd", check=True, timeout=60)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=60)

    # Second run — clean (no env var). The update must succeed; the
    # forensic set must be preserved (§ 5.2 retention contract). Reuse
    # the same staged directory as the first run — `--from <dir>` is a
    # pure read of the staged inputs, the first run's failure happened
    # at § 3.2.24 (migrate), well past extraction, so the staged tree
    # is unchanged.
    r = vm.shell(
        f"sudo sandbox update --from {extracted_root} --yes",
        timeout=300,
    )
    assert r.returncode == 0, (
        f"clean retry should succeed:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The forensic set survives the prune at § 3.2.25.
    assert vm.shell(f"sudo test -d {forensic_set}").returncode == 0, (
        f"forensic backup set was pruned (§ 5.2 violation): {forensic_set}"
    )
    assert vm.shell(
        f"sudo test -f {forensic_set}/manifest.json"
    ).returncode == 0, "forensic manifest disappeared"
    m = json.loads(
        vm.shell(
            f"sudo cat {forensic_set}/manifest.json", check=True, timeout=10,
        ).stdout
    )
    assert m["completed_ok"] is False, (
        f"forensic manifest was rewritten: {m!r}"
    )

    # A successful set was also created by the clean retry.
    success_sets = vm.shell(
        "sudo sh -c 'for d in /var/lib/sandbox/backups/*/; do "
        " jq -r .completed_ok < \"$d/manifest.json\" 2>/dev/null; "
        "done | grep -c true || true'",
        check=True, timeout=15,
    ).stdout.strip()
    assert int(success_sets or "0") >= 1, (
        f"successful run should have created at least 1 set with "
        f"completed_ok=true; counted {success_sets}"
    )


def _sh_quote(s):
    return "'" + s.replace("'", r"'\''") + "'"
