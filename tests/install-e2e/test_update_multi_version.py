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
import sqlite3
import subprocess
import tempfile
from pathlib import Path

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
def test_update_fresh_install_to_next_version(
    distro_template,
    vm_factory,
    release_tarball_x86_64,
    release_tarball_x86_64_bumped,
    sigstore_stack,
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

    r = vm.shell(
        install_sh_cmd(base_tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
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
    # cosign call. Going through `--from <tarball>` would route
    # through cosign verify-blob and add noise that obscures the
    # multi-version contract under test (Spec 5 § 9.1).
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

    # 3. sessions.db integrity — Spec 5 § 3.2.15 backs the DB up
    # to /var/lib/sandbox/backups/, then preserves the live copy
    # through the update. After a successful update the live DB at
    # /var/lib/sandbox/sessions.db must (a) exist, (b) be a
    # well-formed SQLite database (`PRAGMA integrity_check` returns
    # "ok"), and (c) carry the `sessions` table the daemon depends
    # on for queries. Without these assertions a regression that
    # left the DB truncated or corrupted post-update would only
    # surface on the next session-create — too late for the update
    # test to catch.
    #
    # The DB is mode 0600 owned by sandbox:sandbox and the guest has
    # no sqlite CLI (the daemon uses rusqlite statically, so an
    # operator install never needs one). Stage a world-readable copy
    # under /tmp, pull it to the host with `limactl copy`, and run
    # the checks against Python's bundled `sqlite3` module — keeping
    # the guest's tool surface honest to the real install contract.
    vm.shell(
        "sudo install -m 0644 -o root -g root "
        "/var/lib/sandbox/sessions.db /tmp/sessions.db.inspect",
        check=True, timeout=10,
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        host_db = Path(tmpdir) / "sessions.db"
        subprocess.run(
            ["limactl", "copy", f"{vm.name}:/tmp/sessions.db.inspect", str(host_db)],
            check=True, timeout=60, capture_output=True, text=True,
        )
        with sqlite3.connect(f"file:{host_db}?mode=ro", uri=True) as conn:
            integrity = conn.execute("PRAGMA integrity_check;").fetchone()
            assert integrity is not None and integrity[0] == "ok", (
                f"post-update sessions.db integrity_check failed: {integrity!r}; "
                f"the live DB at /var/lib/sandbox/sessions.db is corrupted or truncated"
            )
            # `sessions` table must exist (the migration set is up-to-
            # date post-update; the table presence is the minimum
            # schema-shape assertion).
            row = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='sessions';"
            ).fetchone()
            assert row is not None and row[0] == "sessions", (
                f"post-update sessions.db missing `sessions` table: {row!r}"
            )
    vm.shell("sudo rm -f /tmp/sessions.db.inspect", check=True, timeout=10)

    # 4. Spec § 7.2 step 10 (post-update green-light gate): doctor
    # passes against the running v' daemon.
    assert_doctor_passes(vm)
