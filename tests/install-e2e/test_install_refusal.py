"""Refusal-path tests for install.sh.



- ``test_install_refuses_wrong_arch_tarball`` — aarch64 MANIFEST on
  x86_64 host. Expect non-zero exit + clear error.
- ``test_install_refuses_when_preexisting`` — install once, install
  again with the *same* version on disk; expect early skip-and-exit-0
  (per install.sh step 5 "preexist action=skip" path). With a
  *different* version on disk, expect exit 1 with a clear "use update"
  message.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest

from conftest import copy_tarball_to_vm, install_sh_cmd


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_refuses_wrong_arch_tarball(
    distro_template, vm_factory, release_tarball_x86_64, tmp_path
):
    """A tarball whose MANIFEST claims aarch64 is rejected on x86_64.

    Reproducer: extract the x86_64 tarball into a temp dir, rewrite
    MANIFEST's "arch" field to aarch64-unknown-linux-gnu, re-tar,
    re-sign-stub, copy into an x86_64 VM, run install.sh, expect
    non-zero exit + a MANIFEST-mismatch message in the log.
    """
    vm = vm_factory(distro_template)

    # Build a tampered tarball locally.
    tampered = _repack_with_arch(
        release_tarball_x86_64, tmp_path,
        new_arch="aarch64-unknown-linux-gnu",
    )

    tampered_in_vm = copy_tarball_to_vm(vm, tampered)

    # Use install_sh_cmd so --version matches the tarball's top-level
    # directory name (which encodes the ORIGINAL version, not the
    # tampered arch). With --version correct, the extract step succeeds
    # and the MANIFEST arch check is the load-bearing assertion under
    # test. Previously the test invoked install.sh without --version,
    # which made VERSION="latest" and tripped a pre-MANIFEST extract
    # failure ("did not contain expected top-level directory") that
    # masked the actual arch-mismatch check.
    #
    # SANDBOX_INSTALL_SKIP_SIGSTORE=1: the re-packed tampered tarball
    # has no valid signature bundle (the local stack signed the
    # original; the tampered bytes don't satisfy that signature).
    # Bypassing sigstore_verify keeps the test focused on the
    # MANIFEST arch-mismatch refusal under test rather than coupling
    # it to the tampered-signature negative path.
    r = vm.shell(
        install_sh_cmd(tampered_in_vm,
                       env={"SANDBOX_INSTALL_SKIP_SIGSTORE": "1"}),
        timeout=300,
    )
    assert r.returncode != 0, (
        f"install.sh accepted a wrong-arch tarball:\n{r.stdout}\n{r.stderr}"
    )
    output = (r.stdout + r.stderr).lower()
    # ONLY the MANIFEST arch-mismatch path is acceptable. Previously
    # the test allowed a pre-MANIFEST extract failure too, which let a
    # regression in MANIFEST.arch validation pass undetected.
    assert "arch" in output and "mismatch" in output, (
        f"missing MANIFEST arch-mismatch error:\n{r.stdout}\n{r.stderr}"
    )
    # Cross-check against the install log: arch_detect must have run
    # (so we're past the pre-extract distro/arch sanity steps) and the
    # extract step must NOT have logged manifest_ok=true.
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=arch_detect" in log, (
        f"install log missing step=arch_detect (test never reached MANIFEST check):\n{log}"
    )
    assert "manifest_ok=true" not in log, (
        f"install log claims manifest_ok=true on a wrong-arch tarball:\n{log}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_refuses_when_preexisting(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack, tmp_path,
):
    """Same-version re-install short-circuits (exit 0). Different-version refuses (exit 1).

    
    version equals the target; otherwise it refuses and points the user
    at `sandbox update`.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # First install.
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, f"first install failed:\n{r.stdout}\n{r.stderr}"

    # Second install at the same version: exit 0 (idempotent skip).
    r2 = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=120,
    )
    assert r2.returncode == 0, (
        f"re-install at same version did not idempotently exit 0:\n{r2.stdout}\n{r2.stderr}"
    )
    assert "already installed" in (r2.stdout + r2.stderr).lower()

    # Build a tarball claiming a different version (string-level only;
    # the binaries inside are unchanged, but install.sh's preexist guard
    # keys off MANIFEST.version vs. the installed daemon's --version).
    tampered = _repack_with_version(
        release_tarball_x86_64, tmp_path, new_version="9.9.9",
    )
    tampered_in_vm = copy_tarball_to_vm(vm, tampered)

    r3 = vm.shell(
        f"sudo bash /tmp/install.sh --from {tampered_in_vm} --yes --no-color",
        timeout=120,
    )
    assert r3.returncode != 0, (
        f"different-version re-install must refuse:\n{r3.stdout}\n{r3.stderr}"
    )
    output = (r3.stdout + r3.stderr).lower()
    assert "already installed" in output and "update" in output, (
        f"refusal message missing 'update' hint:\n{r3.stdout}\n{r3.stderr}"
    )


# ---------------------------------------------------------------------------
# Helpers — repackage the staged tarball with a tampered MANIFEST.
# ---------------------------------------------------------------------------

def _repack_with_arch(src_tarball, work_dir, *, new_arch):
    """Re-tar the staged tree with MANIFEST.arch overwritten."""
    return _repack(
        src_tarball, work_dir,
        mutator=lambda m: dict(m, arch=new_arch),
        dest_suffix=f"-arch-{new_arch}",
    )


def _repack_with_version(src_tarball, work_dir, *, new_version):
    """Re-tar the staged tree with MANIFEST.version overwritten.

    Also renames the top-level directory inside the tarball to match
    the new version, otherwise install.sh's extract step fails before
    the version check fires.
    """
    return _repack(
        src_tarball, work_dir,
        mutator=lambda m: dict(m, version=new_version),
        rename_to_version=new_version,
        dest_suffix=f"-ver-{new_version}",
    )


def _repack(src_tarball, work_dir, *, mutator,
            rename_to_version=None, dest_suffix=""):
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    extract_dir = work_dir / "extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir()

    with tarfile.open(src_tarball, "r:gz") as tf:
        tf.extractall(extract_dir, filter="data")
    top = next(p for p in extract_dir.iterdir() if p.is_dir())

    manifest_path = top / "MANIFEST"
    manifest = json.loads(manifest_path.read_text())
    manifest = mutator(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    if rename_to_version is not None:
        new_top_name = f"sandboxd-{rename_to_version}-{manifest['arch']}"
        new_top = top.parent / new_top_name
        top.rename(new_top)
        top = new_top

    dest = work_dir / f"{top.name}{dest_suffix}.tar.gz"
    with tarfile.open(dest, "w:gz") as tf:
        tf.add(top, arcname=top.name)
    # Stub .sigstore (install.sh's cosign step is patched out, but the
    # bundle-copy in tarball_fetch still needs a sibling file to exist
    # when --cosign-bundle is not passed).
    sigstore_stub = work_dir / f"{dest.name}.sigstore"
    sigstore_stub.write_bytes(b"")
    return dest
