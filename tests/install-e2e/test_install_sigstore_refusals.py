"""Negative-path tests for install.sh's sigstore_verify step.

Pairs with the happy-path coverage in ``test_install_happy_path.py``.
Both tests assume the locally-signed release tarball from the
session-scope ``release_tarball_x86_64`` fixture and the live
``sigstore_stack`` fixture.

Scenarios:

* **Missing bundle.** Delete the sibling ``.sigstore`` bundle from
  the VM before install.sh runs. The script's ``tarball_fetch`` step
  must surface the operator-readable refusal "no cosign bundle: pass
  --cosign-bundle or place a .sigstore file next to the tarball"
  (install.sh §§ 4.4.9-4.4.10, mirrored in
  ``sandbox-cli/src/update/fetch.rs::resolve_bundle_path``).

* **Tampered tarball.** Sign the tarball, then flip a single byte of
  the tarball bytes BEFORE install.sh runs. The script's
  ``sigstore_verify`` step must surface a non-zero exit with a
  cosign verify-blob failure message; the install must abort before
  the user / binary / systemd-unit mutations land.

A third candidate (expired JWT → Fulcio refuses at sign time) is out
of scope here because the tarball is already signed by the
session-scope fixture; exercising expired-JWT would require a
separate per-test bumped fixture and adds little marginal coverage
over the two scenarios above.
"""

from __future__ import annotations

import pytest

from conftest import (
    copy_tarball_to_vm,
    install_sh_cmd,
    stage_sigstore_trust_material_in_vm,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_aborts_on_missing_sigstore_bundle(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """install.sh refuses cleanly when the .sigstore bundle is absent.

    Reproducer: copy the tarball in via the canonical helper (which
    plants both ``<tarball>.tar.gz`` and ``<tarball>.tar.gz.sigstore``),
    then delete the bundle alone. install.sh's tarball_fetch step
    will fail at the "no cosign bundle" guard well before any state
    mutation; we assert both the exit code and the operator-visible
    error string.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Stage trust material (so install.sh has the env vars it expects
    # in the unlikely path of reaching sigstore_verify before this
    # guard — we want the failure to surface at the bundle guard, not
    # downstream from missing trust material).
    env = stage_sigstore_trust_material_in_vm(vm, sigstore_stack)

    # Delete the bundle. We assert it was present before so a
    # regression that breaks copy_tarball_to_vm's bundle staging
    # doesn't masquerade as a pass on this test.
    assert vm.shell(
        f"test -e {tarball_in_vm}.sigstore"
    ).returncode == 0, "bundle not staged before delete — fixture regression"
    vm.shell(f"rm -f {tarball_in_vm}.sigstore", check=True, timeout=10)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, env=env),
        timeout=180,
    )
    assert r.returncode != 0, (
        f"install.sh accepted a missing sigstore bundle:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )
    output = (r.stdout + r.stderr).lower()
    assert "no cosign bundle" in output or ".sigstore" in output, (
        f"missing bundle refusal message not surfaced:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The aborted install must not have created the sandbox system
    # user or planted any binaries — tarball_fetch fails well before
    # those steps. This is the load-bearing assertion: a regression
    # that REACHES later steps (despite the missing bundle) would
    # leak state.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode != 0, (
        "sandboxd binary installed despite missing-bundle refusal — "
        "install.sh ordering regression"
    )
    assert vm.shell("getent passwd sandbox").returncode != 0, (
        "sandbox user created despite missing-bundle refusal — "
        "install.sh ordering regression"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_aborts_on_tampered_tarball(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """install.sh refuses cleanly when the tarball bytes were mutated.

    Reproducer: copy the signed tarball into the VM, then flip a
    single byte in the tarball file (NOT the bundle — the bundle's
    embedded cert chain remains valid). cosign verify-blob inside
    install.sh's sigstore_verify step computes the digest over the
    tarball bytes and compares against the signature; the digest no
    longer matches, so verify-blob exits non-zero. install.sh's
    ``die "sigstore verification failed for ..."`` translates that
    into a non-zero exit + operator-visible refusal.

    Byte-flip target: offset 0 (gzip magic header). This guarantees
    the digest changes; cosign doesn't decompress, so the failure
    point is the cryptographic check, not a tar/gzip parse error.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)
    env = stage_sigstore_trust_material_in_vm(vm, sigstore_stack)

    # Confirm the bundle is non-empty (regression guard against the
    # build script emitting the zero-byte stub when the stack didn't
    # come up — without this guard, the test would pass for the
    # wrong reason).
    size_check = vm.shell(
        f"stat --format=%s {tarball_in_vm}.sigstore",
        check=True, timeout=10,
    )
    bundle_size = int(size_check.stdout.strip())
    assert bundle_size > 0, (
        f"sigstore bundle is empty ({bundle_size}B) — the build script "
        "did not sign against the local stack; test cannot exercise "
        "the tampered-signature contract"
    )

    # Flip the first byte of the tarball. We overwrite byte 0 with a
    # NUL from /dev/zero rather than going through printf (whose
    # \xNN form is a bash extension; POSIX sh doesn't accept it).
    # conv=notrunc keeps the file size; bs=1 count=1 writes one byte.
    # status=none keeps the test output clean; on failure we re-run
    # without it to surface the underlying error.
    vm.shell(
        f"sudo dd if=/dev/zero of={tarball_in_vm} bs=1 count=1 "
        f"conv=notrunc status=none",
        check=True, timeout=10,
    )

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, env=env),
        timeout=300,
    )
    assert r.returncode != 0, (
        f"install.sh accepted a tampered tarball:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # The refusal must mention sigstore verification specifically —
    # if a regression makes install.sh fail at a later step (e.g.
    # gzip decode), the test passes for the wrong reason.
    output = (r.stdout + r.stderr).lower()
    assert "sigstore" in output or "verification" in output, (
        f"sigstore-verification refusal message not surfaced:\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Same state-leak assertions as the missing-bundle test.
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode != 0, (
        "sandboxd installed despite tampered-tarball refusal"
    )
    assert vm.shell("getent passwd sandbox").returncode != 0, (
        "sandbox user created despite tampered-tarball refusal"
    )
