"""macOS install.sh refusal-path e2e (Tart guest).

Two refusals validated live on Darwin:

* ``test_install_macos_refuses_missing_qemu_prereq`` — with socket_vmnet + lima
  present but ``qemu-system-aarch64`` hidden, install.sh's Darwin
  ``check_prereqs`` must refuse with actionable ``brew install qemu`` guidance
  and never touch the system (no ``_sandboxd`` user, no binaries).
* ``test_install_macos_refuses_tampered_signature`` — a tarball whose
  ``.sigstore`` bundle has been corrupted must be rejected at the cosign
  ``verify-blob`` step; install.sh exits non-zero and stages nothing.

NOTE — Intel-refusal (the arch-mismatch refusal install.sh raises on an Intel
host fed an arm64 tarball, or vice versa) is NOT runnable on this arm64 host:
Tart cannot boot an x86_64 macOS guest on Apple Silicon. It is skipped with a
clear note rather than faked.

macOS-only (Darwin/arm64); the fixtures skip on every other host.
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

import pytest

from conftest import (
    DIST_DIR,
    copy_tarball_to_tart_vm,
    install_sh_cmd_macos,
    version_from_tarball,
)


@pytest.mark.macos
def test_install_macos_refuses_missing_qemu_prereq(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
):
    """install.sh refuses (exit !=0, actionable guidance) when qemu is absent.

    socket_vmnet + lima are present (factory brew-installs them); we hide the
    qemu binary so only the qemu prereq is missing, isolating the GAP-#5 qemu
    prereq check that the bfb5540 fix added to the Darwin path.
    """
    vm = tart_vm_factory()

    # Hide qemu-system-aarch64 from both probe sites: the PATH lookup
    # (`command -v`) and the explicit `/opt/homebrew/bin/qemu-system-aarch64`
    # fallback in check_qemu_installed. Homebrew symlinks the binary into
    # /opt/homebrew/bin; renaming the symlink aside makes both probes fail
    # without uninstalling the (lima-dependency) keg.
    vm.shell(
        "if [ -e /opt/homebrew/bin/qemu-system-aarch64 ]; then "
        "  sudo mv /opt/homebrew/bin/qemu-system-aarch64 "
        "    /opt/homebrew/bin/qemu-system-aarch64.hidden; "
        "fi",
        check=True, timeout=30,
    )
    # Sanity: qemu is now unreachable both ways.
    probe = vm.shell(
        "command -v qemu-system-aarch64 >/dev/null 2>&1 && echo FOUND || echo HIDDEN; "
        "test -x /opt/homebrew/bin/qemu-system-aarch64 && echo FALLBACK || echo NOFALLBACK"
    )
    assert "HIDDEN" in probe.stdout and "NOFALLBACK" in probe.stdout, (
        f"failed to hide qemu before the refusal test: {probe.stdout!r}"
    )

    tarball_in_vm = copy_tarball_to_tart_vm(vm, release_tarball_darwin)
    r = vm.shell(
        install_sh_cmd_macos(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=300,
    )
    assert r.returncode != 0, (
        f"install.sh accepted a host missing qemu-system-aarch64:\n{r.stdout}\n{r.stderr}"
    )
    output = (r.stdout + r.stderr).lower()
    assert "missing prerequisites" in output, (
        f"refusal missing the 'missing prerequisites' banner:\n{r.stdout}\n{r.stderr}"
    )
    assert "qemu" in output and "brew install qemu" in output, (
        f"qemu refusal missing actionable 'brew install qemu' guidance:\n{r.stdout}\n{r.stderr}"
    )

    # Refusal must have touched nothing: no _sandboxd user, no staged binary.
    assert vm.shell("dscl . -read /Users/_sandboxd UniqueID").returncode != 0, (
        "install.sh created the _sandboxd user despite a prereq refusal"
    )
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "install.sh staged the daemon binary despite a prereq refusal"
    )


@pytest.mark.macos
def test_install_macos_refuses_tampered_signature(
    tart_vm_factory, release_tarball_darwin, sigstore_stack, tart_sigstore_relay,
    tmp_path,
):
    """A corrupted .sigstore bundle is rejected at cosign verify-blob.

    We copy the genuine Darwin tarball in, then overwrite its sibling
    ``.sigstore`` bundle with garbage. install.sh's sigstore_verify step runs
    cosign verify-blob against the real trust material (staged via the relay)
    and must fail closed — exit non-zero, stage nothing.
    """
    vm = tart_vm_factory()

    # Build a tampered copy of the tarball + a corrupted sibling bundle on the
    # host, then copy BOTH in (copy_tarball_to_tart_vm copies the tarball + its
    # .sigstore sibling). We tamper the bundle after the copy instead, in-guest,
    # to avoid disturbing the host dist artifacts other session-scoped fixtures
    # reuse.
    tarball_in_vm = copy_tarball_to_tart_vm(vm, release_tarball_darwin)

    # Corrupt the staged .sigstore bundle in the guest (flip it to garbage).
    vm.shell(
        f"printf 'tampered-not-a-valid-sigstore-bundle\\n' | "
        f"tee {tarball_in_vm}.sigstore >/dev/null",
        check=True, timeout=15,
    )

    r = vm.shell(
        install_sh_cmd_macos(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=300,
    )
    assert r.returncode != 0, (
        f"install.sh accepted a tampered .sigstore bundle:\n{r.stdout}\n{r.stderr}"
    )
    output = (r.stdout + r.stderr).lower()
    # The refusal should mention signature/verification failure. install.sh's
    # sigstore_verify emits a verification-failure message; cosign's own error
    # is routed to the debug log under the test env.
    assert any(
        tok in output for tok in ("signature", "verif", "cosign", "sigstore")
    ), (
        f"tampered-signature refusal missing a signature-verification message:\n"
        f"{r.stdout}\n{r.stderr}"
    )

    # Nothing staged.
    assert vm.shell("dscl . -read /Users/_sandboxd UniqueID").returncode != 0, (
        "install.sh created the _sandboxd user despite a signature refusal"
    )
    assert vm.shell("test -x /usr/local/libexec/sandboxd/sandboxd").returncode != 0, (
        "install.sh staged the daemon binary despite a signature refusal"
    )


@pytest.mark.macos
@pytest.mark.skip(
    reason="Intel-refusal (arm64 tarball on x86_64 macOS host, or vice versa) "
    "cannot run on this Apple-Silicon host — Tart cannot boot an x86_64 macOS "
    "guest on arm64. The arch-mismatch refusal logic is covered by the Linux "
    "test_install_refusal.py::test_install_refuses_wrong_arch_tarball cell + "
    "install.sh's MANIFEST arch cross-check; revalidate on an Intel Mac host."
)
def test_install_macos_refuses_wrong_arch_intel():
    """Placeholder for the Intel/arch-mismatch refusal — not runnable on arm64."""
