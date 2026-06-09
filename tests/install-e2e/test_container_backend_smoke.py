"""Container backend lite-image smoke test under the real systemd unit.

This test guards against the regression where ``docker build`` fails when
the daemon runs under systemd with ``HOME=/nonexistent`` (the system user
home): Docker's build client tries to create its config directory under
``$HOME`` and aborts with ``mkdir /nonexistent: permission denied`` before
any layer is fetched.

The fix in ``container.rs`` sets ``HOME`` and ``DOCKER_CONFIG`` explicitly
on the docker subprocess so the config directory lands in the writable
daemon base-dir. This test exercises exactly that path — the real systemd
unit, the real ``sandbox rebuild-image --backend container`` command, and
the production ``HOME=/nonexistent`` system-user environment — and will
FAIL without the fix, PASS with it.

The container (lite) backend requires Docker but NOT nested KVM, so it is
feasible inside the Lima-controlled e2e VMs (unlike the Lima backend, which
would need nested KVM and is explicitly excluded here).
"""

from __future__ import annotations

import pytest

from conftest import (
    assert_doctor_passes,
    copy_tarball_to_vm,
    install_sh_cmd,
    wait_for_socket,
    wait_for_systemd_active,
)


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_container_backend_rebuild_image_under_systemd(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """sandbox rebuild-image --backend container succeeds under the real systemd unit.

    Regression guard for the ``HOME=/nonexistent`` bug: the daemon's system
    user is created with ``--home-dir /nonexistent``; systemd inherits that
    HOME; docker build fails trying to create its config dir there.

    Steps:
    1. Fresh install via install.sh (with --no-provision as normal for e2e).
    2. systemctl enable --now sandboxd — daemon starts under the real unit.
    3. ``sandbox rebuild-image --backend container`` as the sandbox user —
       must exit 0. Fails without the container.rs HOME/DOCKER_CONFIG fix.
    4. Assert the image tag is present via ``docker image inspect``.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # Step 1: install sandboxd.
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install.sh failed (exit {r.returncode})\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Step 2: start the daemon under the real systemd unit.
    r = vm.shell("sudo systemctl enable --now sandboxd", timeout=60)
    assert r.returncode == 0, (
        f"systemctl enable --now sandboxd failed:\n{r.stdout}\n{r.stderr}"
    )
    wait_for_systemd_active(vm.name, "sandboxd", timeout=30)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=30)

    # Sanity-check: daemon passes doctor before we stress the build path.
    assert_doctor_passes(vm)

    # Step 3: request a lite-image rebuild via the container backend.
    # We run as the sandbox user (the daemon's uid), pointing the CLI at
    # the production socket, and capture full output for diagnosis.
    #
    # The rebuild command shells out to ``docker build``; the daemon's
    # subprocess must NOT inherit ``HOME=/nonexistent`` — that is exactly
    # what container.rs now prevents by setting HOME and DOCKER_CONFIG
    # explicitly on the Command before exec-ing docker.
    r = vm.shell(
        "sudo -u sandbox env"
        " SANDBOX_SOCKET=/run/sandbox/sandboxd.sock"
        " /usr/local/bin/sandbox rebuild-image --backend container",
        timeout=300,
    )
    text = r.stdout + r.stderr
    assert r.returncode == 0, (
        f"sandbox rebuild-image --backend container exited {r.returncode}\n"
        f"This indicates the docker build failed — likely HOME/DOCKER_CONFIG "
        f"not set correctly on the docker subprocess.\n"
        f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    )

    # Step 4: verify the image tag is present in the Docker image store.
    # The tag pattern is ``sandboxd-lite:<daemon-version>`` where the version
    # comes from the installed binary's ``/version`` response. We probe with
    # a name-only filter because the exact version string is embedded in the
    # tarball and not repeated here.
    r_tag = vm.shell(
        "sudo -u sandbox docker image ls --format '{{.Repository}}:{{.Tag}}'"
        " | grep sandboxd-lite",
        timeout=30,
    )
    assert r_tag.returncode == 0 and "sandboxd-lite" in r_tag.stdout, (
        f"sandboxd-lite image not found after rebuild-image succeeded\n"
        f"docker image ls output:\n{r_tag.stdout}\nstderr:\n{r_tag.stderr}"
    )

    # Step 5 (optional probe): prove the Rust cmd.env("HOME", ...) is load-bearing.
    # Inject Environment=HOME=/nonexistent via a systemd drop-in (overriding the
    # defense-in-depth Environment=HOME=@SANDBOX_BASE_DIR@ line in the unit) to
    # simulate the broken-HOME environment, then verify rebuild-image still
    # succeeds. This proves the Rust-level fix does the work — not just the unit
    # file. Skipped when the test user cannot sudo (shouldn't happen in the VM).
    r_sudo = vm.shell("sudo -n true", timeout=5)
    if r_sudo.returncode != 0:
        return  # cannot create drop-in without sudo — skip

    dropin_dir = "/etc/systemd/system/sandboxd.service.d"
    dropin_path = f"{dropin_dir}/test-broken-home.conf"
    vm.shell(f"sudo mkdir -p {dropin_dir}", check=True, timeout=5)
    vm.shell(
        f"printf '[Service]\\nEnvironment=HOME=/nonexistent\\n'"
        f" | sudo tee {dropin_path} > /dev/null",
        check=True, timeout=5,
    )
    try:
        vm.shell("sudo systemctl daemon-reload", check=True, timeout=15)
        vm.shell("sudo systemctl restart sandboxd", check=True, timeout=30)
        wait_for_systemd_active(vm.name, "sandboxd", timeout=30)
        wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=30)

        r_dropin = vm.shell(
            "sudo -u sandbox env"
            " SANDBOX_SOCKET=/run/sandbox/sandboxd.sock"
            " /usr/local/bin/sandbox rebuild-image --backend container",
            timeout=300,
        )
        assert r_dropin.returncode == 0, (
            f"rebuild-image failed even with Rust fix in place (drop-in injects "
            f"HOME=/nonexistent to replicate the pre-fix environment)\n"
            f"exit={r_dropin.returncode}\n"
            f"stdout:\n{r_dropin.stdout}\nstderr:\n{r_dropin.stderr}"
        )
    finally:
        vm.shell(f"sudo rm -f {dropin_path}", timeout=5)
        vm.shell("sudo systemctl daemon-reload", timeout=15)
