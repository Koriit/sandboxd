"""Shared fixtures + helpers for the install.sh / uninstall.sh Lima harness.

The harness boots a fresh Lima VM per test, copies the locally-built
release tarball into it, copies a patched install.sh/uninstall.sh into
it, and runs the install path end-to-end. Each VM is torn down in the
test's ``finally``; the suite is intentionally serial.

Why patch install.sh? Two reasons:

* The release tarball assembled by ``build-local-tarball.sh`` is
  unsigned. The script's sigstore-verify step would otherwise refuse it.
* Downloading the real cosign binary inside every VM is slow and noisy.

The patch replaces ``cosign_bootstrap`` and ``sigstore_verify`` with
no-ops that emit the same log lines as the real flow. Every other step
(arch detect, prereq, useradd, setcap, docker load, systemd unit
install, write_install_state, ...) runs unmodified — those are the
steps the harness exists to exercise.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
INSTALL_SH = SCRIPTS_DIR / "install.sh"
UNINSTALL_SH = SCRIPTS_DIR / "uninstall.sh"
LIB_SH = SCRIPTS_DIR / "lib.sh"

DIST_DIR = HERE / "dist"
LOGS_DIR = HERE / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

VM_BOOT_TIMEOUT = 360  # seconds
VM_PROVISION_TIMEOUT = 600
SOCKET_WAIT_TIMEOUT = 60

# Distro templates available via `template://<name>` on Lima >=2.0.
# fedora-40 isn't shipped with Lima 2.1; fedora-41 is the closest stand-in
# for the RHEL-paths test (same /usr/libexec/qemu-bridge-helper layout).
DEFAULT_FEDORA = "fedora-41"


# ---------------------------------------------------------------------------
# pytest_runtest_makereport — stash phase outcome for autouse log-on-fail.
# ---------------------------------------------------------------------------

@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)


# ---------------------------------------------------------------------------
# Lima primitives.
# ---------------------------------------------------------------------------

def _run(cmd, *, check=True, timeout=120, capture=True, env=None):
    """Thin wrapper around subprocess.run with sensible defaults."""
    result = subprocess.run(
        cmd,
        check=False,
        timeout=timeout,
        capture_output=capture,
        text=True,
        env=env,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed (exit {result.returncode}): {cmd}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def lima_shell(vm_name, command, *, check=False, timeout=180, user=None):
    """Run a shell command inside the Lima VM via ``limactl shell``.

    Returns a CompletedProcess. By default does NOT raise on non-zero so
    tests can assert on exit codes; pass ``check=True`` to fault on
    failure.

    ``user`` (if given) wraps the command with ``sudo -u <user> sh -c
    '...'`` so we exercise the post-install operator's view of the
    system (the install script's pre-installed Lima user is ``lima``,
    not ``sandbox``).
    """
    if user is not None:
        # Wrap in `sudo -u USER` from inside the VM. We pass `--` after
        # `shell <vm>` to prevent limactl from interpreting test
        # commands as its own flags.
        wrapped = f"sudo -u {user} -- sh -c {_sh_quote(command)}"
        argv = ["limactl", "shell", vm_name, "--", "sh", "-c", wrapped]
    else:
        argv = ["limactl", "shell", vm_name, "--", "sh", "-c", command]
    return _run(argv, check=check, timeout=timeout)


def _sh_quote(s):
    """POSIX-safe single-quote wrap."""
    return "'" + s.replace("'", r"'\''") + "'"


def lima_cp(vm_name, src, dst):
    """Copy a local file into the Lima VM.

    Uses `limactl copy <src> <vm>:<dst>` (where <dst> is an absolute
    path in the guest). Permissions follow Lima's defaults (rw-r--r--);
    the install scripts re-install binaries with explicit modes anyway.
    """
    src_str = str(src)
    dst_target = f"{vm_name}:{dst}"
    _run(["limactl", "copy", src_str, dst_target], timeout=120)


def wait_for_socket(vm_name, sock_path, *, timeout=SOCKET_WAIT_TIMEOUT):
    """Block until <sock_path> exists inside the VM as a unix socket.

    Runs the probe under ``sudo`` because the parent runtime directory
    (``/run/sandbox``) is created by systemd at mode 0750 owned by
    ``sandbox:sandbox`` — the default ``lima`` user that ``limactl
    shell`` lands as is not in the ``sandbox`` group, so an unprivileged
    ``test -S`` would always fail with EACCES regardless of whether the
    socket exists.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = lima_shell(
            vm_name,
            f"sudo test -S {sock_path} && echo ok",
            timeout=10,
        )
        if result.returncode == 0 and "ok" in result.stdout:
            return
        time.sleep(2)
    raise AssertionError(
        f"{sock_path} did not appear in {vm_name} within {timeout}s"
    )


def wait_for_systemd_active(vm_name, unit, *, timeout=30):
    """Poll ``systemctl is-active <unit>`` until it returns ``active``.

    ``systemctl enable --now`` returns once the unit is *enqueued* — the
    daemon may still be in the ``activating`` state when the call returns.
    This helper closes that race by polling until the unit reaches a
    terminal state. On ``failed`` we short-circuit (no point waiting) and
    surface a journal dump in the AssertionError to keep failures
    self-debugging.
    """
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        result = lima_shell(
            vm_name,
            f"systemctl is-active {unit}",
            timeout=10,
        )
        last = result.stdout.strip()
        if last == "active":
            return
        if last == "failed":
            journal = lima_shell(
                vm_name,
                f"sudo journalctl -u {unit} -n 50 --no-pager",
                timeout=15,
            ).stdout
            raise AssertionError(
                f"{unit} entered failed state\n"
                f"--- journalctl -u {unit} -n 50 ---\n{journal}"
            )
        time.sleep(1)
    journal = lima_shell(
        vm_name,
        f"sudo journalctl -u {unit} -n 50 --no-pager",
        timeout=15,
    ).stdout
    raise AssertionError(
        f"{unit} did not reach active within {timeout}s (last state: {last!r})\n"
        f"--- journalctl -u {unit} -n 50 ---\n{journal}"
    )


def lima_vm_name(prefix="iet"):
    """A short, unique VM name. Lima caps at 60 chars; keep margin."""
    return f"sb-{prefix}-{uuid.uuid4().hex[:8]}"


def lima_start(vm_name, template, *, cpus=2, memory_gib=2, disk_gib=10):
    """Start a Lima VM from a builtin template.

    template is the short name (e.g. "ubuntu-22.04", "fedora-41");
    we use the `template:<name>` form (Lima v2.0+; older
    `template://<name>` is deprecated).

    Default templates mount the host's home directory at the same path
    inside the guest. This collides on shared workstations where the
    host's effective home directory differs from `$HOME` (e.g. a sudo'd
    test runner). We zero out mounts via ``--set`` so the test guest is
    fully isolated from the host filesystem; files are copied in
    explicitly via ``limactl copy``.
    """
    cmd = [
        "limactl", "start",
        f"--name={vm_name}",
        f"template:{template}",
        f"--cpus={cpus}",
        f"--memory={memory_gib}",
        f"--disk={disk_gib}",
        "--set", ".mounts=[]",
        "--tty=false",
    ]
    _run(cmd, timeout=VM_BOOT_TIMEOUT)


def lima_delete(vm_name):
    """Force-delete a Lima VM. Idempotent."""
    subprocess.run(
        ["limactl", "delete", "--force", vm_name],
        capture_output=True, text=True, timeout=120,
    )


# ---------------------------------------------------------------------------
# Install-script patching.
# ---------------------------------------------------------------------------
#
# The patches turn cosign_bootstrap + sigstore_verify into no-ops so the
# locally-assembled (unsigned) tarball passes through the rest of
# install.sh unchanged. They are applied to a tempfile copy; the
# canonical scripts/install.sh on disk is untouched.

_COSIGN_PATCH_TAG = "# PATCHED-BY-INSTALL-E2E"

_COSIGN_BOOTSTRAP_REPLACEMENT = f"""cosign_bootstrap() {{
    {_COSIGN_PATCH_TAG}
    COSIGN=/bin/true
    log_ok "step=cosign_bootstrap version=stub source=test"
}}
"""

_SIGSTORE_VERIFY_REPLACEMENT = f"""sigstore_verify() {{
    {_COSIGN_PATCH_TAG}
    log_ok "step=sigstore_verify bundle=stub identity=test"
}}
"""


def _patch_install_sh(src_path, dst_path):
    """Write a patched copy of install.sh to dst_path.

    Replaces the cosign_bootstrap() and sigstore_verify() function
    bodies with stub implementations that log the same step names.
    """
    text = Path(src_path).read_text()
    text = _replace_shell_function(text, "cosign_bootstrap",
                                   _COSIGN_BOOTSTRAP_REPLACEMENT)
    text = _replace_shell_function(text, "sigstore_verify",
                                   _SIGSTORE_VERIFY_REPLACEMENT)
    Path(dst_path).write_text(text)
    os.chmod(dst_path, 0o755)


def _replace_shell_function(text, func_name, replacement):
    """Replace ``<func_name>() { ... }`` (POSIX shell) with replacement.

    Matches the function header, then walks brace depth (ignoring
    quoted braces is heuristic but install.sh has no such cases in
    cosign_bootstrap / sigstore_verify).
    """
    header_re = re.compile(rf"^{re.escape(func_name)}\(\)\s*\{{\s*$",
                           re.MULTILINE)
    m = header_re.search(text)
    if not m:
        raise AssertionError(f"could not find {func_name}() in install.sh")
    start = m.start()
    # Walk braces from the opening { (which is at m.end() - 1).
    i = m.end() - 1
    depth = 0
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                # Consume the trailing newline if present.
                if end < len(text) and text[end] == "\n":
                    end += 1
                return text[:start] + replacement + text[end:]
        i += 1
    raise AssertionError(f"unmatched braces in {func_name}()")


# ---------------------------------------------------------------------------
# Release tarball fixture.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def release_tarball_x86_64() -> Path:
    """Build the local release tarball once per test session.

    Drives ``build-local-tarball.sh``; honors the script's
    SANDBOX_RELEASE_SKIP_BUILD / SKIP_GATEWAY env vars when set in the
    pytest invocation environment so iteration is fast.
    """
    if subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip() != "x86_64":
        pytest.skip("release_tarball_x86_64 fixture only assembles on x86_64 hosts")

    ver = _read_workspace_version()
    arch = "x86_64-unknown-linux-gnu"
    tarball = DIST_DIR / f"sandboxd-{ver}-{arch}.tar.gz"

    if not tarball.exists() or os.environ.get("SANDBOX_RELEASE_FORCE_REBUILD") == "1":
        subprocess.run(
            [str(HERE / "build-local-tarball.sh")],
            check=True,
            timeout=1800,
        )

    assert tarball.exists(), f"tarball not produced: {tarball}"
    return tarball


def _read_workspace_version() -> str:
    cargo_toml = PROJECT_ROOT / "sandboxd" / "sandboxd" / "Cargo.toml"
    for line in cargo_toml.read_text().splitlines():
        if line.startswith("version"):
            parts = line.split('"')
            if len(parts) >= 2:
                return parts[1]
    raise AssertionError("could not parse workspace version")


# ---------------------------------------------------------------------------
# VM lifecycle fixture factory.
# ---------------------------------------------------------------------------

@dataclass
class VM:
    """Handle on a running Lima VM, with helpers."""
    name: str
    distro: str

    def shell(self, command, **kw):
        return lima_shell(self.name, command, **kw)

    def cp(self, src, dst):
        return lima_cp(self.name, src, dst)


@pytest.fixture
def vm_factory(request):
    """Spawn-on-demand factory for Lima VMs scoped to a single test.

    The factory returns a callable; each invocation produces a fresh VM,
    boots it from the given template, installs the install/uninstall
    prerequisites (jq, curl, qemu, lima, docker, setcap, ovmf, ...) via
    the distro's package manager, copies in install.sh / uninstall.sh,
    and returns a VM handle.

    Every VM created via the factory is force-deleted on test teardown
    (success or failure). On failure, the install log + journalctl
    snapshot is harvested to tests/install-e2e/logs/<test>/<vm>/.
    """
    created = []
    test_name = request.node.name.replace("/", "_").replace(":", "_")[:80]

    def _factory(template, *, install_prereqs=True, install_scripts=True,
                 patch_install_sh=True):
        name = lima_vm_name()
        lima_start(name, template)
        vm = VM(name=name, distro=template)
        created.append(vm)

        if install_prereqs:
            _install_prereqs(vm)

        if install_scripts:
            _stage_scripts(vm, patch_install=patch_install_sh)

        return vm

    yield _factory

    # --- teardown ---
    rep = getattr(request.node, "rep_call", None)
    failed = rep is not None and rep.failed
    for vm in created:
        if failed:
            _harvest_logs(vm, LOGS_DIR / test_name / vm.name)
        lima_delete(vm.name)


def _install_prereqs(vm):
    """Install the install.sh prerequisite packages inside the VM.

    Branches on the distro family; this is the same set of packages
    install.sh's step 6 (`check_prereqs`) verifies.
    """
    if vm.distro.startswith(("ubuntu", "debian")):
        cmd = (
            "set -eux; "
            "export DEBIAN_FRONTEND=noninteractive; "
            "sudo apt-get update; "
            "sudo apt-get install -y --no-install-recommends "
            "ca-certificates curl jq tar qemu-system-x86 qemu-utils "
            "ovmf libcap2-bin coreutils"
        )
        vm.shell(cmd, check=True, timeout=600)
        # Docker
        vm.shell(
            "set -eux; "
            "sudo apt-get install -y --no-install-recommends "
            "docker.io || sudo apt-get install -y docker-ce",
            check=True, timeout=600,
        )
        # Lima — only needed for sandbox doctor's `limactl --version`
        # check. The deb repos don't ship it; install from upstream
        # release.
        vm.shell(
            "set -eux; "
            "ver=2.1.1; "
            "arch=$(uname -m); "
            "case $arch in x86_64) suffix=Linux-x86_64;; "
            "aarch64) suffix=Linux-aarch64;; esac; "
            "tmp=$(mktemp -d); cd $tmp; "
            "curl -fsSL "
            "https://github.com/lima-vm/lima/releases/download/v${ver}/lima-${ver}-${suffix}.tar.gz "
            "-o lima.tar.gz; "
            "sudo tar -C /usr/local -xzf lima.tar.gz",
            check=True, timeout=300,
        )
    elif vm.distro.startswith("fedora"):
        vm.shell(
            "set -eux; "
            "sudo dnf install -y "
            "curl jq tar qemu-kvm qemu-system-x86 edk2-ovmf "
            "libcap docker iptables-services",
            check=True, timeout=600,
        )
        vm.shell(
            "set -eux; "
            "ver=2.1.1; "
            "arch=$(uname -m); "
            "case $arch in x86_64) suffix=Linux-x86_64;; "
            "aarch64) suffix=Linux-aarch64;; esac; "
            "tmp=$(mktemp -d); cd $tmp; "
            "curl -fsSL "
            "https://github.com/lima-vm/lima/releases/download/v${ver}/lima-${ver}-${suffix}.tar.gz "
            "-o lima.tar.gz; "
            "sudo tar -C /usr/local -xzf lima.tar.gz",
            check=True, timeout=300,
        )
    else:
        raise AssertionError(f"unknown distro: {vm.distro}")

    # Enable + start docker — install.sh probes `docker info`.
    vm.shell(
        "set -eux; sudo systemctl enable --now docker",
        check=True, timeout=120,
    )


def _stage_scripts(vm, *, patch_install):
    """Copy install.sh + uninstall.sh into /tmp inside the VM."""
    if patch_install:
        # Write the patched script to a host-side tempfile, then copy.
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", prefix="install-patched-",
            delete=False,
        ) as tf:
            tf.close()
            _patch_install_sh(INSTALL_SH, tf.name)
            vm.cp(tf.name, "/tmp/install.sh")
            os.unlink(tf.name)
    else:
        vm.cp(INSTALL_SH, "/tmp/install.sh")
    vm.cp(UNINSTALL_SH, "/tmp/uninstall.sh")
    # install.sh sources scripts/lib.sh (cosign pin constants) — stage it
    # adjacent so the in-tree fallback `$(dirname $0)/lib.sh` resolves.
    vm.cp(LIB_SH, "/tmp/lib.sh")
    vm.shell("chmod +x /tmp/install.sh /tmp/uninstall.sh", check=True)


def _harvest_logs(vm, dest_dir):
    """Best-effort: dump the install log + journal to disk on failure."""
    dest_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        ("install.log",     "sudo cat /var/log/sandbox-install.log 2>/dev/null || true"),
        ("install-state",   "sudo cat /var/lib/sandbox/.install-state.json 2>/dev/null || true"),
        ("journal-sandboxd", "sudo journalctl -u sandboxd --no-pager 2>/dev/null || true"),
        ("getcap",          "getcap /usr/local/libexec/sandboxd/sandbox-route-helper 2>/dev/null || true"),
        ("ls-bin",          "ls -la /usr/local/bin/sandboxd /usr/local/bin/sandbox /etc/systemd/system/sandboxd.service /etc/sandboxd/users.conf 2>&1 || true"),
    ]
    for fname, cmd in targets:
        try:
            r = vm.shell(cmd, timeout=30)
            (dest_dir / fname).write_text(
                f"=== stdout ===\n{r.stdout}\n=== stderr ===\n{r.stderr}\n"
            )
        except Exception as exc:  # noqa: BLE001
            (dest_dir / fname).write_text(f"harvest error: {exc}\n")


# ---------------------------------------------------------------------------
# Pre-flight check: Lima available on host.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _preflight():
    """Skip the whole suite if Lima or /dev/kvm is unavailable."""
    if shutil.which("limactl") is None:
        pytest.skip("limactl not installed on host")
    if not Path("/dev/kvm").exists():
        pytest.skip("/dev/kvm not available; install-e2e requires KVM")


# ---------------------------------------------------------------------------
# Convenience helpers re-exported for tests.
# ---------------------------------------------------------------------------

def parse_install_log_actions(log_text):
    """Return a dict {step_name: [action, ...]} from an install log."""
    actions = {}
    for line in log_text.splitlines():
        m_step = re.search(r"\bstep=(\S+)", line)
        m_action = re.search(r"\baction=(\S+)", line)
        if m_step and m_action:
            actions.setdefault(m_step.group(1), []).append(m_action.group(1))
    return actions


def copy_tarball_to_vm(vm, tarball_path, dst="/tmp"):
    """Copy a release tarball + its sigstore stub into the VM.

    Both files end up next to each other in /tmp so install.sh's
    ``--from /tmp/<name>.tar.gz`` flow finds the sibling .sigstore
    bundle without an explicit ``--cosign-bundle`` flag.

    Returns the in-VM tarball path.
    """
    tarball_path = Path(tarball_path)
    dst_path = f"{dst.rstrip('/')}/{tarball_path.name}"
    vm.cp(tarball_path, dst_path)

    sig = Path(str(tarball_path) + ".sigstore")
    if not sig.exists():
        sig.write_bytes(b"")
    vm.cp(sig, f"{dst_path}.sigstore")
    return dst_path


_TARBALL_VERSION_RE = re.compile(r"^sandboxd-([^-]+(?:\.[^-]+)*)-")


def version_from_tarball(tarball_path):
    """Extract the version string encoded in the tarball filename.

    Tarball naming convention is ``sandboxd-<version>-<arch>.tar.gz``
    (spec § 2.1). install.sh's resolve_target_version step skips
    network lookup when ``--from`` is set but does NOT auto-derive the
    version from the tarball filename — operators are expected to pass
    ``--version`` alongside ``--from``. The harness mirrors that
    contract here so tests don't have to hard-code "0.1.0".
    """
    name = Path(tarball_path).name
    m = _TARBALL_VERSION_RE.match(name)
    if not m:
        raise AssertionError(
            f"could not parse version from tarball name: {name}"
        )
    return m.group(1)


def make_bumped_tarball(base_tarball, new_version, *, dst_dir=None):
    """Repack ``base_tarball`` with a synthetic bumped version.

    Spec 5 § 9.1's update tests are written against transitions like
    ``v1.0.0 → v1.1.0``. Building a second release tarball with a
    different *binary* version requires either CI-style cross-builds
    (slow + complicated) or version-bumping the source tree (mutates the
    workspace under test). Both are heavy.

    This helper takes the existing single-version tarball and rewrites
    just the metadata so the update flow believes it's a different
    version:

      1. extract to a temp dir;
      2. rename ``sandboxd-<base>-<arch>/`` → ``sandboxd-<new>-<arch>/``;
      3. rewrite ``MANIFEST.version`` to ``new_version``;
      4. rename ``images/sandbox-gateway-<base>.tar`` →
         ``sandbox-gateway-<new>.tar`` (the bytes stay the same — the
         daemon's image-load step short-circuits on ``docker image
         inspect`` when the tag exists in the VM, which the test sets up
         with a manual ``docker tag``);
      5. repack as ``sandboxd-<new>-<arch>.tar.gz``.

    The synthesised tarball still ships the **original** v<base>
    binaries. Tests that observe daemon ``/version`` after the upgrade
    will read the binary's compiled-in version (= the base version),
    NOT the synthesised ``new_version``. The synthesised version is
    visible only in:

      * ``MANIFEST.version`` inside the tarball;
      * the staged directory + image-tar paths;
      * ``install_state.installed_version`` (written by the update flow
        from the MANIFEST, not from the binary).

    Tests that assert "daemon at v1.1.0 after upgrade" cannot be
    satisfied by this helper — they need a genuinely-different binary,
    which Spec 5 § 9.1 acknowledges as a multi-version harness gap. The
    skips in the test files document this constraint explicitly.

    Returns the path to the bumped tarball; the caller is responsible
    for copying it into the VM via ``copy_tarball_to_vm``.
    """
    import tarfile
    import tempfile

    base_tarball = Path(base_tarball)
    base_ver = version_from_tarball(base_tarball)
    if new_version == base_ver:
        raise AssertionError(
            f"make_bumped_tarball: new_version {new_version} == base_version; "
            "use the base tarball directly"
        )
    arch = "x86_64-unknown-linux-gnu"
    if dst_dir is None:
        dst_dir = DIST_DIR
    dst_dir = Path(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    new_tarball = dst_dir / f"sandboxd-{new_version}-{arch}.tar.gz"
    if new_tarball.exists():
        return new_tarball  # cached

    with tempfile.TemporaryDirectory(prefix="bumped-tar-") as tmp:
        tmp = Path(tmp)
        with tarfile.open(base_tarball, "r:gz") as tf:
            tf.extractall(tmp)
        old_stage = tmp / f"sandboxd-{base_ver}-{arch}"
        new_stage = tmp / f"sandboxd-{new_version}-{arch}"
        old_stage.rename(new_stage)

        # Rewrite MANIFEST.version (preserve all other fields).
        manifest_path = new_stage / "MANIFEST"
        manifest = json.loads(manifest_path.read_text())
        manifest["version"] = new_version
        # Also bump the gateway-image path key — the daemon reads
        # `staged.gateway_image_tar()` as `images/sandbox-gateway-<ver>.tar`,
        # so the artifact path needs to match.
        if "gateway-image" in manifest.get("artifacts", {}):
            manifest["artifacts"]["gateway-image"]["path"] = (
                f"images/sandbox-gateway-{new_version}.tar"
            )
            manifest["artifacts"]["gateway-image"]["docker_tag"] = (
                f"sandbox-gateway:{new_version}"
            )
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

        # Rename gateway-image tar (same bytes).
        old_image = new_stage / "images" / f"sandbox-gateway-{base_ver}.tar"
        new_image = new_stage / "images" / f"sandbox-gateway-{new_version}.tar"
        if old_image.exists():
            old_image.rename(new_image)

        # Repack.
        with tarfile.open(new_tarball, "w:gz") as tf:
            tf.add(new_stage, arcname=new_stage.name)

    # Sigstore stub.
    Path(str(new_tarball) + ".sigstore").write_bytes(b"")
    return new_tarball


def retag_gateway_image_in_vm(vm, *, from_tag, to_tag):
    """Manually ``docker tag`` the gateway image inside the VM.

    The bumped tarball's image-tar bytes are identical to the base
    tarball's, but the daemon's ``docker image inspect
    sandbox-gateway:<new>`` short-circuit means a load is never
    attempted. We pre-tag the already-loaded image so the inspect
    succeeds.
    """
    vm.shell(
        f"sudo docker tag {from_tag} {to_tag}",
        check=True, timeout=30,
    )


def install_sh_cmd(tarball_in_vm, *extra_flags, env=None):
    """Build the canonical install.sh invocation used by every test.

    Always passes ``--from``, ``--version``, ``--yes``, ``--no-color``
    so test output is parser-friendly and idempotency assertions land
    on a known version string. Additional flags (e.g. ``--cosign-bundle``)
    can be appended.

    ``env`` is an optional dict of environment variables exported to
    the install.sh process (via ``sudo VAR=val ...``). Used by the
    air-gapped test to set ``SANDBOX_INSTALL_SKIP_SIGSTORE=1`` (test-
    only bypass; see install.sh::sigstore_verify).
    """
    ver = version_from_tarball(tarball_in_vm)
    env_prefix = ""
    if env:
        # `sudo VAR=val ...` preserves the env var into the script's
        # process; `sudo -E` would pull the entire current env in, which
        # we deliberately avoid to keep the test's contract narrow.
        env_prefix = " ".join(f"{k}={_sh_quote(v)}" for k, v in env.items()) + " "
    base = [
        f"sudo {env_prefix}bash /tmp/install.sh",
        f"--from {tarball_in_vm}",
        f"--version {ver}",
        "--yes",
        "--no-color",
    ]
    base.extend(extra_flags)
    return " ".join(base)


def assert_doctor_passes(vm, *, user=None, timeout=60, sock_path=None):
    """Run `sandbox doctor` and assert it reports zero failures.

    The CLI's doctor command exit code is 0 on green; we also assert
    the ``"checks passed, 0 failed"`` token per spec § 6.2 — exit code
    alone is insufficient because a broken doctor might silently exit 0
    without performing checks.

    Defaults to running as the ``sandbox`` system user with
    ``SANDBOX_SOCKET=/run/sandbox/sandboxd.sock`` (matches the production
    daemon's socket path and the runtime user of the systemd unit).
    """
    if user is None:
        user = "sandbox"
    if sock_path is None:
        sock_path = "/run/sandbox/sandboxd.sock"
    # `sudo -u <user> env SANDBOX_SOCKET=... sandbox doctor` — the env
    # wrapper is required because `sudo -u` drops most of the caller's
    # env unless we replant the socket path explicitly. Mirrors
    # integration_systemd_unit_smokes.
    cmd = f"sudo -u {user} env SANDBOX_SOCKET={sock_path} /usr/local/bin/sandbox doctor"
    r = vm.shell(cmd, timeout=timeout)
    text = r.stdout + r.stderr
    if r.returncode != 0:
        raise AssertionError(
            f"sandbox doctor exited {r.returncode}\n{text}"
        )
    if "checks passed, 0 failed" not in r.stdout:
        raise AssertionError(
            f"sandbox doctor missing 'checks passed, 0 failed' token\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )
    return text


def assert_full_install_landed(vm):
    """Shared post-install filesystem-state asserts.

    Covers the observable post-conditions every install path must
    satisfy regardless of distro: binaries in place + executable, route-
    helper has the expected file capabilities, systemd unit installed,
    install-state file present and parseable, sandbox system user
    created. Lifted into a helper so both the Debian-family and RHEL-
    family happy-path tests assert the same contract (per § 6.3).
    """
    assert vm.shell("test -x /usr/local/bin/sandboxd").returncode == 0, (
        "sandboxd binary missing or not executable"
    )
    assert vm.shell("test -x /usr/local/bin/sandbox").returncode == 0, (
        "sandbox CLI binary missing or not executable"
    )
    assert vm.shell(
        "test -x /usr/local/libexec/sandboxd/sandbox-route-helper"
    ).returncode == 0, "route-helper missing or not executable"
    assert vm.shell(
        "test -f /etc/systemd/system/sandboxd.service"
    ).returncode == 0, "systemd unit not installed"

    caps = vm.shell(
        "getcap /usr/local/libexec/sandboxd/sandbox-route-helper",
    ).stdout
    assert "cap_net_admin,cap_sys_admin=eip" in caps, (
        f"unexpected route-helper caps: {caps!r}"
    )

    # State file exists and is valid JSON.
    state_check = vm.shell(
        "sudo cat /var/lib/sandbox/.install-state.json",
        check=True, timeout=10,
    )
    state = json.loads(state_check.stdout)
    assert state.get("installed_version"), (
        f"install-state missing installed_version: {state!r}"
    )
    # `jq -e .` is the canonical "this is well-formed" smoke; cross-
    # check that the same file parses under jq inside the VM (json.loads
    # above runs on the host).
    assert vm.shell(
        "sudo jq -e . /var/lib/sandbox/.install-state.json",
        timeout=10,
    ).returncode == 0, "install-state.json not parseable by jq inside the VM"

    # `getent passwd sandbox` returns a row; the daemon runs as this user.
    r = vm.shell("getent passwd sandbox")
    assert r.returncode == 0 and r.stdout.strip(), (
        f"sandbox user missing: {r.stdout!r}"
    )

    return state


# ---------------------------------------------------------------------------
# Pre-staged cosign binary (air-gapped test).
# ---------------------------------------------------------------------------
#
# The air-gapped test exercises install.sh's `cosign_bootstrap` fallback
# (which copies /usr/local/bin/cosign into the script's tmpdir after
# verifying its sha256 against the pinned constant). To exercise that
# path we pre-stage a cosign binary whose sha256 matches the constant
# baked into install.sh. The binary is downloaded once per session on
# the host (before any test goes air-gapped) and cached under
# tests/install-e2e/dist/cosign-pinned/.

# Mirrors the COSIGN_SHA256_AMD64 / COSIGN_VERSION constants in
# scripts/install.sh. If install.sh bumps cosign, update these in
# lockstep — there is no automated drift check (call out in the spec
# review pass).
COSIGN_VERSION = "v2.4.1"
COSIGN_SHA256_AMD64 = (
    "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b"
)
COSIGN_SHA256_ARM64 = (
    "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a"
)


@pytest.fixture(scope="session")
def pinned_cosign_binary() -> Path:
    """Return a host-cached cosign binary matching install.sh's pin.

    Downloaded once per session on the host (where network is
    available) so individual VMs can have egress blocked before the
    test body runs. The fixture verifies sha256 against the constant
    install.sh bakes in; a mismatch fails fast rather than letting the
    in-VM install.sh discover it.
    """
    cosign_dir = DIST_DIR / "cosign-pinned"
    cosign_dir.mkdir(parents=True, exist_ok=True)
    machine = subprocess.run(
        ["uname", "-m"], capture_output=True, text=True
    ).stdout.strip()
    if machine == "x86_64":
        cosign_bin = "cosign-linux-amd64"
        expected_sha = COSIGN_SHA256_AMD64
    elif machine == "aarch64":
        cosign_bin = "cosign-linux-arm64"
        expected_sha = COSIGN_SHA256_ARM64
    else:
        pytest.skip(f"no pinned cosign for {machine}")
    dest = cosign_dir / cosign_bin
    if not dest.exists() or hashlib.sha256(dest.read_bytes()).hexdigest() != expected_sha:
        url = (
            f"https://github.com/sigstore/cosign/releases/download/"
            f"{COSIGN_VERSION}/{cosign_bin}"
        )
        subprocess.run(
            ["curl", "-fsSL", "-o", str(dest), url],
            check=True, timeout=300,
        )
    actual = hashlib.sha256(dest.read_bytes()).hexdigest()
    if actual != expected_sha:
        raise AssertionError(
            f"cached cosign sha256 mismatch: got {actual} expected {expected_sha}"
        )
    return dest
