"""Shared fixtures + helpers for the install.sh / uninstall.sh Lima harness.

The harness boots a fresh Lima VM per test, copies the locally-built
release tarball into it (sibling ``.sigstore`` bundle included), copies
the unmodified install.sh/uninstall.sh into it, and runs the install
path end-to-end. Each VM is torn down in the test's ``finally``; the
suite is intentionally serial.

The release tarball assembled by ``build-local-tarball.sh`` is signed
against the local Sigstore stack (see ``sigstore_stack`` fixture and
``tests/install-e2e/sigstore-stack/``). install.sh runs unmodified;
the SANDBOX_INSTALL_TEST_* env vars (set by ``install_sh_cmd`` when
passed a ``sigstore_stack`` handle) redirect cosign's trust material
at the local stack so the real cosign verify-blob path is exercised
end-to-end against a real signature. Operator-discoverable surface
(``--help``, ``installation.md``) is unchanged; the env vars are
deliberately undocumented test-only escape hatches.

The air-gapped test path (``test_install_air_gapped.py``) is the
single exception: it exercises install.sh's cosign-download +
SANDBOX_INSTALL_SKIP_SIGSTORE bypass path deliberately, so it stages
cosign by hand and sets the skip env var explicitly.
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

    Production-hostname injection: Lima's ``hostResolver.hosts`` map
    rewrites DNS lookups inside the VM to point production sigstore
    hostnames at ``host.lima.internal`` — which is the qemu user-net
    gateway address (typically 192.168.5.2) and reaches the host's
    127.0.0.1-bound Sigstore stack via Lima's port forwarding. The
    entries are inert when the local Sigstore stack isn't running:
    install.sh consults them only when the SANDBOX_INSTALL_TEST_*
    trust-material env vars are also set, which the harness wires up
    in lockstep with the stack-up signal.
    """
    cmd = [
        "limactl", "start",
        f"--name={vm_name}",
        f"template:{template}",
        f"--cpus={cpus}",
        f"--memory={memory_gib}",
        f"--disk={disk_gib}",
        "--set", ".mounts=[]",
        # Map production sigstore hostnames to host.lima.internal so a
        # cosign sign/verify inside the VM dialled against the
        # production hostname lands on the host-bound local stack. The
        # entries merge into the resolved Lima YAML's hostResolver.hosts
        # map; they are inert when the stack isn't reachable.
        # Multiple --set flags compose via yq.
        "--set",
        '.hostResolver.hosts."token.actions.githubusercontent.com" = "host.lima.internal"',
        "--set",
        '.hostResolver.hosts."fulcio.local" = "host.lima.internal"',
        "--set",
        '.hostResolver.hosts."rekor.local" = "host.lima.internal"',
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
# Release tarball fixture.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def release_tarball_x86_64(sigstore_stack) -> Path:
    """Build the local release tarball once per test session.

    Drives ``build-local-tarball.sh``; honors the script's
    SANDBOX_RELEASE_SKIP_BUILD / SKIP_GATEWAY env vars when set in the
    pytest invocation environment so iteration is fast.

    Depends on ``sigstore_stack``: the build script signs the
    tarball against the local Fulcio + Rekor stack so install.sh's
    real ``cosign verify-blob`` path can run end-to-end. If
    ``sigstore_stack`` skipped (no Docker on the host), the build
    script emits a zero-byte sigstore stub and downstream tests must
    rely on the ``SANDBOX_INSTALL_SKIP_SIGSTORE=1`` test-only escape.

    Cache shape:

    * Output: ``tests/install-e2e/dist/sandboxd-<ver>-<arch>.tar.gz``.
    * Skip rebuild when the cached tarball's mtime is newer than the
      youngest ``*.rs`` file in the workspace tree. Mirrors the bumped
      fixture's check (`release_tarball_x86_64_bumped` below) so a
      workspace ``.rs`` edit invalidates the cached tarball.
      ``SANDBOX_RELEASE_FORCE_REBUILD=1`` overrides.
    * Re-sign (without rebuilding binaries) when the cached
      ``.sigstore`` bundle is older than the live stack's rekor public
      key (``sigstore-stack/state/rekor.pub.cached.pem``). The local
      Rekor instance runs with ``--rekor_server.signer=memory``, so
      every container restart mints a fresh key. A bundle signed by a
      previous run encodes a logID derived from the now-defunct key;
      cosign verify-blob rejects it with ``rekor log public key not
      found for payload``. The fixture detects this by comparing
      mtimes — ``sigstore_stack`` writes the rekor pubkey cache file
      on every bring-up — and re-drives ``build-local-tarball.sh``
      with ``SANDBOX_RELEASE_SKIP_BUILD=1`` to re-stage + re-sign
      without paying the cargo cost.

    Without the mtime guard, an iteration cycle that edits Rust code and
    re-runs pytest would happily reuse a stale tarball whose binaries
    were built against the *pre-edit* tree — so tests would pass /
    fail against artifacts that no longer reflect HEAD. The
    ``test_release_tarball_x86_64_fixture_invalidates_on_rs_touch``
    pytest case below pins this contract.
    """
    if subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip() != "x86_64":
        pytest.skip("release_tarball_x86_64 fixture only assembles on x86_64 hosts")

    ver = _read_workspace_version()
    arch = "x86_64-unknown-linux-gnu"
    tarball = DIST_DIR / f"sandboxd-{ver}-{arch}.tar.gz"
    bundle = Path(f"{tarball}.sigstore")
    rekor_pub_cache = SIGSTORE_STACK_DIR / "state" / "rekor.pub.cached.pem"

    force_rebuild = os.environ.get("SANDBOX_RELEASE_FORCE_REBUILD") == "1"
    stale = (
        not tarball.exists()
        or tarball.stat().st_mtime < _newest_rs_mtime()
    )
    # Bundle is stale relative to the live rekor key when the
    # sigstore_stack fixture (which writes rekor_pub_cache on every
    # bring-up) wrote a newer file than the cached bundle. A non-empty
    # bundle is the canonical "tarball was signed against a previous
    # stack run" signal — a zero-byte stub is the stack-down fallback
    # and never triggers re-sign.
    bundle_stale = (
        bundle.exists()
        and bundle.stat().st_size > 0
        and rekor_pub_cache.exists()
        and bundle.stat().st_mtime < rekor_pub_cache.stat().st_mtime
    )

    if force_rebuild or stale:
        subprocess.run(
            [str(HERE / "build-local-tarball.sh")],
            check=True,
            timeout=1800,
        )
    elif bundle_stale:
        # Cargo + gateway artefacts are still fresh; only re-stage,
        # re-tar, and re-sign. Pays no cargo build cost.
        env = os.environ.copy()
        env["SANDBOX_RELEASE_SKIP_BUILD"] = "1"
        env["SANDBOX_RELEASE_SKIP_GATEWAY"] = "1"
        subprocess.run(
            [str(HERE / "build-local-tarball.sh")],
            check=True,
            timeout=600,
            env=env,
        )

    assert tarball.exists(), f"tarball not produced: {tarball}"
    return tarball


def _bump_patch_version(version: str) -> str:
    """Return ``version`` with its patch component incremented by one.

    The bump shape matches the convention documented in the release
    notes ("patch bump for an unreleased version"): ``X.Y.Z`` ->
    ``X.Y.(Z+1)``. Anything else (e.g. pre-release suffixes) raises —
    we want a loud refusal rather than a silently-wrong target version
    in the multi-version harness.
    """
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise AssertionError(
            f"unexpected version shape for bump: {version!r}; "
            "expected three numeric dot-separated components"
        )
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def _newest_rs_mtime() -> float:
    """Return the youngest mtime (in seconds since epoch) across every
    ``*.rs`` file under the workspace.

    Used by the bumped-tarball fixture's cache-validity check: a cached
    tarball whose mtime is older than the youngest source file is
    stale and must be rebuilt. Walks ``sandboxd/`` only (the workspace
    root), skipping the cargo target dir which contains build-time
    generated ``.rs`` files we don't want to invalidate against.
    """
    workspace = PROJECT_ROOT / "sandboxd"
    newest = 0.0
    for root, dirs, files in os.walk(workspace):
        # Skip target/, .git/, etc. — they contain generated or
        # unrelated files we don't want to invalidate against.
        dirs[:] = [d for d in dirs if d not in ("target", ".git", "node_modules")]
        for name in files:
            if name.endswith(".rs"):
                try:
                    mtime = os.path.getmtime(os.path.join(root, name))
                    if mtime > newest:
                        newest = mtime
                except OSError:
                    continue
    return newest


@pytest.fixture(scope="session")
def release_tarball_x86_64_bumped(release_tarball_x86_64, sigstore_stack) -> Path:
    """Build a release tarball at a bumped version distinct from the
    workspace's current CARGO_PKG_VERSION.

    The bump produces a genuine v' binary — every crate's Cargo.toml
    is sed-rewritten to the bumped version, ``cargo build --workspace
    --release`` runs against the rewrite, the tarball is assembled,
    and the Cargo.toml files are restored via an EXIT trap inside
    ``build-local-tarball.sh``. This is what
    ``test_update_fresh_install_to_next_version`` needs: a tarball
    whose binary's ``/version`` endpoint reports a different value
    than the base tarball's.

    Cache shape:

    * Output: ``tests/install-e2e/dist/sandboxd-<bumped>-<arch>.tar.gz``.
    * Skip rebuild when the cached tarball's mtime is newer than the
      youngest ``*.rs`` file in the workspace tree. This is the same
      shape as cargo's incremental cache, lifted up to the tarball
      level. ``SANDBOX_RELEASE_FORCE_REBUILD=1`` overrides.

    The bump version defaults to a patch-level bump (``X.Y.Z`` ->
    ``X.Y.(Z+1)``); set ``SANDBOX_RELEASE_BUMP_VERSION`` in the
    pytest invocation env to pick a different shape (the build
    script honours the same env var).

    Depends on ``release_tarball_x86_64`` so the base tarball is
    built first — the bumped build reuses the same docker cargo cache
    (under ``tests/install-e2e/.build-cache``) so the bumped rebuild
    is incremental on a warm cache. The two builds use distinct
    target dirs (``target/portable`` vs ``target/portable-bumped``)
    to keep their cargo fingerprints isolated across version-flips.
    """
    if subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip() != "x86_64":
        pytest.skip("release_tarball_x86_64_bumped fixture only assembles on x86_64 hosts")

    base_ver = _read_workspace_version()
    bumped_ver = os.environ.get("SANDBOX_RELEASE_BUMP_VERSION") \
        or _bump_patch_version(base_ver)
    if bumped_ver == base_ver:
        raise AssertionError(
            f"bumped version equals base version ({bumped_ver}); "
            "the multi-version harness requires distinct versions"
        )

    arch = "x86_64-unknown-linux-gnu"
    tarball = DIST_DIR / f"sandboxd-{bumped_ver}-{arch}.tar.gz"
    bundle = Path(f"{tarball}.sigstore")
    rekor_pub_cache = SIGSTORE_STACK_DIR / "state" / "rekor.pub.cached.pem"

    force_rebuild = os.environ.get("SANDBOX_RELEASE_FORCE_REBUILD") == "1"
    stale = (
        not tarball.exists()
        or tarball.stat().st_mtime < _newest_rs_mtime()
    )
    # Mirror release_tarball_x86_64's bundle-staleness check: the local
    # Rekor signer is memory-only, so every stack restart invalidates
    # any previously-written .sigstore bundle. Re-sign without rebuild
    # via SANDBOX_RELEASE_SKIP_BUILD=1.
    bundle_stale = (
        bundle.exists()
        and bundle.stat().st_size > 0
        and rekor_pub_cache.exists()
        and bundle.stat().st_mtime < rekor_pub_cache.stat().st_mtime
    )

    if force_rebuild or stale:
        env = os.environ.copy()
        env["SANDBOX_RELEASE_BUMP_VERSION"] = bumped_ver
        # The build script auto-detects the bumped build and reuses
        # the base tarball's gateway-image bytes (identical) rather
        # than re-running `make gateway-image`. The bumped cargo
        # build uses a separate target dir
        # (`sandboxd/target/portable-bumped/`) so the base build's
        # incremental cache is unaffected.
        subprocess.run(
            [str(HERE / "build-local-tarball.sh")],
            check=True,
            timeout=3600,  # first build is slow: every crate rebuilds
                            # because CARGO_PKG_VERSION env-var changes.
            env=env,
        )
    elif bundle_stale:
        env = os.environ.copy()
        env["SANDBOX_RELEASE_BUMP_VERSION"] = bumped_ver
        env["SANDBOX_RELEASE_SKIP_BUILD"] = "1"
        env["SANDBOX_RELEASE_SKIP_GATEWAY"] = "1"
        subprocess.run(
            [str(HERE / "build-local-tarball.sh")],
            check=True,
            timeout=600,
            env=env,
        )

    assert tarball.exists(), f"bumped tarball not produced: {tarball}"
    return tarball


@pytest.fixture(scope="session")
def release_tarball_x86_64_bumped_chain(release_tarball_x86_64, sigstore_stack) -> list:
    """Build a chain of N successively bumped release tarballs.

    ``test_update_backup_retention`` needs three real bumped binaries
    in sequence (v → v+1 → v+2 → v+3) to verify Spec 5 § 5.2's keep=2
    retention prune. The synthesised MANIFEST-only fake-bump path
    can't satisfy this: ``verify_version`` in the update flow queries
    the daemon's ``/version`` post-restart and aborts on mismatch.

    Each link in the chain is built independently by re-driving
    ``build-local-tarball.sh`` with ``SANDBOX_RELEASE_BUMP_VERSION``
    set to the chain step's version. The script's EXIT-trap restores
    the workspace Cargo.toml files between invocations, so each
    invocation starts from the committed source and sed-rewrites
    forward to its own target version.

    All bumped builds share ``sandboxd/target/portable-bumped/`` as
    their cargo target dir; this keeps the base build's target dir
    untouched. Successive bumped builds invalidate every crate's
    ``CARGO_PKG_VERSION`` fingerprint, so each link's compile is
    near-full — that is the cost of producing genuinely distinct
    binaries. The fixture is ``scope="session"``, so this happens
    once per pytest invocation.

    Cache shape per link: ``dist/sandboxd-<v>-<arch>.tar.gz``. A link
    is rebuilt only when its cached tarball is older than the
    youngest ``*.rs`` file in the workspace (same shape as the
    single bumped fixture). ``SANDBOX_RELEASE_FORCE_REBUILD=1``
    forces every link to rebuild.

    Returns: list of pathlib.Path entries, ordered (oldest → newest).
    Length defaults to 3; override with ``SANDBOX_RELEASE_BUMP_CHAIN_LEN``.
    """
    if subprocess.run(["uname", "-m"], capture_output=True, text=True).stdout.strip() != "x86_64":
        pytest.skip("release_tarball_x86_64_bumped_chain fixture only assembles on x86_64 hosts")

    base_ver = _read_workspace_version()
    chain_len = int(os.environ.get("SANDBOX_RELEASE_BUMP_CHAIN_LEN", "3"))
    if chain_len < 1:
        raise AssertionError(
            f"SANDBOX_RELEASE_BUMP_CHAIN_LEN must be >= 1, got {chain_len}"
        )

    # Generate the chain versions by repeatedly bumping the patch
    # component. Same shape as the single bumped fixture: X.Y.Z ->
    # X.Y.(Z+1) -> X.Y.(Z+2) -> ...
    chain_versions = []
    cur = base_ver
    for _ in range(chain_len):
        cur = _bump_patch_version(cur)
        chain_versions.append(cur)

    arch = "x86_64-unknown-linux-gnu"
    chain_tarballs = []
    force_rebuild = os.environ.get("SANDBOX_RELEASE_FORCE_REBUILD") == "1"
    newest_rs = _newest_rs_mtime()
    rekor_pub_cache = SIGSTORE_STACK_DIR / "state" / "rekor.pub.cached.pem"

    for ver in chain_versions:
        tarball = DIST_DIR / f"sandboxd-{ver}-{arch}.tar.gz"
        bundle = Path(f"{tarball}.sigstore")
        stale = not tarball.exists() or tarball.stat().st_mtime < newest_rs
        bundle_stale = (
            bundle.exists()
            and bundle.stat().st_size > 0
            and rekor_pub_cache.exists()
            and bundle.stat().st_mtime < rekor_pub_cache.stat().st_mtime
        )

        if force_rebuild or stale:
            env = os.environ.copy()
            env["SANDBOX_RELEASE_BUMP_VERSION"] = ver
            subprocess.run(
                [str(HERE / "build-local-tarball.sh")],
                check=True,
                timeout=3600,
                env=env,
            )
        elif bundle_stale:
            env = os.environ.copy()
            env["SANDBOX_RELEASE_BUMP_VERSION"] = ver
            env["SANDBOX_RELEASE_SKIP_BUILD"] = "1"
            env["SANDBOX_RELEASE_SKIP_GATEWAY"] = "1"
            subprocess.run(
                [str(HERE / "build-local-tarball.sh")],
                check=True,
                timeout=600,
                env=env,
            )

        assert tarball.exists(), f"chain link not produced: {tarball}"
        chain_tarballs.append(tarball)

    return chain_tarballs


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

    def _factory(template, *, install_prereqs=True, install_scripts=True):
        name = lima_vm_name()
        lima_start(name, template)
        vm = VM(name=name, distro=template)
        created.append(vm)

        if install_prereqs:
            _install_prereqs(vm)

        if install_scripts:
            _stage_scripts(vm)

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


def _stage_scripts(vm):
    """Copy install.sh + uninstall.sh into /tmp inside the VM.

    install.sh is staged unmodified — the harness no longer patches
    cosign_bootstrap or sigstore_verify. The real cosign verify-blob
    path runs against the local Sigstore stack via the
    SANDBOX_INSTALL_TEST_* env vars that ``install_sh_cmd`` injects.
    """
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


SIGSTORE_TRUST_MATERIAL_VM_DIR = "/tmp/sandboxd-sigstore-trust"


def stage_sigstore_trust_material_in_vm(vm, stack):
    """Copy the local Sigstore stack's trust material into the VM.

    Plants four files under
    ``/tmp/sandboxd-sigstore-trust/`` inside the guest:

      fulcio-root.pem     Fulcio CA root used by --certificate-chain.
      rekor.pub.pem       Rekor server public key (transparency log).
      ct-log.pub.pem      CT log public key (used at sign time, and
                          referenced during verify-blob when the
                          signing-time SCT is embedded in the cert).

    Returns a dict of env-var values pointing at the in-VM paths,
    suitable for splatting into ``install_sh_cmd(..., env={...})``.
    The URLs (Fulcio, Rekor) are rewritten to ``host.lima.internal``
    so the cosign client inside the VM reaches the host-bound stack
    via Lima's qemu user-net gateway.
    """
    vm.shell(f"mkdir -p {SIGSTORE_TRUST_MATERIAL_VM_DIR}", check=True, timeout=10)

    in_vm_fulcio = f"{SIGSTORE_TRUST_MATERIAL_VM_DIR}/fulcio-root.pem"
    in_vm_rekor = f"{SIGSTORE_TRUST_MATERIAL_VM_DIR}/rekor.pub.pem"
    in_vm_ctlog = f"{SIGSTORE_TRUST_MATERIAL_VM_DIR}/ct-log.pub.pem"

    vm.cp(stack.fulcio_root_path, in_vm_fulcio)
    vm.cp(stack.rekor_public_key_path, in_vm_rekor)
    vm.cp(stack.ct_log_public_key_path, in_vm_ctlog)

    # Rewrite localhost-bound URLs to the Lima host-gateway name. The
    # `host.lima.internal` hostname is predefined by Lima's
    # hostResolver and points at the qemu user-net gateway IP, which
    # reaches the host's 127.0.0.1-bound Docker port mappings.
    fulcio_url = stack.fulcio_url.replace("127.0.0.1", "host.lima.internal")
    rekor_url = stack.rekor_url.replace("127.0.0.1", "host.lima.internal")

    return {
        "SANDBOX_INSTALL_TEST_FULCIO_ROOT": in_vm_fulcio,
        "SANDBOX_INSTALL_TEST_REKOR_URL": rekor_url,
        "SANDBOX_INSTALL_TEST_REKOR_PUBLIC_KEY": in_vm_rekor,
        "SANDBOX_INSTALL_TEST_CT_LOG_PUBLIC_KEY": in_vm_ctlog,
        # Echoed for fixtures that want to invoke sandbox-cli's update
        # path against the local stack (SANDBOX_UPDATE_TEST_* mirrors
        # the install-side prefix; see sandboxd/sandbox-cli/src/update/
        # fetch.rs::verify_signature).
        "SANDBOX_UPDATE_TEST_FULCIO_ROOT": in_vm_fulcio,
        "SANDBOX_UPDATE_TEST_REKOR_URL": rekor_url,
        "SANDBOX_UPDATE_TEST_REKOR_PUBLIC_KEY": in_vm_rekor,
        "SANDBOX_UPDATE_TEST_CT_LOG_PUBLIC_KEY": in_vm_ctlog,
        # Side-band: the fulcio URL isn't consumed by verify-blob, but
        # surfacing it lets tests that want to sign inside the VM (e.g.
        # a future per-VM signing fixture) dial it. Currently unused
        # by sigstore_verify.
        "SANDBOX_INSTALL_TEST_FULCIO_URL": fulcio_url,
        # Test-only diagnostic toggle (install.sh::sigstore_verify):
        # route cosign verify-blob's stdout+stderr to
        # /tmp/sandbox-install-cosign-debug.log so the test harness
        # can recover the real cosign error after a failure. Without
        # this, production's `>/dev/null 2>&1` suppression makes
        # triage impossible. MUST NEVER BE SET IN PRODUCTION.
        "SANDBOX_INSTALL_TEST_DEBUG_COSIGN_STDERR": "1",
    }


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


def install_sh_cmd(tarball_in_vm, *extra_flags, env=None,
                   vm=None, sigstore_stack=None):
    """Build the canonical install.sh invocation used by every test.

    Always passes ``--from``, ``--version``, ``--yes``, ``--no-color``
    so test output is parser-friendly and idempotency assertions land
    on a known version string. Additional flags (e.g. ``--cosign-bundle``)
    can be appended.

    ``env`` is an optional dict of environment variables exported to
    the install.sh process (via ``sudo VAR=val ...``). Used by the
    air-gapped test to set ``SANDBOX_INSTALL_SKIP_SIGSTORE=1`` (test-
    only bypass; see install.sh::sigstore_verify).

    ``vm`` + ``sigstore_stack``: when both are passed, the local
    Sigstore stack's trust material is staged inside the VM and the
    resulting SANDBOX_INSTALL_TEST_* env vars are merged into ``env``
    (without overriding caller-supplied values). This is the canonical
    plumbing for "run install.sh against a locally-signed tarball" —
    every happy-path test using the session-scope ``release_tarball_*``
    fixtures takes this branch. Mutates the VM (limactl copy) as a
    side effect; sequential tests don't observe one another.
    """
    ver = version_from_tarball(tarball_in_vm)
    merged_env = {}
    if vm is not None and sigstore_stack is not None:
        merged_env.update(stage_sigstore_trust_material_in_vm(vm, sigstore_stack))
    if env:
        merged_env.update(env)
    env_prefix = ""
    if merged_env:
        # `sudo VAR=val ...` preserves the env var into the script's
        # process; `sudo -E` would pull the entire current env in, which
        # we deliberately avoid to keep the test's contract narrow.
        env_prefix = " ".join(f"{k}={_sh_quote(v)}" for k, v in merged_env.items()) + " "
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
        "test -x /usr/local/libexec/sandboxd/sandbox-guest"
    ).returncode == 0, (
        "sandbox-guest missing or not executable — daemon startup "
        "staging will fail to read it; see install.sh::install_binaries"
    )
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


# ---------------------------------------------------------------------------
# Local Sigstore stack — session-scope fixture.
# ---------------------------------------------------------------------------
#
# The seven-container stack under ``tests/install-e2e/sigstore-stack/``
# stands in for the production Fulcio + Rekor + CT-log trio so install.sh
# (and ``sandbox update``) can exercise the real cosign verify-blob path
# against locally-signed tarballs. See the README.md alongside
# ``docker-compose.yml`` for operator notes; the architectural
# rationale (DNS interception, TLS CA injection, JWT minting strategy)
# is recorded in the stack's bring-up handoff in ``.tasks/handoffs/``.

SIGSTORE_STACK_DIR = HERE / "sigstore-stack"


@dataclass(frozen=True)
class SigstoreStackHandle:
    """Handle on the running Sigstore stack returned by ``sigstore_stack``.

    All paths reference files on the *host* (the stack runs on the host
    via ``docker compose``). Tests that need these inside a Lima VM are
    responsible for copying the files in via ``vm.cp``; the typical
    pattern is ``copy_signed_tarball_to_vm`` (defined below), which also
    plants the sibling ``.sigstore`` bundle.

    The URLs (``fulcio_url``, ``rekor_url``, ``oidc_url``) are
    host-side bindings on ``127.0.0.1``; install.sh running inside a
    Lima VM reaches them as ``host.lima.internal:PORT`` after the
    ``hostResolver.hosts`` injection performed at VM start time.
    """

    fulcio_url: str
    rekor_url: str
    oidc_url: str
    fulcio_root_path: Path
    rekor_public_key_path: Path
    ct_log_public_key_path: Path
    oidc_signing_key_path: Path
    mint_token_script: Path


def _docker_compose_available() -> bool:
    if not shutil.which("docker"):
        return False
    rc = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, text=True,
    )
    return rc.returncode == 0


def _sigstore_compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=SIGSTORE_STACK_DIR,
        check=check,
        capture_output=True,
        text=True,
    )


def _wait_http_200(url: str, deadline_seconds: float) -> None:
    """Poll *url* until it returns HTTP 200. Best-effort retry on any error."""
    import urllib.request
    deadline = time.monotonic() + deadline_seconds
    last_err = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as e:  # noqa: BLE001 — best-effort retry
            last_err = e
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {url}: {last_err}")


@pytest.fixture(scope="session")
def sigstore_stack():
    """Bring up the local Sigstore stack once per pytest session.

    Skips the whole session if docker compose is unavailable; tests
    that depend on the fixture will be skipped, which is the right
    behaviour on hosts without Docker (smoke test included).

    The stack runs on the host (127.0.0.1:5555 Fulcio, :3000 Rekor,
    :8443 OIDC discovery). Tests running install.sh inside a Lima VM
    reach the stack via ``host.lima.internal:PORT`` after the VM
    factory injects the ``hostResolver.hosts`` entries (see
    ``lima_start``); tests running cosign on the host (the smoke test)
    use ``127.0.0.1`` directly.
    """
    if not _docker_compose_available():
        pytest.skip("docker compose not available; sigstore_stack unusable")

    # Idempotent state generation.
    init_rc = subprocess.run(
        [str(SIGSTORE_STACK_DIR / "init.sh")],
        capture_output=True, text=True,
    )
    if init_rc.returncode != 0:
        raise RuntimeError(
            f"sigstore-stack init.sh failed: rc={init_rc.returncode}\n"
            f"stdout:\n{init_rc.stdout}\nstderr:\n{init_rc.stderr}"
        )

    bringup = _sigstore_compose("up", "-d", check=False)
    if bringup.returncode != 0:
        # Surface the failure with teardown noise so the operator sees
        # both the bring-up error AND the cleanup result.
        teardown = _sigstore_compose("down", "-v", check=False)
        raise RuntimeError(
            f"docker compose up failed: rc={bringup.returncode}\n"
            f"stdout:\n{bringup.stdout}\nstderr:\n{bringup.stderr}\n"
            f"teardown stdout:\n{teardown.stdout}\n"
            f"teardown stderr:\n{teardown.stderr}"
        )

    try:
        # Fulcio's /healthz blocks until its downstream deps (CT log
        # included) are reachable, so we don't need a separate
        # tesseract probe.
        _wait_http_200("http://127.0.0.1:5555/healthz", deadline_seconds=120.0)
        # Rekor's /ping returns 200 once Trillian is initialised.
        _wait_http_200("http://127.0.0.1:3000/ping", deadline_seconds=60.0)

        # Cache the Rekor public key on disk so install.sh inside the
        # VM (which gets the file copied in) can point at a path rather
        # than re-fetching at install time.
        rekor_pub_path = SIGSTORE_STACK_DIR / "state" / "rekor.pub.cached.pem"
        import urllib.request
        with urllib.request.urlopen(
            "http://127.0.0.1:3000/api/v1/log/publicKey", timeout=5,
        ) as resp:
            rekor_pub_path.write_bytes(resp.read())

        yield SigstoreStackHandle(
            fulcio_url="http://127.0.0.1:5555",
            rekor_url="http://127.0.0.1:3000",
            oidc_url="https://127.0.0.1:8443",
            fulcio_root_path=SIGSTORE_STACK_DIR / "state" / "fulcio-root" / "root.pem",
            rekor_public_key_path=rekor_pub_path,
            ct_log_public_key_path=SIGSTORE_STACK_DIR / "state" / "ct-log" / "pubkey.pem",
            oidc_signing_key_path=SIGSTORE_STACK_DIR / "state" / "oidc" / "signing.key.pem",
            mint_token_script=SIGSTORE_STACK_DIR / "mint_token.py",
        )
    finally:
        _sigstore_compose("down", "-v", check=False)


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


# ---------------------------------------------------------------------------
# Multi-uid peercred test harness (Spec 2 § 9.2, Spec 1 § 8.4).
# ---------------------------------------------------------------------------
#
# The peercred-connector helper lives at
# ``sandboxd/tests/helpers/peercred-connector`` as a deliberately
# standalone Cargo crate (NOT a workspace member, see the crate's
# Cargo.toml). The release tarball never ships it; the host-side
# fixture builds it on demand and copies it into the Lima VM
# alongside the install tarball, where the in-VM provisioning step
# installs it setuid-root at ``/usr/local/lib/sandboxd-tests/``.
#
# Why setuid-root: ``SO_PEERCRED`` is kernel-set on ``connect(2)``;
# faking the peer uid requires real privilege separation. The helper
# drops to a caller-specified numeric uid (``setresuid``/``setresgid``)
# before opening the daemon socket, so the daemon's per-connection
# acceptor reads the dropped uid through the kernel.

PEERCRED_CONNECTOR_CRATE_DIR = (
    PROJECT_ROOT / "sandboxd" / "tests" / "helpers" / "peercred-connector"
)
PEERCRED_CONNECTOR_BINARY = (
    PEERCRED_CONNECTOR_CRATE_DIR / "target" / "release" / "peercred-connector"
)
PEERCRED_CONNECTOR_VM_PATH = "/usr/local/lib/sandboxd-tests/peercred-connector"


@pytest.fixture(scope="session")
def peercred_connector_binary() -> Path:
    """Build ``peercred-connector`` once per session, return its host path.

    The crate is standalone (no workspace membership) so a host-side
    ``cargo build --release`` from its own directory produces the
    binary at ``target/release/peercred-connector`` without invalidating
    the workspace cargo cache. The binary is rebuilt only when stale
    relative to the crate's own source files.

    Cache shape mirrors the release-tarball fixture: a stamp file in
    the crate's ``target/`` records the source-mtime; we recompile only
    when any ``src/*.rs`` is newer than the existing binary. Set
    ``SANDBOX_PEERCRED_CONNECTOR_FORCE_REBUILD=1`` to override.

    The host build is x86_64 → x86_64 (release tarball is x86_64-only
    today, so the Lima E2E VMs are x86_64). Cross-host is left to a
    follow-up if the matrix ever widens.
    """
    if subprocess.run(
        ["uname", "-m"], capture_output=True, text=True
    ).stdout.strip() != "x86_64":
        pytest.skip(
            "peercred_connector_binary fixture only builds on x86_64 hosts"
        )

    force_rebuild = (
        os.environ.get("SANDBOX_PEERCRED_CONNECTOR_FORCE_REBUILD") == "1"
    )
    stale = (
        force_rebuild
        or not PEERCRED_CONNECTOR_BINARY.exists()
        or PEERCRED_CONNECTOR_BINARY.stat().st_mtime
        < _newest_helper_src_mtime()
    )

    if stale:
        subprocess.run(
            ["cargo", "build", "--release"],
            cwd=PEERCRED_CONNECTOR_CRATE_DIR,
            check=True,
            timeout=600,
        )

    if not PEERCRED_CONNECTOR_BINARY.exists():
        raise AssertionError(
            f"peercred-connector did not build at {PEERCRED_CONNECTOR_BINARY}"
        )
    return PEERCRED_CONNECTOR_BINARY


def _newest_helper_src_mtime() -> float:
    """Return youngest mtime across the peercred-connector crate sources.

    Walks ``src/`` and ``Cargo.toml``; skips ``target/``. Same shape as
    ``_newest_rs_mtime`` but scoped to a single helper crate.
    """
    newest = 0.0
    candidates = [
        PEERCRED_CONNECTOR_CRATE_DIR / "Cargo.toml",
        PEERCRED_CONNECTOR_CRATE_DIR / "Cargo.lock",
    ]
    for c in candidates:
        if c.exists():
            try:
                m = c.stat().st_mtime
                if m > newest:
                    newest = m
            except OSError:
                pass
    src = PEERCRED_CONNECTOR_CRATE_DIR / "src"
    if src.exists():
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d not in ("target", ".git")]
            for name in files:
                if name.endswith(".rs"):
                    try:
                        m = os.path.getmtime(os.path.join(root, name))
                        if m > newest:
                            newest = m
                    except OSError:
                        continue
    return newest


def provision_peercred_connector_in_vm(vm, host_binary):
    """Copy ``peercred-connector`` into the VM and install it setuid-root.

    Mirrors Spec 2 § 9.2's provisioning recipe:

    ```
    install -o root -g root -m 4755 <built-binary> \
        /usr/local/lib/sandboxd-tests/peercred-connector
    ```

    The 4755 mode is **required** for the helper's privilege drop to
    actually take effect — ``setresuid`` from a non-root process whose
    euid is not 0 is a no-op, and the helper detects that case
    (``Error::PrivDropFailed``) by re-reading ``geteuid()`` after the
    call. Without setuid-root, every multi-uid test would fail loudly
    at the helper's drop-verification step.
    """
    vm.cp(host_binary, "/tmp/peercred-connector")
    vm.shell(
        "sudo install -d -m 0755 -o root -g root /usr/local/lib/sandboxd-tests",
        check=True,
    )
    vm.shell(
        "sudo install -o root -g root -m 4755 /tmp/peercred-connector "
        f"{PEERCRED_CONNECTOR_VM_PATH}",
        check=True,
    )
    # Verify the setuid bit took — ``install -m 4755`` is supposed to
    # apply 04755, but some fs mount options (nosuid) silently strip
    # the setuid bit, which would make the helper's privilege drop
    # mis-fire later in mysterious ways. Cross-check the resulting
    # mode and fail loudly here instead.
    r = vm.shell(
        f"stat -c '%a' {PEERCRED_CONNECTOR_VM_PATH}",
        check=True,
    )
    mode = r.stdout.strip()
    if mode != "4755":
        raise AssertionError(
            f"peercred-connector setuid bit not preserved: mode={mode!r} "
            f"(filesystem may be mounted nosuid; cannot exercise multi-uid "
            f"peercred tests on this VM)"
        )


# ---------------------------------------------------------------------------
# Multi-operator user provisioning inside the test VM.
# ---------------------------------------------------------------------------
#
# Three test identities live alongside the install-created ``sandbox``
# daemon user:
#
# - ``alice`` (uid 4001) — primary test operator, owns sessions
# - ``bob`` (uid 4002)   — second operator, attempts cross-user reads
# - uid 7777             — synthetic uid with NO ``/etc/passwd`` entry,
#                          used by tests that pin the unresolvable-uid
#                          deny/close behavior (Spec 1 § 8.4 #148 and
#                          Spec 2 § 4.1 / 7.5 #150)
#
# alice and bob both join the ``sandbox`` group so they can traverse
# the socket's 0660 sandbox:sandbox parent dir / socket node. The
# install harness's pre-existing ``lima`` user is also in that group
# (install.sh's ``add_operator_to_group`` does this when run under
# sudo); we don't reuse ``lima`` because Spec 2 § 7.5 wants two real
# operator uids distinct from any administrative role.
#
# uid 7777 is created with ``useradd`` and immediately ``userdel``-ed
# so the uid number remains stranded in the kernel uid space without
# a passwd entry — exactly the "uid without passwd lookup result"
# state the deny/close tests exercise. The ``userdel`` step is what
# decouples the uid number from the name; this is the same shape Spec
# 1 § 8.4 specifies for the route-helper test.

TEST_UID_ALICE = 4001
TEST_UID_BOB = 4002
# Synthetic uid with no /etc/passwd entry. Chosen well above the
# system-uid (<1000) and below the dynamic-uid (>65000) ranges; not in
# /etc/passwd on any stock Lima distro template.
TEST_UID_NOPASSWD = 7777


def provision_test_operators_in_vm(vm):
    """Create alice and bob inside the VM and join them to ``sandbox`` group.

    Idempotent: re-running against a VM that already has the users is
    a no-op (the ``id -u alice`` short-circuit avoids a duplicate
    ``useradd``).

    Pre-condition: the ``sandbox`` group must already exist (install.sh
    creates it via ``useradd --system --user-group sandbox``); callers
    invoke this fixture after install.
    """
    cmd = (
        "set -eux; "
        f"if ! id -u alice >/dev/null 2>&1; then "
        f"  sudo useradd --uid {TEST_UID_ALICE} --create-home --shell /bin/sh alice; "
        "fi; "
        f"if ! id -u bob >/dev/null 2>&1; then "
        f"  sudo useradd --uid {TEST_UID_BOB} --create-home --shell /bin/sh bob; "
        "fi; "
        "sudo usermod -aG sandbox alice; "
        "sudo usermod -aG sandbox bob; "
    )
    vm.shell(cmd, check=True, timeout=60)


def install_multi_operator_users_conf(vm):
    """Rewrite /etc/sandboxd/users.conf to include alice and bob.

    Replaces the install-default ``allow_users: ["sandbox", "lima"]``
    with ``["sandbox", "alice", "bob"]`` so the daemon's startup
    subnet-resolution finds the same row regardless of which test
    operator we run as later. Callers must restart sandboxd after
    invoking this — the daemon reads users.conf once at startup.
    """
    users_conf = (
        '{\n'
        '  "_schema_version": 1,\n'
        '  "subnets": [\n'
        '    {\n'
        '      "comment": "Test pool — multi-uid peercred isolation suite.",\n'
        '      "cidr": "10.209.0.0/20",\n'
        '      "allow_users": ["sandbox", "alice", "bob"]\n'
        '    }\n'
        '  ]\n'
        '}\n'
    )
    # Stage via /tmp then sudo-install so we don't depend on the test
    # runner having root-writable /etc.
    vm.shell(
        "cat > /tmp/users.conf <<'EOF'\n" + users_conf + "EOF",
        check=True,
    )
    vm.shell(
        "sudo install -m 0644 -o root -g root /tmp/users.conf "
        "/etc/sandboxd/users.conf",
        check=True,
    )


def restart_sandboxd(vm, *, timeout=60):
    """Restart sandboxd and wait for the socket to reappear.

    Convenience wrapper around ``systemctl restart`` +
    ``wait_for_systemd_active`` + ``wait_for_socket``.
    """
    vm.shell("sudo systemctl restart sandboxd", check=True, timeout=timeout)
    wait_for_systemd_active(vm.name, "sandboxd", timeout=timeout)
    wait_for_socket(vm.name, "/run/sandbox/sandboxd.sock", timeout=timeout)


def vm_invoking_user(vm):
    """Return the in-VM username that ``limactl shell`` lands as.

    Lima maps the host invoking user (`$USER` on the host) onto an
    in-VM account; the name is host-dependent (`lima` on Lima's stock
    bootstrap, but matches `$USER` once the host's user differs from
    the template's default `lima` user). This helper captures the name
    by running an unwrapped ``whoami`` inside the VM through
    ``limactl shell`` (i.e. NOT under ``sudo -u <name>``), which is
    exactly the user identity that install.sh's ``add_operator_to_group``
    joined to the ``sandbox`` group at install time.

    Tests that need to invoke a setuid-root helper from a uid which is
    a member of ``sandbox`` (so the kernel-side socket-traversal check
    on the 0660 socket succeeds before ``setresuid`` drops to the
    target uid) should use this name rather than a hardcoded ``lima``.
    """
    r = vm.shell("whoami", check=True, timeout=10)
    name = r.stdout.strip()
    if not name:
        raise AssertionError(
            f"vm_invoking_user: `whoami` returned empty output "
            f"(stdout={r.stdout!r}, stderr={r.stderr!r})"
        )
    return name


# ---------------------------------------------------------------------------
# Route-helper audit-log scraping (Spec 1 § 3.5).
# ---------------------------------------------------------------------------

def read_route_helper_audit_log(vm, audit_log_path):
    """Cat the audit log out of the VM and parse JSON-Lines records.

    Returns a list of dicts (one per record). Empty list if the file
    does not exist (the helper writes to the resolved path on demand;
    an absent file means no record was ever appended). Per Spec 1
    § 3.5 every invocation writes exactly one record.

    The audit-log path inside the VM depends on the helper's
    ``audit_log_path()`` resolution: usually
    ``$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log`` for the
    daemon-driven path, but tests that invoke the helper directly
    pin the path via ``XDG_RUNTIME_DIR`` in the invocation
    environment so they can read a known location.
    """
    r = vm.shell(
        f"sudo cat {audit_log_path} 2>/dev/null || true",
        timeout=10,
    )
    records = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records
