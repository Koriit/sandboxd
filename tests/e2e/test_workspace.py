"""E2E tests for M5 workspace features: git clone mode, boot command,
file copy (sandbox cp), and directory sync (sandbox sync) between host
and VM.

These tests boot real Lima/QEMU VMs and are SLOW (3-10 minutes per test).
Run with generous timeouts:

    cd tests/e2e
    source .venv/bin/activate
    python -m pytest test_workspace.py -v --timeout=600

Backend coverage: **agnostic** — parametrized over ``[lima, container]``
via the ``backend`` fixture. ``--repo``, ``sandbox cp``, and
``--workspace shared:`` are spec-required behaviours on both backends
(spec § "Workspace" lines ~570-595); ``test_lite.py`` already covers
``--workspace shared:`` for the container backend, and this
parametrization extends the rest to the matrix.
"""

from __future__ import annotations

import os
import stat
import tempfile

import pytest

from conftest import (
    cleanup_policy_file,
    make_create_args,
    parse_session_id,
    wait_for_state,
    write_policy_file,
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(600)
def test_clone_repo(sandbox_cli, backend):
    """Create a session with --repo pointing to a small public repo.
    Verify the repository is cloned into /home/agent/workspace/.

    Backend-agnostic: both backends advertise
    `WorkspaceModeKind::Clone` and the daemon dispatches `git clone`
    in-guest via `GuestConnector` after the runtime starts.
    """
    session_id = None
    policy_path = None
    try:
        # We need a policy that allows github.com for the git clone to work.
        # Policy v2 schema: rule identity is (host, port); protocol is L4.
        # `git clone https://…` over HTTPS → (github.com, 443, tcp).
        policy = {
            "version": "2.0.0",
            "rules": [
                {
                    "host": "github.com",
                    "port": 443,
                    "protocol": "tcp",
                    "level": "transport",
                },
            ],
        }
        policy_path = write_policy_file(policy)

        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-clone",
                "--policy", policy_path,
                "--repo", "https://github.com/octocat/Hello-World.git",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-clone", "Running", timeout=10)

        # Verify /home/agent/workspace/ exists and has expected content.
        ls_result = sandbox_cli(
            "exec", "ws-clone", "--", "ls", "/home/agent/workspace/",
            timeout=120,
        )
        assert ls_result.returncode == 0, (
            f"ls /home/agent/workspace/ failed.\n"
            f"stdout: {ls_result.stdout}\nstderr: {ls_result.stderr}"
        )
        # The Hello-World repo should have a README file.
        assert "README" in ls_result.stdout, (
            f"Expected README in /home/agent/workspace/, got:\n{ls_result.stdout}"
        )

        # Verify it's a git repo.
        git_result = sandbox_cli(
            "exec", "ws-clone", "--",
            "git", "-C", "/home/agent/workspace/", "log", "--oneline", "-1",
            timeout=120,
        )
        assert git_result.returncode == 0, (
            f"git log failed in /home/agent/workspace/.\n"
            f"stdout: {git_result.stdout}\nstderr: {git_result.stderr}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-clone", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-clone", timeout=120)
        if policy_path is not None:
            cleanup_policy_file(policy_path)


@pytest.mark.timeout(600)
def test_cp_host_to_vm(sandbox_cli, backend):
    """Create a session, create a temp file locally, use `sandbox cp` to
    upload it into the VM, then verify contents via `sandbox exec`.
    """
    session_id = None
    local_file = None
    try:
        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-cp-up"),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-cp-up", "Running", timeout=10)

        # Create a local temp file with known content.
        fd, local_file = tempfile.mkstemp(prefix="sandbox-cp-test-", suffix=".txt")
        test_content = "hello from sandbox cp test\nline two\n"
        os.write(fd, test_content.encode())
        os.close(fd)

        # Upload the file into the VM.
        cp_result = sandbox_cli(
            "cp", local_file, "ws-cp-up:/home/agent/uploaded.txt",
            timeout=120,
        )
        assert cp_result.returncode == 0, (
            f"sandbox cp upload failed (rc={cp_result.returncode}).\n"
            f"stdout: {cp_result.stdout}\nstderr: {cp_result.stderr}"
        )

        # Verify the file contents in the VM.
        cat_result = sandbox_cli(
            "exec", "ws-cp-up", "--", "cat", "/home/agent/uploaded.txt",
            timeout=120,
        )
        assert cat_result.returncode == 0, (
            f"cat failed in VM.\n"
            f"stdout: {cat_result.stdout}\nstderr: {cat_result.stderr}"
        )
        assert cat_result.stdout == test_content, (
            f"File contents mismatch.\n"
            f"Expected: {test_content!r}\nGot: {cat_result.stdout!r}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-cp-up", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-cp-up", timeout=120)
        if local_file is not None:
            try:
                os.unlink(local_file)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_cp_vm_to_host(sandbox_cli, backend):
    """Create a session, create a file in the VM via `sandbox exec`, then
    use `sandbox cp` to download it to the host and verify contents.
    """
    session_id = None
    local_file = None
    try:
        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-cp-down"),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-cp-down", "Running", timeout=10)

        # Create a file inside the VM.
        test_content = "content created inside VM for download test"
        exec_result = sandbox_cli(
            "exec", "ws-cp-down", "--",
            "bash", "-c", f"echo -n '{test_content}' > /home/agent/vm-file.txt",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"Failed to create file in VM.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )

        # Download the file from the VM.
        fd, local_file = tempfile.mkstemp(prefix="sandbox-cp-down-", suffix=".txt")
        os.close(fd)

        cp_result = sandbox_cli(
            "cp", "ws-cp-down:/home/agent/vm-file.txt", local_file,
            timeout=120,
        )
        assert cp_result.returncode == 0, (
            f"sandbox cp download failed (rc={cp_result.returncode}).\n"
            f"stdout: {cp_result.stdout}\nstderr: {cp_result.stderr}"
        )

        # Verify the downloaded content.
        with open(local_file) as f:
            downloaded_content = f.read()
        assert downloaded_content == test_content, (
            f"Downloaded content mismatch.\n"
            f"Expected: {test_content!r}\nGot: {downloaded_content!r}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-cp-down", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-cp-down", timeout=120)
        if local_file is not None:
            try:
                os.unlink(local_file)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_cp_native_attributes(sandbox_cli, backend):
    """Round-trip a 10 MB sparse file with mode 0700 across both backends
    and verify size + mode are preserved end-to-end.

    Validates that the M12-S7 native-cp dispatch (`limactl cp` /
    `docker cp`) preserves file attributes the prior base64-pump
    implementation never did. The pre-M12-S7 path lost mode (the CLI
    never set it on `FileUploadRequest`) and inflated sparse files
    (base64 + decode forces every hole into a real byte). The native
    tools handle both: `scp` (under `limactl cp`) preserves mode and
    sparseness with `-p`/`-S`; `docker cp` preserves mode by default
    and copies sparse-aware via tar streaming.

    Sparseness is asserted via the *apparent* vs *allocated* size
    relationship: a true sparse file has `du --apparent-size` = 10 MB
    but `du` (allocated) ≪ 10 MB. We tolerate some inflation up to 1 MB
    to leave headroom for filesystem-block rounding without admitting
    a full inflation regression.

    Path layout:
      host  /tmp/<tmpdir>/sparse.bin   (apparent 10 MB, mode 0700)
      VM    /home/agent/sparse-uploaded.bin
      host  /tmp/<tmpdir>/sparse-roundtripped.bin

    Backend coverage: parametrised over [lima, container] like the
    other M5 cp tests.
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-cp-attr-")
        original = os.path.join(host_dir, "sparse.bin")
        roundtrip = os.path.join(host_dir, "sparse-roundtripped.bin")

        # Create a 10 MB sparse file on the host: open, seek to 10 MB - 1,
        # write a single byte, close. This is the canonical sparse-file
        # pattern; `du --apparent-size` reports 10 MB while `du` reports
        # only the allocated blocks (typically 4-8 KB).
        with open(original, "wb") as f:
            f.seek(10 * 1024 * 1024 - 1)
            f.write(b"\0")
        os.chmod(original, 0o700)

        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-cp-attr"),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-cp-attr", "Running", timeout=10)

        # Upload via `sandbox cp`. The native tool (limactl cp / docker
        # cp) is what actually crosses the host/VM boundary.
        cp_up = sandbox_cli(
            "cp", original, "ws-cp-attr:/home/agent/sparse-uploaded.bin",
            timeout=180,
        )
        assert cp_up.returncode == 0, (
            f"sandbox cp upload failed (rc={cp_up.returncode}).\n"
            f"stdout: {cp_up.stdout}\nstderr: {cp_up.stderr}"
        )

        # In-VM mode check: stat -c %a returns the file mode in octal.
        # Mode 0700 must round-trip — the pre-M12-S7 path lost it.
        mode_in_vm = sandbox_cli(
            "exec", "ws-cp-attr", "--",
            "stat", "-c", "%a", "/home/agent/sparse-uploaded.bin",
            timeout=120,
        )
        assert mode_in_vm.returncode == 0, (
            f"stat -c %a failed in VM.\n"
            f"stdout: {mode_in_vm.stdout}\nstderr: {mode_in_vm.stderr}"
        )
        assert mode_in_vm.stdout.strip() == "700", (
            f"mode for /home/agent/sparse-uploaded.bin not preserved across upload: "
            f"expected 700, got {mode_in_vm.stdout.strip()!r}"
        )

        # In-VM size check: the apparent (logical) size must equal
        # 10 MB exactly. `stat -c %s` returns size in bytes.
        size_in_vm = sandbox_cli(
            "exec", "ws-cp-attr", "--",
            "stat", "-c", "%s", "/home/agent/sparse-uploaded.bin",
            timeout=120,
        )
        assert size_in_vm.returncode == 0, (
            f"stat -c %s failed in VM: stderr={size_in_vm.stderr!r}"
        )
        assert int(size_in_vm.stdout.strip()) == 10 * 1024 * 1024, (
            f"apparent size for /home/agent/sparse-uploaded.bin not preserved: "
            f"expected {10 * 1024 * 1024}, got {size_in_vm.stdout.strip()!r}"
        )

        # In-VM allocated-size check: `du -B1 --apparent-size` should
        # report ≥ 10 MB; plain `du -B1` (allocated, in bytes) must
        # report ≤ 10 MB + 1 MB tolerance (so sparseness is still
        # recognisable, even if the backend reinflates a bit during
        # transit). Catching full inflation: if a base64-style pump
        # crept back in, allocated would equal apparent (10 MB).
        allocated_in_vm = sandbox_cli(
            "exec", "ws-cp-attr", "--",
            "du", "-B1", "/home/agent/sparse-uploaded.bin",
            timeout=120,
        )
        assert allocated_in_vm.returncode == 0, (
            f"du failed in VM: stderr={allocated_in_vm.stderr!r}"
        )
        # `du` output: "<bytes>\t<path>". Extract the number.
        allocated_bytes = int(allocated_in_vm.stdout.split()[0])
        assert allocated_bytes <= 10 * 1024 * 1024 + 1024 * 1024, (
            f"allocated bytes ({allocated_bytes}) for sparse file exceed "
            f"apparent size + 1 MB tolerance — sparseness was not preserved "
            f"(suggests a base64-style pump regression)."
        )

        # Round-trip back to the host via `sandbox cp`.
        cp_down = sandbox_cli(
            "cp", "ws-cp-attr:/home/agent/sparse-uploaded.bin", roundtrip,
            timeout=180,
        )
        assert cp_down.returncode == 0, (
            f"sandbox cp download failed (rc={cp_down.returncode}).\n"
            f"stdout: {cp_down.stdout}\nstderr: {cp_down.stderr}"
        )

        # Host-side mode check after round-trip.
        host_mode = stat.S_IMODE(os.stat(roundtrip).st_mode)
        assert host_mode == 0o700, (
            f"mode for round-tripped file not preserved on host: "
            f"expected 0o700, got {oct(host_mode)}"
        )

        # Host-side apparent size after round-trip.
        host_size = os.path.getsize(roundtrip)
        assert host_size == 10 * 1024 * 1024, (
            f"apparent size for round-tripped file not preserved on host: "
            f"expected {10 * 1024 * 1024}, got {host_size}"
        )

        # Host-side allocated-size sparseness check (st_blocks * 512
        # bytes is the standard POSIX allocated-size formula).
        host_allocated = os.stat(roundtrip).st_blocks * 512
        assert host_allocated <= 10 * 1024 * 1024 + 1024 * 1024, (
            f"host-side round-tripped file allocated {host_allocated} bytes "
            f"for {host_size} apparent — exceeds 1 MB tolerance, sparseness "
            f"lost on the download leg."
        )

        sandbox_cli("rm", "ws-cp-attr", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-cp-attr", timeout=120)
        if host_dir is not None:
            import shutil
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_sync_full_tree(sandbox_cli, backend):
    """Create a session, build a small directory tree on the host, use
    `sandbox sync` to upload it, then verify every file landed in the
    session with the same contents and (for symlinks) the same target.

    `sandbox sync` dispatches to host `rsync` over the backend's
    native shell (`limactl shell` for Lima, `docker exec -i` for
    container). This is the happy-path baseline: a fresh tree
    transferred end-to-end.
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-sync-full-")
        # Build a small tree: a regular file, a nested file, an
        # executable file (mode preservation matters), a symlink.
        with open(os.path.join(host_dir, "a.txt"), "w") as f:
            f.write("file a contents\n")
        os.makedirs(os.path.join(host_dir, "nested"))
        with open(os.path.join(host_dir, "nested", "b.txt"), "w") as f:
            f.write("file b contents\n")
        script_path = os.path.join(host_dir, "run.sh")
        with open(script_path, "w") as f:
            f.write("#!/bin/sh\necho ok\n")
        os.chmod(script_path, 0o755)
        os.symlink("a.txt", os.path.join(host_dir, "a.symlink"))

        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-sync-full"),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-sync-full", "Running", timeout=10)

        sync_result = sandbox_cli(
            "sync", host_dir, "ws-sync-full:/home/agent/workspace/synced",
            timeout=300,
        )
        assert sync_result.returncode == 0, (
            f"sandbox sync upload failed (rc={sync_result.returncode}).\n"
            f"stdout: {sync_result.stdout}\nstderr: {sync_result.stderr}"
        )

        # Verify each entry landed.
        for relpath, expected in [
            ("a.txt", "file a contents\n"),
            ("nested/b.txt", "file b contents\n"),
            ("run.sh", "#!/bin/sh\necho ok\n"),
        ]:
            cat = sandbox_cli(
                "exec", "ws-sync-full", "--",
                "cat", f"/home/agent/workspace/synced/{relpath}",
                timeout=120,
            )
            assert cat.returncode == 0 and cat.stdout == expected, (
                f"contents mismatch for {relpath}: rc={cat.returncode} "
                f"stdout={cat.stdout!r} stderr={cat.stderr!r}"
            )

        # Verify mode preservation (`-a` / `--archive`).
        stat = sandbox_cli(
            "exec", "ws-sync-full", "--",
            "stat", "-c", "%a", "/home/agent/workspace/synced/run.sh",
            timeout=120,
        )
        assert stat.returncode == 0 and stat.stdout.strip() == "755", (
            f"mode for run.sh not preserved: stdout={stat.stdout!r} "
            f"stderr={stat.stderr!r}"
        )

        # Verify symlink preservation.
        readlink = sandbox_cli(
            "exec", "ws-sync-full", "--",
            "readlink", "/home/agent/workspace/synced/a.symlink",
            timeout=120,
        )
        assert readlink.returncode == 0 and readlink.stdout.strip() == "a.txt", (
            f"symlink target not preserved: stdout={readlink.stdout!r} "
            f"stderr={readlink.stderr!r}"
        )

        sandbox_cli("rm", "ws-sync-full", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-sync-full", timeout=120)
        if host_dir is not None:
            import shutil
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_sync_incremental_no_op(sandbox_cli, backend):
    """Sync a tree, then immediately re-sync the same tree. The second
    invocation should transfer no file contents — `rsync --itemize-
    changes` should report no `>f` (file-update) lines.

    This pins the property that distinguishes `sync` from `cp`: a
    no-change re-run is cheap, not a full retransfer.
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-sync-incr-")
        for i in range(5):
            with open(os.path.join(host_dir, f"file{i}.txt"), "w") as f:
                f.write(f"contents {i}\n")

        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-sync-incr"),
            timeout=600,
        )
        assert result.returncode == 0
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-sync-incr", "Running", timeout=10)

        # First sync: transfers everything.
        first = sandbox_cli(
            "sync", host_dir, "ws-sync-incr:/home/agent/workspace/incr",
            timeout=300,
        )
        assert first.returncode == 0, (
            f"first sync failed: stdout={first.stdout!r} stderr={first.stderr!r}"
        )

        # Second sync with --itemize-changes via env passthrough is
        # not possible at the `sandbox sync` surface (no flag pass-
        # through by design — see "explicitly deferred"). Instead,
        # assert the second sync's stderr contains no rsync transfer
        # lines: rsync's verbose output includes `>f` markers only
        # when a file is updated. With our default `-a --delete`
        # flags rsync stays silent on a no-change run, so the second
        # invocation produces empty stdout.
        second = sandbox_cli(
            "sync", host_dir, "ws-sync-incr:/home/agent/workspace/incr",
            timeout=300,
        )
        assert second.returncode == 0, (
            f"second sync failed: stdout={second.stdout!r} stderr={second.stderr!r}"
        )
        assert ">f" not in second.stdout and ">f" not in second.stderr, (
            f"second sync transferred files (expected no-op):\n"
            f"stdout={second.stdout!r}\nstderr={second.stderr!r}"
        )

        sandbox_cli("rm", "ws-sync-incr", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-sync-incr", timeout=120)
        if host_dir is not None:
            import shutil
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_sync_delete_mirroring(sandbox_cli, backend):
    """Sync a tree, remove a file on the host, sync again. The file
    must be gone in the session — `--delete` mirror semantics.
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-sync-del-")
        for name in ("keep.txt", "obsolete.txt"):
            with open(os.path.join(host_dir, name), "w") as f:
                f.write(f"contents of {name}\n")

        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-sync-del"),
            timeout=600,
        )
        assert result.returncode == 0
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-sync-del", "Running", timeout=10)

        # Initial sync — both files present.
        s1 = sandbox_cli(
            "sync", host_dir, "ws-sync-del:/home/agent/workspace/del",
            timeout=300,
        )
        assert s1.returncode == 0
        for name in ("keep.txt", "obsolete.txt"):
            check = sandbox_cli(
                "exec", "ws-sync-del", "--",
                "test", "-f", f"/home/agent/workspace/del/{name}",
                timeout=120,
            )
            assert check.returncode == 0, f"{name} should exist after first sync"

        # Remove the file on the host, re-sync.
        os.unlink(os.path.join(host_dir, "obsolete.txt"))
        s2 = sandbox_cli(
            "sync", host_dir, "ws-sync-del:/home/agent/workspace/del",
            timeout=300,
        )
        assert s2.returncode == 0

        # `keep.txt` still there, `obsolete.txt` deleted by --delete.
        keep = sandbox_cli(
            "exec", "ws-sync-del", "--",
            "test", "-f", "/home/agent/workspace/del/keep.txt",
            timeout=120,
        )
        assert keep.returncode == 0, "keep.txt should still exist after second sync"
        gone = sandbox_cli(
            "exec", "ws-sync-del", "--",
            "test", "-e", "/home/agent/workspace/del/obsolete.txt",
            timeout=120,
        )
        assert gone.returncode != 0, (
            f"obsolete.txt should be deleted by --delete; "
            f"rc={gone.returncode} stdout={gone.stdout!r} stderr={gone.stderr!r}"
        )

        sandbox_cli("rm", "ws-sync-del", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-sync-del", timeout=120)
        if host_dir is not None:
            import shutil
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_sync_attribute_preservation(sandbox_cli, backend):
    """Sync a tree containing files with non-default modes and verify
    the modes are preserved in the session (`-a` / `--archive` slot).
    """
    session_id = None
    host_dir = None
    try:
        host_dir = tempfile.mkdtemp(prefix="sandbox-sync-attr-")
        # File modes chosen to be distinguishable: 0644 (default-ish),
        # 0600 (private), 0755 (executable). rsync's `-a` should
        # carry all three across.
        cases = [
            ("plain.txt", 0o644),
            ("private.txt", 0o600),
            ("script.sh", 0o755),
        ]
        for name, mode in cases:
            path = os.path.join(host_dir, name)
            with open(path, "w") as f:
                f.write(f"contents {name}\n")
            os.chmod(path, mode)

        result = sandbox_cli(
            "create", *make_create_args(backend, "ws-sync-attr"),
            timeout=600,
        )
        assert result.returncode == 0
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-sync-attr", "Running", timeout=10)

        s = sandbox_cli(
            "sync", host_dir, "ws-sync-attr:/home/agent/workspace/attr",
            timeout=300,
        )
        assert s.returncode == 0, (
            f"sync failed: stdout={s.stdout!r} stderr={s.stderr!r}"
        )

        for name, expected_mode in cases:
            stat = sandbox_cli(
                "exec", "ws-sync-attr", "--",
                "stat", "-c", "%a", f"/home/agent/workspace/attr/{name}",
                timeout=120,
            )
            assert stat.returncode == 0, (
                f"stat failed for {name}: stderr={stat.stderr!r}"
            )
            assert stat.stdout.strip() == oct(expected_mode)[2:], (
                f"mode for {name} not preserved: "
                f"expected {oct(expected_mode)[2:]}, got {stat.stdout.strip()!r}"
            )

        sandbox_cli("rm", "ws-sync-attr", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-sync-attr", timeout=120)
        if host_dir is not None:
            import shutil
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass


@pytest.mark.timeout(600)
def test_shared_mount(sandbox_cli, backend):
    """Create a session with --workspace shared:<tmpdir>.
    Verify bidirectional file visibility between host and VM.

    Backend-agnostic: the container backend's bind target
    is unified with Lima's at `/home/agent/workspace/`, so the path
    assertions below work on both backends.

    Rootless-Docker handling lives daemon-side: the daemon
    refuses container session-create on rootless hosts by default
    (spec § Non-goals line 1195 + `RootlessDockerRefused` mapped to
    HTTP 400). The previous in-body `is_rootless_docker()` skip is no
    longer needed — on a rootless rig the `sandbox create` call below
    fails loudly with the daemon's rejection text, which is the
    correct signal that the host is operating outside the supported
    envelope. On default-hardened Docker (the supported configuration)
    the test runs as a hard contract.
    """
    session_id = None
    host_dir = None
    try:
        # Create a temporary directory on the host to be shared.
        host_dir = tempfile.mkdtemp(prefix="sandbox-shared-ws-")

        result = sandbox_cli(
            "create",
            *make_create_args(
                backend, "ws-shared",
                "--workspace", f"shared:{host_dir}",
            ),
            timeout=600,
        )
        assert result.returncode == 0, (
            f"sandbox create failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        session_id = parse_session_id(result.stdout)
        wait_for_state(sandbox_cli, "ws-shared", "Running", timeout=10)

        # 1. Host -> VM: create a file on the host, verify visible in the VM.
        host_file = os.path.join(host_dir, "from-host.txt")
        host_content = "hello from the host\n"
        with open(host_file, "w") as f:
            f.write(host_content)

        # The file should be visible at /home/agent/workspace/from-host.txt
        cat_result = sandbox_cli(
            "exec", "ws-shared", "--",
            "cat", "/home/agent/workspace/from-host.txt",
            timeout=120,
        )
        assert cat_result.returncode == 0, (
            f"cat from-host.txt failed in VM.\n"
            f"stdout: {cat_result.stdout}\nstderr: {cat_result.stderr}"
        )
        assert cat_result.stdout == host_content, (
            f"Host file content mismatch in VM.\n"
            f"Expected: {host_content!r}\nGot: {cat_result.stdout!r}"
        )

        # 2. VM -> Host: create a file in the VM, verify visible on the host.
        vm_content = "hello from the VM"
        exec_result = sandbox_cli(
            "exec", "ws-shared", "--",
            "bash", "-c",
            f"echo -n '{vm_content}' > /home/agent/workspace/from-vm.txt",
            timeout=120,
        )
        assert exec_result.returncode == 0, (
            f"Failed to create file in VM.\n"
            f"stdout: {exec_result.stdout}\nstderr: {exec_result.stderr}"
        )

        vm_file_on_host = os.path.join(host_dir, "from-vm.txt")
        assert os.path.exists(vm_file_on_host), (
            f"File created in VM not visible on host at {vm_file_on_host}"
        )
        with open(vm_file_on_host) as f:
            downloaded_content = f.read()
        assert downloaded_content == vm_content, (
            f"VM file content mismatch on host.\n"
            f"Expected: {vm_content!r}\nGot: {downloaded_content!r}"
        )

        # Clean up.
        sandbox_cli("rm", "ws-shared", timeout=120)
        session_id = None

    finally:
        if session_id is not None:
            sandbox_cli("rm", "ws-shared", timeout=120)
        if host_dir is not None:
            import shutil
            try:
                shutil.rmtree(host_dir)
            except OSError:
                pass
