"""Meta-tests for the release-tarball fixture cache validity.

The ``release_tarball_x86_64`` and ``release_tarball_x86_64_bumped``
session-scoped fixtures both cache their output tarball under
``tests/install-e2e/dist/`` and skip the rebuild on subsequent
invocations. Without a freshness check, an iteration cycle that
edits Rust code and re-runs pytest would happily reuse a stale
tarball whose binaries were built against the *pre-edit* tree.

The fixtures guard against this by invalidating the cache when any
``*.rs`` file under ``sandboxd/`` is younger than the cached tarball.
This test pins that contract for the base fixture: a workspace ``.rs``
``touch`` (which only updates mtime) is enough to make the staleness
predicate fire.

The bumped fixture's check is symmetric and shares the same
``_newest_rs_mtime`` helper, so this single test covers both code
paths.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

# Import the helper so we exercise the same predicate the fixtures use.
from conftest import (
    DIST_DIR,
    PROJECT_ROOT,
    _newest_rs_mtime,
    _read_workspace_version,
)


def _cached_base_tarball() -> Path | None:
    """Return the cached base tarball path, or None if it isn't present.

    The cache lives at ``tests/install-e2e/dist/sandboxd-<ver>-<arch>.tar.gz``;
    we only care about x86_64 here (mirrors the fixture's own guard).
    """
    ver = _read_workspace_version()
    arch = "x86_64-unknown-linux-gnu"
    candidate = DIST_DIR / f"sandboxd-{ver}-{arch}.tar.gz"
    return candidate if candidate.exists() else None


def test_release_tarball_x86_64_fixture_invalidates_on_rs_touch():
    """Touch any workspace ``.rs`` file; assert the cached tarball
    becomes stale per the same predicate the fixture uses.

    The test is non-mutating: we ``os.utime`` the ``.rs`` file forward
    by one second, observe the predicate firing, then restore the
    original mtime so a subsequent pytest run is not perturbed.

    Skips when there is no cached tarball to invalidate (fresh checkout
    or after ``make clean``) — there is no cache to test in that case;
    the fixture will build unconditionally and the freshness guard
    short-circuits trivially.
    """
    tarball = _cached_base_tarball()
    if tarball is None:
        pytest.skip(
            "no cached release_tarball_x86_64 tarball under dist/ — nothing to "
            "invalidate. Run `make test-e2e-container` once to populate the "
            "cache, then re-run this test."
        )

    # Sanity precondition: the cached tarball must currently be FRESH
    # against the workspace's `.rs` files. If it's already stale, this
    # test cannot distinguish its own touch from a pre-existing edit —
    # bail with a clear signal.
    initial_newest_rs = _newest_rs_mtime()
    initial_stale = tarball.stat().st_mtime < initial_newest_rs
    if initial_stale:
        pytest.skip(
            f"cached tarball at {tarball} is already stale relative to "
            f"workspace .rs files (newest .rs mtime={initial_newest_rs}, "
            f"tarball mtime={tarball.stat().st_mtime}); the cache "
            "invalidation contract is already engaged. Run "
            "`make test-e2e-container` to rebuild, then re-run this test."
        )

    # Pick a representative `.rs` file to touch. The workspace's
    # `lib.rs` files are stable across iterations; the helper walks
    # every `.rs` under `sandboxd/`, so any one of them shifts the
    # `_newest_rs_mtime()` reading. We deliberately avoid `main.rs`
    # files (some of them are bin entry points whose mtime is checked
    # by cargo's incremental cache) and pick a library lib.rs which
    # cargo will rebuild idempotently against.
    target_rs = PROJECT_ROOT / "sandboxd" / "sandbox-core" / "src" / "lib.rs"
    assert target_rs.exists(), (
        f"expected workspace canary .rs file at {target_rs}; "
        "the test relies on this path existing under sandboxd/"
    )

    original_atime_ns = target_rs.stat().st_atime_ns
    original_mtime_ns = target_rs.stat().st_mtime_ns

    try:
        # Push the .rs mtime past the tarball's mtime + 1s margin.
        # Some filesystems (ext4 with default options) record mtime at
        # 1-second granularity, so a sub-second bump can land on the
        # same recorded value and the predicate would still see the
        # tarball as fresh.
        new_mtime_ns = max(
            tarball.stat().st_mtime_ns + 2_000_000_000,
            original_mtime_ns + 1_000_000_000,
        )
        os.utime(target_rs, ns=(original_atime_ns, new_mtime_ns))

        # Force the os.walk inside _newest_rs_mtime to observe the
        # new mtime — utimes(2) is synchronous so this is immediate,
        # but on some kernels mtime updates are debounced; a tiny
        # sleep removes the last micro-race.
        time.sleep(0.05)

        newest_rs_after_touch = _newest_rs_mtime()
        assert newest_rs_after_touch >= (new_mtime_ns / 1_000_000_000), (
            f"_newest_rs_mtime() returned {newest_rs_after_touch}; "
            f"expected >= {new_mtime_ns / 1_000_000_000} after touching "
            f"{target_rs}. The helper may be skipping a directory that "
            "actually holds workspace .rs sources."
        )

        # The fixture's staleness predicate is
        # `tarball.stat().st_mtime < _newest_rs_mtime()` — re-evaluate
        # it the same way and assert it now fires.
        stale_after_touch = tarball.stat().st_mtime < newest_rs_after_touch
        assert stale_after_touch, (
            f"cached tarball at {tarball} (mtime={tarball.stat().st_mtime}) "
            f"is NOT stale relative to workspace .rs files "
            f"(newest .rs mtime={newest_rs_after_touch}) after touching "
            f"{target_rs}. The fixture would happily reuse a tarball whose "
            "binaries were built before the .rs edit."
        )
    finally:
        # Restore the original mtime so subsequent pytest runs (and
        # cargo's incremental cache) are not perturbed by this test.
        os.utime(target_rs, ns=(original_atime_ns, original_mtime_ns))


def test_newest_rs_mtime_skips_target_directory():
    """Regression guard: ``_newest_rs_mtime`` must not walk into
    ``sandboxd/target/``.

    Cargo writes generated ``.rs`` files (proc-macro expansions,
    ``build.rs`` outputs) into ``target/`` whose mtime is bumped on
    every build. If the walk included ``target/``, every pytest
    invocation after a cargo rebuild would see a stale tarball — the
    fixture would then *unconditionally* rebuild on every run,
    defeating the cache entirely.

    The fixture's `os.walk` filter excludes ``target``, ``.git``, and
    ``node_modules``. This test pins ``target`` specifically because
    it is the dangerous one — both because cargo writes .rs files
    there and because cargo rebuilds touch them on every workspace
    edit.
    """
    target_dir = PROJECT_ROOT / "sandboxd" / "target"
    if not target_dir.exists():
        pytest.skip(
            f"no cargo target/ directory at {target_dir} — workspace has "
            "not been built. Run `cargo build --workspace` once, then "
            "re-run this test."
        )

    # Find one .rs file inside target/ to plant a far-future mtime on.
    candidate_rs = None
    for root, _dirs, files in os.walk(target_dir):
        for name in files:
            if name.endswith(".rs"):
                candidate_rs = Path(root) / name
                break
        if candidate_rs is not None:
            break

    if candidate_rs is None:
        pytest.skip(
            f"no .rs file found under {target_dir} — target/ has no "
            "build artifacts to walk. Run `cargo build --workspace` "
            "once, then re-run this test."
        )

    original_atime_ns = candidate_rs.stat().st_atime_ns
    original_mtime_ns = candidate_rs.stat().st_mtime_ns

    try:
        # Plant a mtime well past every conceivable real source file
        # (one year in the future). If the walk includes target/, the
        # helper would return roughly this value; if it correctly
        # excludes target/, the return must be strictly less.
        future_ns = (int(time.time()) + 365 * 24 * 3600) * 1_000_000_000
        os.utime(candidate_rs, ns=(original_atime_ns, future_ns))
        time.sleep(0.05)

        newest_rs = _newest_rs_mtime()
        future_s = future_ns / 1_000_000_000
        # The helper's return must be strictly less than our planted
        # value — if target/ were walked, the planted mtime would
        # dominate.
        assert newest_rs < future_s, (
            f"_newest_rs_mtime() returned {newest_rs}, which is >= the "
            f"future mtime ({future_s}) planted under {candidate_rs}. "
            "The helper appears to be walking into sandboxd/target/, "
            "which would invalidate the tarball cache on every cargo "
            "rebuild."
        )
    finally:
        os.utime(candidate_rs, ns=(original_atime_ns, original_mtime_ns))
