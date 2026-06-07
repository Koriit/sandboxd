"""Host-side assembly correctness tests for scripts/build.sh.

Runs ``scripts/build.sh`` (with various flags) against a temp output directory
and asserts structural properties of the produced artifacts.  No Lima VM is
spawned; these tests are fast and run on any developer machine.

Coverage:
- Both artifacts are produced by default.
- No inline marker lines survive in either artifact.
- No ```. ui.sh``` invocation line survives in either artifact.
- The engine sentinel (``_ui_spinner_frame()`` definition) is present in built
  install.sh (ui.sh was inlined).
- No ``BEGIN_TEST_ENV``/``END_TEST_ENV`` spans survive in built install.sh
  without ``--keep-test-env``.
- ``--keep-test-env`` retains test-env spans in built install.sh.
- Two runs with the same flags produce byte-identical output (R4.5).
- ``--install-only`` produces only install.sh (no uninstall.sh).
- ``--uninstall-only`` produces only uninstall.sh (no install.sh).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent.parent / "scripts"
BUILD_SH = SCRIPTS / "build.sh"


def _build(out: Path, *extra_flags: str) -> None:
    """Run build.sh into *out* and assert it exits cleanly."""
    subprocess.run(
        [str(BUILD_SH), "--out", str(out)] + list(extra_flags),
        check=True,
        timeout=60,
    )


@pytest.fixture()
def build_dir(tmp_path):
    """Run a default build once and return the output directory."""
    _build(tmp_path)
    return tmp_path


def test_both_artifacts_produced(build_dir):
    assert (build_dir / "install.sh").exists(), "install.sh not produced"
    assert (build_dir / "uninstall.sh").exists(), "uninstall.sh not produced"


def test_no_inline_markers_in_install_sh(build_dir):
    text = (build_dir / "install.sh").read_text()
    assert "# BEGIN_INLINE" not in text, "BEGIN_INLINE survived in install.sh"
    assert "# END_INLINE" not in text, "END_INLINE survived in install.sh"


def test_no_inline_markers_in_uninstall_sh(build_dir):
    text = (build_dir / "uninstall.sh").read_text()
    assert "# BEGIN_INLINE" not in text, "BEGIN_INLINE survived in uninstall.sh"
    assert "# END_INLINE" not in text, "END_INLINE survived in uninstall.sh"


def test_no_dot_ui_sh_in_install_sh(build_dir):
    text = (build_dir / "install.sh").read_text()
    for line in text.splitlines():
        assert not (line.strip().startswith(". ") and "ui.sh" in line), (
            f"'. ui.sh' invocation survived in install.sh: {line!r}"
        )


def test_no_dot_ui_sh_in_uninstall_sh(build_dir):
    text = (build_dir / "uninstall.sh").read_text()
    for line in text.splitlines():
        assert not (line.strip().startswith(". ") and "ui.sh" in line), (
            f"'. ui.sh' invocation survived in uninstall.sh: {line!r}"
        )


def test_engine_sentinel_present_in_install_sh(build_dir):
    text = (build_dir / "install.sh").read_text()
    assert "_ui_spinner_frame()" in text, (
        "engine sentinel _ui_spinner_frame() not found in built install.sh — "
        "ui.sh was not inlined correctly"
    )


def test_no_test_env_spans_in_install_sh_by_default(build_dir):
    text = (build_dir / "install.sh").read_text()
    assert "# BEGIN_TEST_ENV" not in text, (
        "BEGIN_TEST_ENV survived in install.sh without --keep-test-env"
    )
    assert "# END_TEST_ENV" not in text, (
        "END_TEST_ENV survived in install.sh without --keep-test-env"
    )


def test_keep_test_env_retains_spans(tmp_path):
    _build(tmp_path, "--keep-test-env")
    text = (tmp_path / "install.sh").read_text()
    assert "# BEGIN_TEST_ENV" in text, (
        "BEGIN_TEST_ENV not found in install.sh built with --keep-test-env"
    )


def test_idempotent(tmp_path):
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    out1.mkdir()
    out2.mkdir()
    _build(out1)
    _build(out2)
    for name in ("install.sh", "uninstall.sh"):
        b1 = (out1 / name).read_bytes()
        b2 = (out2 / name).read_bytes()
        assert b1 == b2, f"{name}: two build runs produced different output (not idempotent)"


def test_install_only_produces_only_install_sh(tmp_path):
    _build(tmp_path, "--install-only")
    assert (tmp_path / "install.sh").exists(), "install.sh not produced with --install-only"
    assert not (tmp_path / "uninstall.sh").exists(), (
        "uninstall.sh produced despite --install-only"
    )


def test_uninstall_only_produces_only_uninstall_sh(tmp_path):
    _build(tmp_path, "--uninstall-only")
    assert (tmp_path / "uninstall.sh").exists(), "uninstall.sh not produced with --uninstall-only"
    assert not (tmp_path / "install.sh").exists(), (
        "install.sh produced despite --uninstall-only"
    )
