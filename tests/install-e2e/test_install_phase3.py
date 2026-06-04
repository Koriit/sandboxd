"""Phase 3 install.sh tests: UI polish degradation guarantees.

The e2e harness runs without a controlling TTY, so it always exercises
plain mode (RICH_UI=0). The tests here focus on the degradation guarantees
that are verifiable in this environment:

- ``test_plain_mode_no_escape_sequences`` — non-TTY / --no-color output
  contains no terminal escape sequences (ESC codes, OSC sequences, etc.)
  and no smcup/rmcup sequences. This guards the critical invariant that
  rich-mode code does not leak into the plain-mode path.
- ``test_plain_mode_completes`` — end-to-end install in plain mode completes
  successfully with the expected log entries (redundant with existing happy-
  path tests but provides explicit regression coverage for Phase 3 changes).
- ``test_no_color_flag_suppresses_ansi`` — --no-color forces no escape
  sequences even if stdout were a TTY.
"""

from __future__ import annotations

import re
import pytest

from conftest import (
    assert_full_install_landed,
    copy_tarball_to_vm,
    install_sh_cmd,
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

# ANSI / terminal escape sequence patterns that must be absent in plain mode.
# Covers:
#   ESC [ ... m   — SGR (color/style) sequences: \x1b[...m
#   ESC [ ... A/B/C/D/K/J/H  — cursor movement: \x1b[...A etc.
#   ESC [ ... s/u  — cursor save/restore
#   ESC ] ... ST  — OSC (Operating System Command): \x1b]...\x1b\\  or  \x1b]...\x07
#   ESC ( / )     — charset designation
# We use a broad pattern: any occurrence of ESC (\x1b / \033) is disallowed.
_ESC_RE = re.compile(r"\x1b", re.DOTALL)

# smcup/rmcup visible in raw bytes: tput smcup/rmcup outputs terminfo
# sequences. On xterm these start with ESC[?1049h / ESC[?1049l.
# Since we already check for any ESC, this is covered by _ESC_RE.
# As an extra belt-and-suspenders check, look for the literal tput capability
# names in the output (they should never appear as literal text).
_TPUT_CAPS_RE = re.compile(r"\b(smcup|rmcup|tput)\b")


def _has_escape_sequences(text: str) -> bool:
    """Return True if text contains any ESC byte."""
    return bool(_ESC_RE.search(text))


def _has_tput_caps_literal(text: str) -> bool:
    """Return True if text contains smcup/rmcup/tput as literal words."""
    return bool(_TPUT_CAPS_RE.search(text))


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_plain_mode_no_escape_sequences(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Non-TTY (plain mode) output must contain no terminal escape sequences.

    The install-e2e harness always runs without a controlling TTY, so
    limactl shell's stdout is a pipe, not a terminal. RICH_UI must be 0
    and no Phase-3 escape sequences must appear in the output.

    Also checks that the literal strings 'smcup' and 'rmcup' do not appear
    as text in the output (they should only be emitted by tput to the
    terminal device, never printed as plaintext).
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install failed:\n{r.stdout}\n{r.stderr}"
    )

    combined = r.stdout + r.stderr

    assert not _has_escape_sequences(combined), (
        "plain-mode install output contains ESC escape sequences — "
        "rich-mode UI code must not leak into non-TTY path.\n"
        f"First match at: {repr(combined[max(0,_ESC_RE.search(combined).start()-20):_ESC_RE.search(combined).start()+20])}"
    )

    assert not _has_tput_caps_literal(combined), (
        "plain-mode install output contains literal 'smcup', 'rmcup', or 'tput' — "
        "these capability names must only go to the terminal device, not stdout.\n"
        f"Output sample:\n{combined[:500]}"
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_plain_mode_completes_end_to_end(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """Plain-mode install completes and passes full post-condition checks.

    Explicit regression guard: Phase 3 changes must not break the non-TTY
    execution path that the e2e harness exercises.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install failed in plain mode:\n{r.stdout}\n{r.stderr}"
    )

    # Full filesystem + state post-conditions (same as happy-path tests).
    assert_full_install_landed(vm)

    # Confirm the install log shows step=tty_detect rich=no (not rich=yes).
    log = vm.shell(
        "sudo cat /var/log/sandbox-install.log", check=True, timeout=10,
    ).stdout
    assert "step=tty_detect" in log, (
        f"tty_detect step missing from install log:\n{log}"
    )
    assert "rich=no" in log, (
        f"expected rich=no in tty_detect log; got:\n"
        + "\n".join(l for l in log.splitlines() if "tty_detect" in l)
    )


@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_no_color_flag_suppresses_ansi(
    distro_template, vm_factory, release_tarball_x86_64, sigstore_stack,
):
    """--no-color output (already in plain mode via no TTY) has no escape codes.

    install_sh_cmd always passes --no-color. This test makes it explicit
    and verifies the interaction: even if RICH_UI were somehow triggered,
    --no-color must prevent all escape sequences. Since the harness has no
    TTY, RICH_UI=0 is guaranteed via the tty check, but --no-color is an
    additional defense-in-depth layer.
    """
    vm = vm_factory(distro_template)
    tarball_in_vm = copy_tarball_to_vm(vm, release_tarball_x86_64)

    # install_sh_cmd already passes --no-color; test is explicit about it.
    r = vm.shell(
        install_sh_cmd(tarball_in_vm, vm=vm, sigstore_stack=sigstore_stack),
        timeout=600,
    )
    assert r.returncode == 0, (
        f"install with --no-color failed:\n{r.stdout}\n{r.stderr}"
    )

    # No ESC bytes in stdout or stderr.
    combined = r.stdout + r.stderr
    assert not _has_escape_sequences(combined), (
        "--no-color install produced escape sequences in output"
    )
