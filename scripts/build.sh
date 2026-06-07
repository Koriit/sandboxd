#!/bin/sh
# scripts/build.sh — assemble publishable install.sh / uninstall.sh.
#
# Inlines ui.sh into each selected script (replacing the BEGIN_INLINE…END_INLINE
# marker span), strips BEGIN_TEST_ENV…END_TEST_ENV spans from install.sh and
# uninstall.sh (unless --keep-test-env), and verifies the output before writing
# it to the output directory.
#
# Usage:
#   scripts/build.sh [--install-only|--uninstall-only] [--out DIR] [--keep-test-env]
#
# Flags:
#   --install-only    Build only install.sh (skip uninstall.sh)
#   --uninstall-only  Build only uninstall.sh (skip install.sh)
#   --out DIR         Output directory (default: build/dist/)
#   --keep-test-env   Suppress test-env stripping from install.sh and uninstall.sh
#
# Output files mirror their source scripts' executable bit (chmod --reference).
# Two invocations with the same inputs and flags produce byte-identical output.

set -eu

# ---------------------------------------------------------------------------
# Locate repo root from $0 (works whether invoked as scripts/build.sh or as
# an absolute path; cd avoids reliance on realpath / readlink -f portability).
# ---------------------------------------------------------------------------
_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Argument parsing.
# ---------------------------------------------------------------------------
_OUT_DIR="$_REPO_ROOT/build/dist"
_INSTALL_ONLY=0
_UNINSTALL_ONLY=0
_KEEP_TEST_ENV=0

while [ $# -gt 0 ]; do
    case "$1" in
        --install-only)
            _INSTALL_ONLY=1
            shift
            ;;
        --uninstall-only)
            _UNINSTALL_ONLY=1
            shift
            ;;
        --out)
            if [ $# -lt 2 ] || [ -z "$2" ]; then
                printf 'build.sh: --out requires a non-empty directory argument\n' >&2
                exit 1
            fi
            _OUT_DIR="$2"
            shift 2
            ;;
        --keep-test-env)
            _KEEP_TEST_ENV=1
            shift
            ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            printf 'build.sh: unknown flag: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

if [ "$_INSTALL_ONLY" -eq 1 ] && [ "$_UNINSTALL_ONLY" -eq 1 ]; then
    printf 'build.sh: --install-only and --uninstall-only are mutually exclusive\n' >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Source file paths.
# ---------------------------------------------------------------------------
_UI_SH="$_REPO_ROOT/scripts/ui.sh"
_INSTALL_SH_SRC="$_REPO_ROOT/scripts/install.sh"
_UNINSTALL_SH_SRC="$_REPO_ROOT/scripts/uninstall.sh"

for _f in "$_UI_SH" "$_INSTALL_SH_SRC" "$_UNINSTALL_SH_SRC"; do
    if [ ! -f "$_f" ]; then
        printf 'build.sh: required source file not found: %s\n' "$_f" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Prepare output directory.
# ---------------------------------------------------------------------------
mkdir -p "$_OUT_DIR"

# ---------------------------------------------------------------------------
# _inline_ui <src> <dst>
#
# Stream <src>, replacing the BEGIN_INLINE ui.sh … END_INLINE ui.sh span
# (inclusive of the marker lines) with the body of ui.sh.  Errors out if
# the span is malformed (BEGIN without END or END without BEGIN).
# ---------------------------------------------------------------------------
_inline_ui() {
    _iu_src="$1"
    _iu_dst="$2"

    awk \
        -v ui_file="$_UI_SH" \
        '
        BEGIN {
            in_span = 0
            span_opened = 0
            span_closed = 0
        }

        /^# BEGIN_INLINE ui\.sh$/ {
            if (in_span) {
                print "build.sh: nested BEGIN_INLINE ui.sh in " FILENAME > "/dev/stderr"
                exit 2
            }
            in_span = 1
            span_opened = 1
            # Emit the ui.sh body in place of the span.
            while ((getline line < ui_file) > 0) {
                print line
            }
            close(ui_file)
            next
        }

        /^# END_INLINE ui\.sh$/ {
            if (!in_span) {
                print "build.sh: END_INLINE ui.sh without matching BEGIN in " FILENAME > "/dev/stderr"
                exit 2
            }
            in_span = 0
            span_closed = 1
            next
        }

        # Inside the span: suppress source lines (they are replaced by ui.sh body above).
        in_span { next }

        # Outside the span: pass through.
        { print }

        END {
            if (in_span) {
                print "build.sh: BEGIN_INLINE ui.sh without matching END in " FILENAME > "/dev/stderr"
                exit 2
            }
            if (!span_opened) {
                print "build.sh: no BEGIN_INLINE ui.sh marker found in " FILENAME > "/dev/stderr"
                exit 2
            }
        }
        ' \
        "$_iu_src" > "$_iu_dst"
}

# ---------------------------------------------------------------------------
# _strip_test_env <file>
#
# In-place removal of BEGIN_TEST_ENV … END_TEST_ENV spans (inclusive).
# Uses a temp file + mv for atomicity.
# ---------------------------------------------------------------------------
_strip_test_env() {
    _ste_file="$1"
    _ste_tmp="${_ste_file}.strip.tmp"
    sed '/# BEGIN_TEST_ENV/,/# END_TEST_ENV/d' "$_ste_file" > "$_ste_tmp"
    mv "$_ste_tmp" "$_ste_file"
}

# ---------------------------------------------------------------------------
# _verify <built_file> <is_install>
#
# Post-build verification:
#   1. No inline marker survivors (BEGIN_INLINE, END_INLINE).
#   2. No `. ui.sh` invocation line.
#   3. Engine sentinel (_ui_spinner_frame() definition) is present.
#   4. For install.sh: no test-env markers and no test-env var leakage
#      (unless _KEEP_TEST_ENV=1).
# ---------------------------------------------------------------------------
_verify() {
    _v_file="$1"
    _v_is_install="$2"
    _v_ok=1

    if grep -qE '^# (BEGIN|END)_INLINE' "$_v_file"; then
        printf 'build.sh: FAIL: inline markers survived in %s\n' "$_v_file" >&2
        _v_ok=0
    fi

    if grep -qE '^[[:space:]]*\. .*ui\.sh' "$_v_file"; then
        printf 'build.sh: FAIL: "`. ui.sh`" invocation survived in %s\n' "$_v_file" >&2
        _v_ok=0
    fi

    if ! grep -q '^_ui_spinner_frame() {' "$_v_file"; then
        printf 'build.sh: FAIL: engine sentinel _ui_spinner_frame() not found in %s\n' "$_v_file" >&2
        _v_ok=0
    fi

    if [ "$_v_is_install" -eq 1 ] && [ "$_KEEP_TEST_ENV" -eq 0 ]; then
        if grep -qE '^[[:space:]]*# (BEGIN|END)_TEST_ENV([[:space:]]|$)' "$_v_file"; then
            printf 'build.sh: FAIL: test-env markers survived in %s\n' "$_v_file" >&2
            _v_ok=0
        fi
        if grep -qE 'SANDBOX_(INSTALL|UPDATE)_TEST_|_DEBUG_COSIGN_STDERR|_SKIP_SIGSTORE' "$_v_file"; then
            printf 'build.sh: FAIL: test-env vars leaked into %s\n' "$_v_file" >&2
            _v_ok=0
        fi
    fi

    if [ "$_v_ok" -eq 0 ]; then
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# _build_script <src> <dst_name> <is_install>
#
# Full pipeline for scripts that carry the BEGIN_INLINE ui.sh marker:
#   inline → strip (if install, unless --keep-test-env) → chmod → verify.
#
# Scripts that lack the BEGIN_INLINE ui.sh marker are copied verbatim
# (chmod --reference preserved) with no further processing.  This handles
# scripts that will adopt the marker in a later phase.
# ---------------------------------------------------------------------------
_build_script() {
    _bs_src="$1"
    _bs_dst_name="$2"
    _bs_is_install="$3"

    _bs_dst="$_OUT_DIR/$_bs_dst_name"

    if ! grep -q '^# BEGIN_INLINE ui\.sh$' "$_bs_src"; then
        cp "$_bs_src" "$_bs_dst"
        chmod --reference="$_bs_src" "$_bs_dst"
        printf 'build.sh: copied %s (no inline marker)\n' "$_bs_dst"
        return
    fi

    _inline_ui "$_bs_src" "$_bs_dst"

    if [ "$_bs_is_install" -eq 1 ] && [ "$_KEEP_TEST_ENV" -eq 0 ]; then
        _strip_test_env "$_bs_dst"
    fi

    chmod --reference="$_bs_src" "$_bs_dst"

    _verify "$_bs_dst" "$_bs_is_install"

    printf 'build.sh: built %s\n' "$_bs_dst"
}

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
if [ "$_UNINSTALL_ONLY" -eq 0 ]; then
    _build_script "$_INSTALL_SH_SRC" "install.sh" 1
fi

if [ "$_INSTALL_ONLY" -eq 0 ]; then
    _build_script "$_UNINSTALL_SH_SRC" "uninstall.sh" 1
fi
