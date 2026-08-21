#!/usr/bin/env bash
#
# codesign-test-bins.sh — ad-hoc codesign workspace test binaries on Darwin.
#
# Background: after a sleep/wake cycle on macOS, syspolicyd scans unsigned
# Mach-O executables that cargo nextest spawns from target/debug/deps/. The
# scan can deadlock the nextest process for several minutes (or indefinitely),
# causing `make test` to stall. Ad-hoc codesigning (`codesign --sign -`)
# pre-registers the binaries with the kernel's code-signing subsystem so
# syspolicyd skips the online scan on subsequent executions from the same inode.
#
# NOTE: whether this fully eliminates the sleep/wake deadlock needs live
# verification (sleep/wake cycle, then `make test`). The code change is bounded
# and safe; effectiveness is a follow-on live-verify item.
#
# Usage: codesign-test-bins.sh [GREEN_ESCAPE] [RESET_ESCAPE]
#   The two optional arguments are ANSI escapes forwarded from the Makefile's
#   $(GREEN) / $(RESET) variables; empty on non-TTY / piped invocations.
#
# Implementation:
#   1. Build workspace test binaries with the same feature flags as `make test`.
#      cargo's own incremental-build check makes this fast on the warm path.
#   2. Parse cargo's --message-format json output to collect the exact paths of
#      the newly-built test executables (reason=compiler-artifact + profile.test).
#      This targets only the CURRENT binaries — not the stale hash-suffixed copies
#      that accumulate in target/debug/deps/ across rebuilds.
#   3. Ad-hoc codesign each binary with --force so re-running is idempotent.

set -euo pipefail

GREEN="${1:-}"
RESET="${2:-}"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "${GREEN}✓ codesign-test-bins skipped (not macOS)${RESET}"
    exit 0
fi

# Must be run from the repo root (Makefile does this via `scripts/dev/…`).
SANDBOXD_DIR="sandboxd"
if [ ! -d "$SANDBOXD_DIR" ]; then
    echo "codesign-test-bins: error: run from the repo root (sandboxd/ subdir not found)" >&2
    exit 1
fi

echo "codesign-test-bins: building workspace test binaries (this is fast on the warm path)..."

# Write the Python filter to a temp file so it can consume cargo's stdout via a
# pipe without stdin-redirect ambiguity (bash heredoc + pipe share stdin, which
# confuses the pipe; a temp file avoids that race).
_py_filter="$(mktemp /tmp/codesign-filter-XXXXXX)"
_tmp_bins="$(mktemp /tmp/codesign-paths-XXXXXX)"
trap 'rm -f "$_py_filter" "$_tmp_bins"' EXIT

cat > "$_py_filter" << 'EOF'
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        m = json.loads(line)
    except json.JSONDecodeError:
        continue
    if (
        m.get("reason") == "compiler-artifact"
        and m.get("executable")
        and m.get("profile", {}).get("test")
    ):
        print(m["executable"])
EOF

# Build and capture test binary paths.  stderr (cargo progress) goes to the
# terminal; stdout (JSON lines) is piped to the filter.
cd "$SANDBOXD_DIR"
cargo build --workspace --tests \
    --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override \
    --message-format json \
    | python3 "$_py_filter" > "$_tmp_bins"

bin_count=$(wc -l < "$_tmp_bins" | tr -d ' ')

if [ "$bin_count" -eq 0 ]; then
    echo "codesign-test-bins: warning: no test binaries found in cargo output; nothing to sign."
    exit 0
fi

echo "codesign-test-bins: ad-hoc signing ${bin_count} test binaries..."
while IFS= read -r bin; do
    codesign --sign - --force "$bin"
done < "$_tmp_bins"

echo "${GREEN}✓ codesign-test-bins: ${bin_count} test binaries ad-hoc signed${RESET}"
echo "  NOTE: effectiveness against the syspolicyd/Gatekeeper sleep-wake stall"
echo "  requires a live verification (sleep then wake, then make test)."
