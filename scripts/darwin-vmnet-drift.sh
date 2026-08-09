#!/bin/sh
# darwin-vmnet-drift.sh — does a loaded vmnet LaunchDaemon still match its plist?
#
# launchd caches a job's definition in memory when it is bootstrapped. Rewriting
# /Library/LaunchDaemons/<label>.plist afterwards changes nothing: the running
# job keeps the argv it was bootstrapped with until it is booted out and
# bootstrapped again. `launchctl kickstart -k` does NOT re-read the plist — it
# restarts the cached job.
#
# That makes "the job is loaded" a useless proxy for "the job is up to date",
# and the gap is not academic: a provisioning run can install a corrected plist,
# see the job loaded, report success, and leave the old definition serving until
# the next reboot silently swaps it in. This script closes the gap by comparing
# the two directly.
#
# Usage:
#   darwin-vmnet-drift.sh <label> <plist-path> [--launchctl-output FILE]
#
# --launchctl-output FILE reads `launchctl print` output from FILE instead of
# invoking launchctl, so the comparison can be tested against fixtures on a host
# where nothing is loaded.
#
# Exit codes:
#   0  in sync — the loaded argv equals the plist's ProgramArguments
#   3  drift — they differ (a unified-ish diff is written to stderr)
#   4  not loaded — no such job in the system domain
#   1  error — bad usage, missing plist, or unparseable launchctl output

set -eu

_usage() {
    echo "usage: $0 <label> <plist-path> [--launchctl-output FILE]" >&2
    exit 1
}

[ "$#" -ge 2 ] || _usage
_label="$1"
_plist="$2"
shift 2

_launchctl_output=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --launchctl-output)
            [ "$#" -ge 2 ] || _usage
            _launchctl_output="$2"
            shift 2
            ;;
        *) _usage ;;
    esac
done

if [ ! -f "$_plist" ]; then
    echo "darwin-vmnet-drift: plist not found: $_plist" >&2
    exit 1
fi

_tmpdir=$(mktemp -d -t darwin-vmnet-drift) || exit 1
# shellcheck disable=SC2064  # expand _tmpdir now, not at trap time
trap "rm -rf '$_tmpdir'" EXIT INT TERM

_disk="$_tmpdir/disk"
_loaded="$_tmpdir/loaded"

# --- argv as the plist on disk declares it ---------------------------------
#
# One argument per line, in order. Walk ProgramArguments.<i> until plutil says
# there is no such index; the cap keeps a malformed plist from looping.
: > "$_disk"
_i=0
while [ "$_i" -lt 64 ]; do
    if _arg=$(plutil -extract "ProgramArguments.$_i" raw -o - "$_plist" 2>/dev/null); then
        printf '%s\n' "$_arg" >> "$_disk"
        _i=$((_i + 1))
    else
        break
    fi
done
if [ "$_i" -eq 0 ]; then
    echo "darwin-vmnet-drift: $_plist has no ProgramArguments array" >&2
    exit 1
fi

# --- argv as launchd is actually running it --------------------------------
#
# `launchctl print system/<label>` renders the in-memory job. The argv lives in
# an `arguments = { ... }` block, one tab-indented entry per line. The closing
# brace is matched only when it is alone on its line: our own argv contains a
# `}` (the codesign guard's `|| { ...; exit 1; }`), so a looser match would
# truncate the block mid-argument.
if [ -n "$_launchctl_output" ]; then
    [ -f "$_launchctl_output" ] || {
        echo "darwin-vmnet-drift: launchctl output file not found: $_launchctl_output" >&2
        exit 1
    }
    cp "$_launchctl_output" "$_tmpdir/print"
else
    if ! launchctl print "system/$_label" > "$_tmpdir/print" 2>/dev/null; then
        exit 4
    fi
fi

awk '
    /^[[:space:]]*arguments = \{[[:space:]]*$/ { in_args = 1; next }
    in_args && /^[[:space:]]*\}[[:space:]]*$/  { in_args = 0; next }
    in_args                                    { sub(/^[\t ]+/, ""); print; seen = 1 }
    END                                        { exit(seen ? 0 : 1) }
' "$_tmpdir/print" > "$_loaded" || {
    echo "darwin-vmnet-drift: no arguments block in launchctl print output for $_label" >&2
    exit 1
}

if cmp -s "$_disk" "$_loaded"; then
    exit 0
fi

echo "darwin-vmnet-drift: $_label is running a definition that no longer matches $_plist" >&2
echo "  loaded (in launchd's memory):" >&2
sed 's/^/    /' "$_loaded" >&2
echo "  on disk (what the next bootstrap would use):" >&2
sed 's/^/    /' "$_disk" >&2
exit 3
