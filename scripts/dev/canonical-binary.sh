#!/usr/bin/env bash
#
# canonical-binary.sh — manage a privileged helper/guest binary at the
# canonical /usr/local/libexec/sandboxd/ path that is SHARED between this
# workspace's dev-env (`make setup-dev-env`) and a co-resident production
# install (`scripts/install.sh`).
#
# dev-env time-shares the canonical path instead of using a separate one, so
# the e2e suite exercises the real binaries at the real paths. To avoid
# destroying a co-resident prod install's binaries, dev-env STASHES a
# prod-installed binary as `<canonical>.prod` before installing the dev build,
# and `make clean` RESTORES it.
#
# Restore is decided by mtime (see `restore` below): `make clean` restores the
# stash only if it is newer-or-equal than the current canonical binary. A
# *fresh* prod install (install.sh / `sandbox update`) that ran after dev-env
# bumps the canonical mtime past the stash, signalling "a newer prod binary is
# here" — clean then keeps it and discards the stale stash rather than
# downgrading the install.
#
#   >>> This depends on every prod-install path setting a FRESH mtime on the
#   >>> installed binary (install(1) without -p; no tar -p; no mtime
#   >>> preservation). That invariant is asserted in scripts/install.sh and
#   >>> sandbox-cli's update path. If a future change starts preserving source
#   >>> mtimes, this restore logic can silently downgrade a prod install.
#
# Usage:
#   canonical-binary.sh install <built> <canonical> <mode> [setcap-args] [expected-getcap]
#   canonical-binary.sh restore <canonical>
#
set -euo pipefail

# A prod install is present iff install.sh has laid down the systemd unit.
# World-readable (0644), created at install.sh step 21, removed by uninstall.sh
# — a reliable, permission-clean marker (unlike .install-state.json at 0640 in
# a 0750 dir, which needs sandbox-group traversal to even stat).
# Overridable only so the unit test can point it at a stand-in; production
# make recipes never set it. Not a privilege boundary — this script is not
# setuid and runs as the operator, who already controls their own env.
PROD_MARKER=${PROD_MARKER:-/etc/systemd/system/sandboxd.service}

usage() {
    echo "usage: $0 install <built> <canonical> <mode> [setcap-args] [expected-getcap]" >&2
    echo "       $0 restore <canonical>" >&2
    exit 2
}

cmd=${1:-}
case "$cmd" in
install)
    built=${2:?built binary path required}
    canonical=${3:?canonical path required}
    mode=${4:?mode required}
    setcap_args=${5:-}
    expected_getcap=${6:-}
    stash="$canonical.prod"

    # Never swap binaries under a running prod daemon — it resolves the
    # canonical path and would start invoking the dev build mid-flight.
    if systemctl is-active --quiet sandboxd 2>/dev/null; then
        echo "ERROR: the 'sandboxd' service is active; stop it before dev-env swaps $canonical:" >&2
        echo "         sudo systemctl stop sandboxd" >&2
        exit 1
    fi

    # Stash a co-resident prod binary the FIRST time dev-env runs after a prod
    # install (guarded on 'no stash yet' so repeated dev-env runs never
    # overwrite the saved prod copy with a dev binary). `mv` preserves the
    # file's capability xattr and original mtime.
    if [ -e "$PROD_MARKER" ] && [ ! -e "$stash" ] && [ -e "$canonical" ]; then
        echo "[sudo] mv $canonical $stash  (preserving prod-installed binary across dev-env)"
        sudo -k mv "$canonical" "$stash"
    fi

    # Install the dev build, skipping the sudo when canonical is already
    # byte-identical AND carries the expected caps — preserves the
    # "no-op ⇒ no sudo" property on a pure dev host (no stash present).
    need_install=1
    if [ -e "$canonical" ] && cmp -s "$built" "$canonical"; then
        if [ -z "$expected_getcap" ] || getcap "$canonical" 2>/dev/null | grep -qF "$expected_getcap"; then
            need_install=0
        fi
    fi
    if [ "$need_install" = 1 ]; then
        echo "[sudo] install -D -m $mode $built $canonical"
        sudo -k install -D -m "$mode" "$built" "$canonical"
        if [ -n "$setcap_args" ]; then
            echo "[sudo] setcap $setcap_args $canonical"
            sudo -k setcap "$setcap_args" "$canonical"
        fi
    else
        echo "✓ already configured: $canonical (content matches build${expected_getcap:+, $expected_getcap})"
    fi

    # Rule 1: keep the stash mtime ≥ canonical mtime on EVERY run (not only the
    # run that stashed), so clean's timestamp test below sees the stash as
    # "ours" until a fresh prod install bumps canonical past it. Touch AFTER
    # the install so the stash is at least as new as canonical.
    if [ -e "$stash" ]; then
        echo "[sudo] touch $stash  (keep stash ≥ canonical for clean-restore)"
        sudo -k touch "$stash"
    fi
    ;;

restore)
    canonical=${2:?canonical path required}
    stash="$canonical.prod"
    [ -e "$stash" ] || exit 0  # nothing stashed → nothing to do

    # Restore iff the stash is newer-or-equal than canonical (i.e. canonical is
    # NOT strictly newer). `test -nt` is strict and treats a missing canonical
    # as "not newer", so a canonical that was removed (uninstall) also restores.
    # If canonical IS strictly newer, a fresh prod install superseded our stash
    # after dev-env ran — keep it, drop the stale stash. Either branch clears
    # the stash (Rule 2), so the next dev-env run re-stashes cleanly.
    if ! [ "$canonical" -nt "$stash" ]; then
        echo "[sudo] mv $stash $canonical  (restoring stashed prod binary)"
        sudo -k mv "$stash" "$canonical"
    else
        echo "[sudo] rm $stash  (canonical is a newer prod install; discarding stale stash)"
        sudo -k rm -f "$stash"
    fi
    ;;

*)
    usage
    ;;
esac
