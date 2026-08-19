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

# normalize_caps — stdin → stdout filter reducing a capability string to a
# canonical, ORDER-INDEPENDENT form, so the install guard below compares
# capability SETS rather than spellings. Same filter as the Makefile's
# NORMALIZE_CAPS, which the cap'd test-path installs use for the same reason.
#
# Why a set compare and not a substring test: `getcap` prints capability names
# in kernel numeric order, not the order `setcap` received them, and older
# libcap spells a clause `<path> = cap_setuid+ep` where newer prints
# `<path> cap_setuid=ep`. A substring test therefore accepts a strict SUPERSET
# — `cap_chown,cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip` contains the
# expected `cap_net_admin,cap_sys_ptrace,cap_sys_admin=eip` verbatim — so an
# over-capped binary was reported as already configured and never brought back
# down to the intended set. Narrowing an over-capped helper is precisely what
# this installer exists to do, so that answer has to be wrong.
#
# How: drop the leading path field `getcap` prints, split the rest on every
# separator libcap uses (space between clauses, `,` between names, `=`/`+`
# before the flag letters), drop empties, sort, rejoin. Both operands go
# through it, so only the token multiset is compared.
#
# It stays strict in the direction that matters — a wrongly-capped binary must
# NOT be reported as current, because that defers the failure to an opaque
# EPERM at run time:
#   - the flag letters survive as their own token, so `=ep` never matches
#     `=eip`;
#   - nothing is de-duplicated (plain `sort`, not `sort -u`), so an extra
#     capability adds a token and fails;
#   - a missing capability removes one and fails;
#   - clauses beyond the first are kept rather than discarded, so an extra
#     capability carrying *different* flags (which libcap emits as a separate
#     clause) also fails;
#   - an uncapped or absent binary yields no capability names at all, so it
#     cannot normalize to the non-empty expected set.
#
# `LC_ALL=C` pins the collation so the sort order cannot drift with the
# operator's locale. The leading-path strip requires a space to match, which
# makes the filter a no-op on a bare expected literal — so expected literals
# passed to this script must stay single-clause and space-free (both cap'd
# call sites are).
normalize_caps() {
    sed 's|^[^ ]* ||' | tr ' ,=+' '\n\n\n\n' | sed '/^$/d' | LC_ALL=C sort | tr '\n' ','
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
    #
    # The capability side compares SETS via normalize_caps (see above), never
    # substrings. Callers that declare no expected caps (the guest binary, which
    # carries none and gets no `setcap`) short-circuit before `getcap` is
    # reached, so this stays runnable on a host that has no `getcap` at all.
    need_install=1
    if [ -e "$canonical" ] && cmp -s "$built" "$canonical"; then
        if [ -z "$expected_getcap" ]; then
            need_install=0
        else
            expected_norm=$(printf '%s\n' "$expected_getcap" | normalize_caps)
            current_caps=$(getcap "$canonical" 2>/dev/null || true)
            current_norm=$(printf '%s\n' "$current_caps" | normalize_caps)
            if [ "$current_norm" = "$expected_norm" ]; then
                need_install=0
            fi
        fi
    fi
    if [ "$need_install" = 1 ]; then
        # Create the parent directory if it does not exist. GNU `install -D`
        # does this automatically, but BSD `install` (macOS) treats `-D` as a
        # destdir prefix flag (different meaning) and does NOT create parent
        # dirs. Explicit `mkdir -p` is portable to both. Guard with a no-op
        # test so a warm re-run never invokes sudo for this step.
        if [ ! -d "$(dirname "$canonical")" ]; then
            echo "[sudo] mkdir -p $(dirname "$canonical")"
            sudo mkdir -p "$(dirname "$canonical")"
        fi
        echo "[sudo] install -m $mode $built $canonical"
        sudo -k install -m "$mode" "$built" "$canonical"
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
