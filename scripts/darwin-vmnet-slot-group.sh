#!/bin/sh
# darwin-vmnet-slot-group.sh — which group owns a socket_vmnet pool slot.
#
# Usage:  darwin-vmnet-slot-group.sh <slot> <fallback-group>
#
# Prints the group name a slot socket must carry, so the plist emitters can
# put it in `--socket-group=`. That group is the entire admission control for
# the slot's L2 segment: anyone in it can attach a VM, be believed as the next
# hop by every guest already there, and terminate their TLS. A single shared
# group across all slots therefore places every enrolled operator on every
# other operator's segment, with nothing in the daemon or the deny-event
# stream showing it. One group per operator is what makes the partition real.
#
# Answers from the per-operator group records only — never from the socket's
# current gid. Those are two different questions: the gid says what the host
# is enforcing today, the records say what it should be. Reading the gid here
# would perpetuate whatever the sockets already carry, and a host could never
# be migrated off the shared group.
#
# Outcomes:
#   exactly one group records the slot -> print it, exit 0
#   no group records the slot          -> print <fallback-group>, exit 0
#   more than one records it           -> diagnose on stderr, exit 2
#
# The no-group case is every host that has not been migrated yet, so it falls
# back rather than refusing — an upgrade must not become an outage. The
# contested case refuses rather than picking: the candidates are
# indistinguishable from here, one of them is a half-finished de-enrollment,
# and emitting either silently hands an operator a segment that is not theirs.
#
# A copy of the resolver below is inlined in scripts/install.sh, which is
# delivered by `curl | bash` and so has no adjacent script to call. The two
# are kept byte-identical by scripts/check-vmnet-uuid-equivalence.py.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <slot> <fallback-group>" >&2
    exit 64
fi

# --- resolver (mirrored in scripts/install.sh) ---
_sandboxd_slot_group() {
    _sg_slot="$1"
    _sg_fallback="$2"
    _sg_found=""
    _sg_n=0
    for _sg_g in $(dscl . -list /Groups 2>/dev/null | awk '/^_sandboxd-op-/{print $1}'); do
        _sg_range=$(dscl . -read "/Groups/$_sg_g" SandboxdSlots 2>/dev/null | awk '/^dsAttrTypeNative:SandboxdSlots: /{print $2}')
        [ -n "$_sg_range" ] || continue
        echo "$_sg_range" | awk -v s="$_sg_slot" 'BEGIN{RS=","} {n=split($0,p,"-"); lo=p[1]+0; hi=(n>1?p[2]+0:lo); if (lo<=s && s<=hi) f=1} END{exit !f}' || continue
        _sg_found="${_sg_found:+$_sg_found, }$_sg_g"
        _sg_n=$((_sg_n + 1))
    done
    if [ "$_sg_n" -gt 1 ]; then
        echo "slot $_sg_slot is recorded by more than one per-operator group ($_sg_found); refusing to pick one" >&2
        return 2
    fi
    if [ "$_sg_n" -eq 1 ]; then echo "$_sg_found"; else echo "$_sg_fallback"; fi
}
# --- end resolver ---

_sandboxd_slot_group "$1" "$2"
