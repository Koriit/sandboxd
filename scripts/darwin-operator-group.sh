#!/bin/sh
# darwin-operator-group.sh — enroll and de-enroll a macOS operator's vmnet slot range.
#
# Every vmnet slot socket is guarded by one Unix group, and every enrolled
# operator is in it. A slot socket is the entire admission control for its L2
# segment: anything that can connect(2) to slot-N.sock becomes a peer on
# segment N, addressable to the victim's sandbox VM and its gateway container.
# One shared group therefore means any enrolled operator can place themselves
# on any other operator's segment and be believed as that segment's next hop —
# the victim's egress policy is void and nothing in the daemon, the session or
# the deny-event stream reflects it.
#
# The fix is a socket group naming only the owning operator, so the kernel
# refuses a connect from anyone else. It ships in two halves because they are
# not independently safe:
#
#   1. Create the per-operator group and assign its slot range  <- this script.
#   2. Point the slot plists at those groups.                   <- later.
#
# Half 2 cannot land yet. The daemon's own gateway VM holds a NIC on *every*
# slot and is started as the daemon uid, so moving the sockets before VM
# ownership flips stops the only gateway VM there is. Until then the sockets
# keep the legacy shared group, and what this script writes is an assignment
# record and an audit surface — NOT an access control. Nothing here moves a
# socket, rewrites a plist, or changes what any host enforces today.
#
# De-enrollment ships with enrollment rather than after it, because reclaiming
# a range without revoking the departing operator's membership recreates the
# defect exactly: the new owner is given the slots, the old owner keeps group
# membership and therefore socket access, and nothing at any layer detects it.
# So revocation strictly precedes reassignment, and this script enforces that
# ordering rather than documenting it — see `deenroll` below.
#
# Usage:
#   darwin-operator-group.sh enroll   --operator NAME [--slots RANGE]
#   darwin-operator-group.sh deenroll --operator NAME [--keep-daemon-access] [--force]
#   darwin-operator-group.sh status   [--operator NAME]
#   darwin-operator-group.sh group-name --operator NAME
#   darwin-operator-group.sh parse-range RANGE
#   darwin-operator-group.sh check-holder UID
#
# check-holder answers the one question de-enrollment can fail on, on its own
# and without mutating anything: does a live process of UID still hold a slot
# socket? It takes a uid rather than a name because that is what identifies a
# process's owner, and because it is the number a refused de-enrollment has
# just printed. Run it after stopping what was holding the slot to confirm the
# sequence can be resumed.
#
# Common options:
#   --dry-run          print the ordered plan; change nothing. Implied by --state-file.
#   --pool-size N      slot count (default: the installed io.sandboxd.vmnet.* plists).
#   --state-file FILE  read host state from a fixture instead of Directory Services.
#                      Forces --dry-run, so the logic is testable with no host state,
#                      no sudo, and no possibility of a mutation. See FIXTURE FORMAT.
#   --socket-dir DIR   where the slot sockets live. check-holder only: a de-enrollment
#                      allowed to aim its residue check at an empty directory would
#                      answer "no holder" for a pool it never looked at, which is the
#                      failure this check exists to prevent.
#
# enroll and deenroll mutate the host and must run as root (via sudo). Both are
# idempotent: a second run of either is a no-op, not an error and not a duplicate.
#
# Exit codes:
#   0  success (or nothing to do)
#   1  usage or environment error
#   2  refused: validation failed (unknown operator, service account, bad range)
#   3  refused: the requested range is held by another operator
#   4  refused: fail-closed — a slot group's membership makes it unassignable
#   5  refused: a live process still holds a slot socket after revocation
#   6  refused: the residue check could not observe the pool, so it certified
#      nothing. Distinct from 5 because the remedy differs — 5 means stop the
#      process, 6 means look from somewhere the pool is visible.
#
# FIXTURE FORMAT (--state-file), one directive per line, '#' starts a comment:
#   pool-size N
#   user NAME UID
#   group NAME GID SLOTS MEMBERS      # SLOTS and MEMBERS use '-' for empty;
#                                     # MEMBERS is comma-separated
#   slot-holder UID                   # a live process of UID holds a slot socket

set -eu

# The daemon account. It is a member of every per-operator group by design —
# see _enroll for why omitting it breaks every operator's sessions, not just
# the daemon's own. Declared here rather than shared with network.rs or the
# Makefile because this script is also copied into standalone contexts;
# scripts/check-vmnet-uuid-equivalence.py is what keeps the copies honest.
SANDBOXD_ACCT="_sandboxd"

# Accounts that are members of these groups by design and are not operators.
# An explicit list, deliberately not a name prefix: prefix matching would
# silently absorb a future real operator whose name happens to start with an
# underscore, and the count below is what decides whether a slot is assignable.
SERVICE_ACCOUNTS="_sandboxd _sandboxd-test"

# Groups this script must never create, edit or delete. _sandbox (gid 60) is
# Apple's reserved Seatbelt group and merely shares a prefix with ours;
# _sandboxd is the shared daemon group that gates the daemon socket, and
# operators must stay in it rather than be moved out of it.
RESERVED_GROUPS="_sandbox _sandboxd _sandboxd-test staff wheel admin everyone"

# Prefix for per-operator socket groups. The 'op-' infix is load-bearing: it
# keeps a per-operator group for an operator named 'test' from colliding with
# the _sandboxd-test service group.
GROUP_PREFIX="_sandboxd-op-"

# Native dscl attribute on the per-operator group record holding its slot
# range. The group record is where the range belongs: it is root-owned, it is
# the same store that holds the membership the range is meaningless without,
# and `dscl . -read /Groups/<opgroup>` then answers assignment and membership
# together. From the phase that moves the sockets, `ls -l` on the socket
# directory answers it too, and the two must agree.
SLOTS_ATTR="SandboxdSlots"

# Below this uid an account is a system account. The daemon's own accept-time
# gate rejects a peer uid strictly below it, so an account under the floor
# would never be treated as an operator however it is enrolled here.
SYSTEM_UID_FLOOR=500

VMNET_SOCKET_DIR="/var/run/sandbox/vmnet"
LAUNCH_DAEMONS_DIR="/Library/LaunchDaemons"

DRY_RUN=0
STATE_FILE=""
POOL_SIZE=""
STEP_NO=0

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------

_err() { echo "darwin-operator-group: $*" >&2; }

_usage() {
    cat >&2 <<'USAGE'
usage:
  darwin-operator-group.sh enroll   --operator NAME [--slots RANGE]
  darwin-operator-group.sh deenroll --operator NAME [--keep-daemon-access] [--force]
  darwin-operator-group.sh status   [--operator NAME]
  darwin-operator-group.sh group-name --operator NAME
  darwin-operator-group.sh parse-range RANGE
  darwin-operator-group.sh check-holder UID

  --dry-run          print the ordered plan; change nothing
  --pool-size N      slot count (default: the installed io.sandboxd.vmnet.* plists)
  --state-file FILE  read host state from a fixture instead of Directory Services
  --socket-dir DIR   where the slot sockets live (check-holder only)
                     (forces --dry-run)
USAGE
    exit 1
}

# Every step a run would take is printed, in order, whether or not it runs.
# A dry run and a live run emit the same lines, so the ordering this script
# guarantees is observable from its output rather than from reading it.
_step() {
    STEP_NO=$((STEP_NO + 1))
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'STEP %d %s %s (dry-run)\n' "$STEP_NO" "$1" "${2-}"
    else
        printf 'STEP %d %s %s\n' "$STEP_NO" "$1" "${2-}"
    fi
}

# ---------------------------------------------------------------------------
# fixture-backed state
# ---------------------------------------------------------------------------

_fixture_lines() {
    # shellcheck disable=SC2002  # cat keeps the read side uniform for callers
    cat "$STATE_FILE" | sed 's/#.*//' | grep -v '^[[:space:]]*$'
}

_fixture_field() {
    # _fixture_field <directive> <key> <field-index>
    _fixture_lines | awk -v d="$1" -v k="$2" -v f="$3" \
        '$1 == d && $2 == k { print $f; found = 1 } END { exit(found ? 0 : 1) }'
}

# ---------------------------------------------------------------------------
# host queries — each one answers from the fixture when one is supplied
# ---------------------------------------------------------------------------

_user_uid() {
    # echoes the uid, or fails if the account does not resolve
    if [ -n "$STATE_FILE" ]; then
        _fixture_field user "$1" 3
    else
        id -u "$1" 2>/dev/null
    fi
}

_group_exists() {
    if [ -n "$STATE_FILE" ]; then
        _fixture_field group "$1" 2 >/dev/null
    else
        dscl . -read "/Groups/$1" >/dev/null 2>&1
    fi
}

# All per-operator groups on the host, one per line.
_op_groups() {
    if [ -n "$STATE_FILE" ]; then
        _fixture_lines | awk '$1 == "group" { print $2 }'
    else
        dscl . -list /Groups 2>/dev/null || true
    fi | grep "^${GROUP_PREFIX}" || true
}

# The slot range recorded on a group, or empty.
#
# `dscl . -read <record> <key>` prints "No such key: <key>" and STILL EXITS 0
# when the attribute is absent, so the exit status cannot be used to detect it.
# A multi-word value is also wrapped onto continuation lines that begin with a
# space, which is why this is a parse rather than a cut.
_group_slots() {
    if [ -n "$STATE_FILE" ]; then
        _val=$(_fixture_field group "$1" 4 || true)
        if [ "$_val" = "-" ]; then _val=""; fi
        printf '%s' "$_val"
        return 0
    fi
    _out=$(dscl . -read "/Groups/$1" "$SLOTS_ATTR" 2>/dev/null || true)
    case "$_out" in
        "No such key"*|"") return 0 ;;
    esac
    # A native attribute reads back as "dsAttrTypeNative:<key>: <value>", so the
    # key runs to the LAST colon before the first space — stripping to the first
    # colon leaves "<key>: <value>" behind and silently compares unequal.
    printf '%s' "$_out" | awk '
        NR == 1 { sub(/^[^ ]*:[[:space:]]*/, ""); printf "%s", $0; next }
                { sub(/^[[:space:]]+/, ""); printf "%s", $0 }
    '
}

# Short names of a group's members, space-separated.
_group_members() {
    if [ -n "$STATE_FILE" ]; then
        _val=$(_fixture_field group "$1" 5 || true)
        if [ "$_val" = "-" ]; then _val=""; fi
        printf '%s' "$_val" | tr ',' ' '
        return 0
    fi
    _out=$(dscl . -read "/Groups/$1" GroupMembership 2>/dev/null || true)
    case "$_out" in
        "No such key"*|"") return 0 ;;
    esac
    printf '%s' "$_out" | awk '
        NR == 1 { sub(/^[^ ]*:[[:space:]]*/, ""); printf "%s ", $0; next }
                { sub(/^[[:space:]]+/, ""); printf "%s ", $0 }
    '
}

_is_member() {
    # _is_member <user> <group>
    if [ -n "$STATE_FILE" ]; then
        for _m in $(_group_members "$2"); do
            if [ "$_m" = "$1" ]; then return 0; fi
        done
        return 1
    fi
    dseditgroup -o checkmember -m "$1" "$2" >/dev/null 2>&1
}

_is_service_account() {
    for _s in $SERVICE_ACCOUNTS; do
        if [ "$_s" = "$1" ]; then return 0; fi
    done
    return 1
}

# Operator members of a group — its total membership minus the service
# accounts that are in it by design. This count is what decides assignability.
_operator_members() {
    _out=""
    for _m in $(_group_members "$1"); do
        if ! _is_service_account "$_m"; then
            _out="${_out:+$_out }$_m"
        fi
    done
    printf '%s' "$_out"
}

_pool_size() {
    if [ -n "$POOL_SIZE" ]; then
        printf '%s' "$POOL_SIZE"
        return 0
    fi
    if [ -n "$STATE_FILE" ]; then
        _n=$(_fixture_lines | awk '$1 == "pool-size" { print $2 }' | head -n 1)
        printf '%s' "${_n:-8}"
        return 0
    fi
    _n=$(find "$LAUNCH_DAEMONS_DIR" -maxdepth 1 -name 'io.sandboxd.vmnet.*.plist' 2>/dev/null | wc -l | tr -d ' ')
    printf '%s' "$_n"
}

# ---------------------------------------------------------------------------
# names and ranges
# ---------------------------------------------------------------------------

_group_name_for() {
    printf '%s%s' "$GROUP_PREFIX" "$1"
}

_reject_reserved_group() {
    for _r in $RESERVED_GROUPS; do
        if [ "$_r" = "$1" ]; then
            _err "refusing to touch reserved group '$1'."
            exit 2
        fi
    done
}

# Expand "0-3,6" to "0 1 2 3 6" — sorted, deduplicated, every element checked.
#
# The trailing newline is not cosmetic: `read` returns non-zero when it reaches
# EOF without a delimiter, so a final comma-separated element with no newline
# after it is silently dropped from the loop.
_range_expand() {
    printf '%s\n' "$1" | tr ',' '\n' | while IFS= read -r _part; do
        [ -n "$_part" ] || continue
        case "$_part" in
            *-*)
                _lo=${_part%%-*}
                _hi=${_part#*-}
                ;;
            *)
                _lo=$_part
                _hi=$_part
                ;;
        esac
        # Both ends are checked separately: "0-" leaves _hi empty, which passes
        # a combined digits-only test and then fails inside the arithmetic
        # comparison with a shell error instead of a refusal.
        case "$_lo" in ''|*[!0-9]*) echo "BAD"; return 0 ;; esac
        case "$_hi" in ''|*[!0-9]*) echo "BAD"; return 0 ;; esac
        if [ "$_lo" -gt "$_hi" ]; then
            echo "BAD"
            return 0
        fi
        _i=$_lo
        while [ "$_i" -le "$_hi" ]; do
            echo "$_i"
            _i=$((_i + 1))
        done
    done | sort -n -u
}

# Canonicalize a range: merge adjacent slots back into "lo-hi" runs so that
# "3,0,1,2" and "0-3" produce the same string and an unchanged assignment
# compares equal on a re-run.
_range_canon() {
    _slots=$(_range_expand "$1")
    case "$_slots" in
        *BAD*|"") return 1 ;;
    esac
    printf '%s\n' "$_slots" | awk '
        NR == 1 { lo = $1; prev = $1; next }
        $1 == prev + 1 { prev = $1; next }
        { printf "%s%s", (out++ ? "," : ""), (lo == prev ? lo : lo "-" prev); lo = $1; prev = $1 }
        END { printf "%s%s", (out++ ? "," : ""), (lo == prev ? lo : lo "-" prev) }
    '
}

_ranges_overlap() {
    # _ranges_overlap <range-a> <range-b>; 0 when they share a slot
    _a=$(_range_expand "$1")
    _b=$(_range_expand "$2")
    for _x in $_a; do
        for _y in $_b; do
            if [ "$_x" = "$_y" ]; then return 0; fi
        done
    done
    return 1
}

# ---------------------------------------------------------------------------
# mutations — every one routes through here so a dry run cannot mutate
# ---------------------------------------------------------------------------

_run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    "$@"
}

_require_root() {
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        _err "must run as root. Re-run with sudo:"
        _err "  sudo $0 $*"
        exit 1
    fi
}

_require_darwin() {
    if [ "$(uname -s)" != "Darwin" ]; then
        _err "macOS only — vmnet slot sockets and Directory Services do not exist here."
        exit 1
    fi
}

_next_free_gid() {
    # Next free gid at or above 300, skipping 60 (Apple's reserved _sandbox).
    # Mirrors the selection install.sh and the Makefile use for their groups.
    if [ -n "$STATE_FILE" ]; then
        printf '%s' "$(_fixture_lines | awk '$1 == "group" { print $3 }' | sort -n \
            | awk 'BEGIN{gid=300} {if ($1==gid){gid++}; if (gid==60){gid++}} END{print gid}')"
        return 0
    fi
    dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}' | sort -n \
        | awk 'BEGIN{gid=300} {if ($1==gid){gid++}; if (gid==60){gid++}} END{print gid}'
}

# ---------------------------------------------------------------------------
# shared validation
# ---------------------------------------------------------------------------

_resolve_operator() {
    # sets OPERATOR_UID; refuses anything that is not a real operator account
    if [ -z "${OPERATOR:-}" ]; then
        _err "--operator is required."
        exit 1
    fi
    case "$OPERATOR" in
        ''|*[!A-Za-z0-9._-]*|-*)
            _err "operator name '$OPERATOR' is not a plain account name."
            exit 2
            ;;
    esac
    if _is_service_account "$OPERATOR"; then
        _err "'$OPERATOR' is a service account, not an operator."
        _err "  Service accounts are members of these groups by design and are never assigned a range."
        exit 2
    fi
    OPERATOR_UID=$(_user_uid "$OPERATOR" || true)
    if [ -z "$OPERATOR_UID" ]; then
        _err "no such account: '$OPERATOR'."
        exit 2
    fi
    if [ "$OPERATOR_UID" -lt "$SYSTEM_UID_FLOOR" ]; then
        _err "'$OPERATOR' has uid $OPERATOR_UID, below the system uid floor ($SYSTEM_UID_FLOOR)."
        _err "  The daemon rejects a peer uid below the floor, so this account could never act"
        _err "  as an operator however it is enrolled here."
        exit 2
    fi
    OP_GROUP=$(_group_name_for "$OPERATOR")
    _reject_reserved_group "$OP_GROUP"
}

# Every slot already spoken for, and by whom. A group whose membership makes
# it unassignable is reported rather than resolved — see _enroll.
_assigned_ranges() {
    for _g in $(_op_groups); do
        _slots=$(_group_slots "$_g")
        [ -n "$_slots" ] || continue
        printf '%s %s\n' "$_g" "$_slots"
    done
}

# ---------------------------------------------------------------------------
# enroll
# ---------------------------------------------------------------------------

_enroll() {
    _resolve_operator

    _pool=$(_pool_size)
    if [ "$_pool" -eq 0 ]; then
        _err "no vmnet slots on this host — $LAUNCH_DAEMONS_DIR holds no io.sandboxd.vmnet.*.plist."
        _err "  Provision the pool first, or pass --pool-size to plan against a host that has one."
        exit 1
    fi

    # A group carrying more than one operator is the defect in miniature: two
    # operators would share one segment. It is left unassignable on purpose —
    # picking the newer one is exactly the "fix" that hides a half-done
    # de-enrollment, so this refuses and says which group.
    for _g in $(_op_groups); do
        _ops=$(_operator_members "$_g")
        _n=$(printf '%s' "$_ops" | wc -w | tr -d ' ')
        if [ "$_n" -gt 1 ]; then
            _err "group '$_g' has $_n operator members ($_ops) — its range is unassignable."
            _err "  Two operators in one slot group share a segment. This is the state a"
            _err "  half-done de-enrollment leaves behind; it surfaces as lost capacity"
            _err "  rather than as silent shared access, and must be resolved by"
            _err "  de-enrolling the departing operator, not by choosing between them."
            exit 4
        fi
    done

    _current=""
    if _group_exists "$OP_GROUP"; then
        _current=$(_group_slots "$OP_GROUP")
    fi

    # Default: the whole pool. A single-operator host must keep exactly the
    # concurrency it has today — partitioning a pool nobody else is using
    # would be a straight regression. With another operator already holding
    # slots there is no safe default, and no automatic rebalancing: the range
    # has to be stated.
    if [ -z "${SLOTS:-}" ]; then
        if [ -n "$_current" ]; then
            SLOTS="$_current"
        else
            _held=""
            for _g in $(_op_groups); do
                if [ "$_g" = "$OP_GROUP" ]; then continue; fi
                _s=$(_group_slots "$_g")
                if [ -n "$_s" ]; then _held="${_held:+$_held,}$_s"; fi
            done
            if [ -n "$_held" ]; then
                _err "another operator already holds slots ($_held) — pass --slots explicitly."
                _err "  Multi-operator enrollment is deliberate, privileged work: there is no"
                _err "  automatic rebalancing and no bouncing of an existing operator's VM."
                exit 3
            fi
            SLOTS="0-$((_pool - 1))"
        fi
    fi

    _canon=$(_range_canon "$SLOTS" || true)
    if [ -z "$_canon" ]; then
        _err "malformed slot range: '$SLOTS' (expected e.g. 0-7, 4-7, or 0,2,5)."
        exit 2
    fi
    for _s in $(_range_expand "$_canon"); do
        if [ "$_s" -ge "$_pool" ]; then
            _err "slot $_s is outside this host's pool of $_pool (slots 0-$((_pool - 1)))."
            _err "  Growing the pool is privileged installer work, not an enrollment option."
            exit 2
        fi
    done

    # Revocation strictly precedes reassignment, and this is where that is
    # enforced rather than described: a range still recorded against another
    # operator's group cannot be handed out, so the only way to reassign it is
    # to de-enroll its holder first.
    _assigned_ranges | while read -r _g _s; do
        if [ "$_g" = "$OP_GROUP" ]; then continue; fi
        if _ranges_overlap "$_canon" "$_s"; then
            _err "slots '$_canon' overlap '$_s', held by group '$_g'."
            _err "  De-enroll that operator first — reclaiming a range without revoking"
            _err "  their membership would leave them on the segment with nothing detecting it."
            exit 3
        fi
    done || exit 3

    echo "enroll operator=$OPERATOR uid=$OPERATOR_UID group=$OP_GROUP slots=$_canon pool=$_pool"

    # 1. The group exists before anything names it. socket_vmnet refuses to
    #    start when its --socket-group does not resolve (exit 1 at bind, before
    #    vmnet.framework initializes, with no fallback to a default group), so
    #    a plist naming a group that was never created takes the slot down at
    #    the next boot rather than widening it. Creating first is what keeps
    #    that from being reachable.
    if _group_exists "$OP_GROUP"; then
        _step skip-group-exists "$OP_GROUP"
    else
        _gid=$(_next_free_gid)
        _step create-group "$OP_GROUP gid=$_gid"
        _run dscl . -create "/Groups/$OP_GROUP"
        _run dscl . -create "/Groups/$OP_GROUP" PrimaryGroupID "$_gid"
        _run dscl . -create "/Groups/$OP_GROUP" RealName "sandboxd vmnet slots for $OPERATOR"
    fi

    # 2. The operator.
    if _is_member "$OPERATOR" "$OP_GROUP"; then
        _step skip-member-operator "$OPERATOR"
    else
        _step add-member-operator "$OPERATOR"
        _run dseditgroup -o edit -a "$OPERATOR" -t user "$OP_GROUP"
    fi

    # 3. The daemon account, in every per-operator group. This is not a
    #    weakening: the daemon is the principal operators are isolated around,
    #    not from. It is also mandatory. The gateway VM is created and started
    #    as the daemon uid, Lima dials each slot socket itself and hands the fd
    #    to QEMU, and that VM holds a NIC on every slot — so a daemon outside
    #    one operator's group fails `limactl start` at the first socket entry,
    #    and no macOS session of ANY operator can be created or recovered.
    if _is_member "$SANDBOXD_ACCT" "$OP_GROUP"; then
        _step skip-member-daemon "$SANDBOXD_ACCT"
    else
        _step add-member-daemon "$SANDBOXD_ACCT"
        _run dseditgroup -o edit -a "$SANDBOXD_ACCT" -t user "$OP_GROUP"
    fi

    # 4. The operator stays in the shared daemon group. That group gates the
    #    daemon socket itself, and it owns the 0750 socket directory the slot
    #    sockets live in — an operator outside it cannot reach a socket
    #    whatever group the socket carries, because they cannot traverse the
    #    directory. The per-operator group is a SECOND group; enrollment adds
    #    one, it does not move anybody out of the other.
    if _is_member "$OPERATOR" "$SANDBOXD_ACCT"; then
        _step skip-shared-group "$SANDBOXD_ACCT"
    else
        _step add-shared-group "$SANDBOXD_ACCT"
        _run dseditgroup -o edit -a "$OPERATOR" -t user "$SANDBOXD_ACCT"
    fi

    # 5. The range last — it names the group, so it is written only once the
    #    group and its members exist. The guard is what makes that ordering a
    #    property rather than a convention: a range recorded against a group
    #    that does not resolve is what the plists are later generated from, and
    #    socket_vmnet given a nonexistent --socket-group exits 1 at bind before
    #    vmnet.framework initializes, with no fallback to a default group. So
    #    getting this order wrong takes the slot down at the next boot; it does
    #    not widen it. Fail here instead, where the cause is still visible.
    if [ "$DRY_RUN" -eq 0 ] && ! _group_exists "$OP_GROUP"; then
        _err "'$OP_GROUP' does not resolve, so its slot range must not be recorded."
        _err "  Create the group and add its members before anything names it."
        exit 2
    fi
    if [ "$_current" = "$_canon" ]; then
        _step skip-range-current "$_canon"
    else
        _step record-range "$_canon"
        _run dscl . -create "/Groups/$OP_GROUP" "$SLOTS_ATTR" "$_canon"
    fi

    _step verify "$OP_GROUP"
    if [ "$DRY_RUN" -eq 0 ]; then
        _is_member "$OPERATOR" "$OP_GROUP" || {
            _err "'$OPERATOR' is still not a member of '$OP_GROUP' after the add."
            exit 1
        }
        _is_member "$SANDBOXD_ACCT" "$OP_GROUP" || {
            _err "'$SANDBOXD_ACCT' is still not a member of '$OP_GROUP' after the add."
            exit 1
        }
        _is_member "$OPERATOR" "$SANDBOXD_ACCT" || {
            _err "'$OPERATOR' is not a member of the shared group '$SANDBOXD_ACCT'."
            exit 1
        }
        _got=$(_group_slots "$OP_GROUP")
        [ "$_got" = "$_canon" ] || {
            _err "'$OP_GROUP' records slots '$_got', expected '$_canon'."
            exit 1
        }
        _traversal_note
    fi

    echo "enrolled: $OPERATOR holds slots $_canon via group $OP_GROUP"
    echo "note: the slot sockets still carry the shared group. This assignment is"
    echo "      auditable and is not yet enforced by the kernel; enforcement lands"
    echo "      when the slot plists move onto these groups."
}

# The socket directory is 0750 and group-owned by the daemon group. An
# operator's reach depends on that traversal as much as on the socket's own
# group, so a mismatch is worth naming here rather than surfacing later as an
# unexplained EACCES.
_traversal_note() {
    [ -d "$VMNET_SOCKET_DIR" ] || return 0
    _dirgrp=$(stat -f '%Sg' "$VMNET_SOCKET_DIR" 2>/dev/null || true)
    [ -n "$_dirgrp" ] || return 0
    if ! _is_member "$OPERATOR" "$_dirgrp"; then
        _err "warning: '$OPERATOR' is not in '$_dirgrp', which owns $VMNET_SOCKET_DIR (0750)."
        _err "  Without traversal there the socket's own group is irrelevant — the operator"
        _err "  cannot reach the socket at all."
    fi
}

# ---------------------------------------------------------------------------
# deenroll
# ---------------------------------------------------------------------------

_deenroll() {
    _resolve_operator

    if ! _group_exists "$OP_GROUP"; then
        echo "deenroll operator=$OPERATOR group=$OP_GROUP"
        echo "nothing to do: '$OP_GROUP' does not exist"
        return 0
    fi

    # De-enrolling the account driving the run removes its own daemon access
    # and its own slot reach. That is a legitimate thing to want and a very
    # easy thing to do by accident.
    _self="${SUDO_USER:-}"
    if [ -n "$_self" ] && [ "$_self" = "$OPERATOR" ] && [ "${FORCE:-0}" -eq 0 ]; then
        _err "'$OPERATOR' is the account invoking this run — refusing without --force."
        _err "  De-enrolling yourself revokes your own slot access and, unless"
        _err "  --keep-daemon-access is given, your access to the daemon socket."
        exit 2
    fi

    _slots=$(_group_slots "$OP_GROUP")
    echo "deenroll operator=$OPERATOR uid=$OPERATOR_UID group=$OP_GROUP slots=${_slots:-none}"

    # 1. Stop the operator's VMs FIRST, while they are still enrolled. The
    #    daemon can act on them now and cannot once the operator's agent is
    #    gone. This also has to precede revocation for a blunter reason:
    #    revocation does not reach credentials already held. Group membership
    #    is checked at connect(2), not continuously, so a detached QEMU keeps
    #    the fd it already opened and stays on the segment regardless of what
    #    the group says afterwards.
    _step stop-vms "$OPERATOR"
    _stop_operator_vms

    # 2. Revoke membership. Everything after this point is release; nothing
    #    before it is. A run that dies here leaves the operator revoked and the
    #    range still recorded against a group with zero operator members —
    #    unassignable, visible as lost capacity, and never as shared access.
    if _is_member "$OPERATOR" "$OP_GROUP"; then
        _step revoke-slot-group "$OPERATOR from $OP_GROUP"
        _run dseditgroup -o edit -d "$OPERATOR" -t user "$OP_GROUP"
        if [ "$DRY_RUN" -eq 0 ] && _is_member "$OPERATOR" "$OP_GROUP"; then
            _err "'$OPERATOR' is still a member of '$OP_GROUP' after the delete — refusing to continue."
            _err "  Releasing the range now would hand these slots to someone else while"
            _err "  '$OPERATOR' could still reach them."
            exit 1
        fi
    else
        _step skip-revoke-slot-group "$OPERATOR"
    fi

    # 3. Revocation is necessary and not sufficient, so check for the residue
    #    it cannot reach: a still-running VM holding an open fd, or a live
    #    login session carrying the supplementary groups it was granted at
    #    login. Either keeps the departing operator on the segment.
    _step verify-no-live-holder "uid=$OPERATOR_UID"
    _holder_rc=0
    _no_live_slot_holder || _holder_rc=$?
    if [ "$_holder_rc" -eq 2 ]; then
        _err "cannot determine whether uid $OPERATOR_UID still holds a vmnet slot socket."
        _err "  Slot sockets exist under $VMNET_SOCKET_DIR, but no socket_vmnet endpoint"
        _err "  was visible to this process — so a live holder would look identical to an"
        _err "  idle pool. The range is NOT released, because releasing it here would be"
        _err "  certifying an absence that was never observed."
        _err "  Resolve by re-running this command where the socket_vmnet processes are"
        _err "  visible, or probe on its own with:"
        _err "      darwin-operator-group.sh check-holder $OPERATOR_UID"
        exit 6
    fi
    if [ "$_holder_rc" -ne 0 ]; then
        _err "a live process owned by uid $OPERATOR_UID still holds a vmnet slot socket."
        _err "  Membership is checked at connect(2), not continuously, so revoking it did"
        _err "  not evict them. The range is NOT released: it stays recorded against"
        _err "  '$OP_GROUP', which now has no operator member, so it is unassignable and"
        _err "  shows up as lost capacity until this is resolved."
        _err "  Resolve by stopping the process (and having '$OPERATOR' log out, which is"
        _err "  what drops the supplementary groups their session still carries), then"
        _err "  re-run this command."
        exit 5
    fi

    # 4. Release the range. Only now may these slots be given to anyone else.
    _step release-range "${_slots:-none}"
    _run dscl . -delete "/Groups/$OP_GROUP" "$SLOTS_ATTR" >/dev/null 2>&1 || true
    _run dscl . -delete "/Groups/$OP_GROUP"

    # 5. The daemon-socket gate. A departing operator loses it too; a range
    #    reclamation that is not a departure keeps it.
    if [ "${KEEP_DAEMON_ACCESS:-0}" -eq 1 ]; then
        _step keep-shared-group "$SANDBOXD_ACCT"
    elif _is_member "$OPERATOR" "$SANDBOXD_ACCT"; then
        _step revoke-shared-group "$OPERATOR from $SANDBOXD_ACCT"
        _run dseditgroup -o edit -d "$OPERATOR" -t user "$SANDBOXD_ACCT"
    else
        _step skip-revoke-shared-group "$OPERATOR"
    fi

    _step verify "$OP_GROUP"
    if [ "$DRY_RUN" -eq 0 ]; then
        if _group_exists "$OP_GROUP"; then
            _err "'$OP_GROUP' still exists after the delete."
            exit 1
        fi
        if [ "${KEEP_DAEMON_ACCESS:-0}" -eq 0 ] && _is_member "$OPERATOR" "$SANDBOXD_ACCT"; then
            _err "'$OPERATOR' is still a member of '$SANDBOXD_ACCT'."
            exit 1
        fi
    fi

    echo "de-enrolled: $OPERATOR no longer holds slots ${_slots:-none}; group $OP_GROUP removed"
    echo "note: nothing deletes a departed operator's gateway VM. Stopping it is part of"
    echo "      this command; removing it is a deliberate administrative act:"
    echo "        sudo -u $OPERATOR env LIMA_HOME=<their-lima-home> limactl delete --force <instance>"
}

# Stop every Lima instance belonging to the operator. Anything that prevents
# this is a hard failure, deliberately BEFORE revocation: failing here leaves
# the operator fully enrolled, which is the safe direction to fail in.
_stop_operator_vms() {
    if [ -n "$STATE_FILE" ]; then
        return 0
    fi
    _daemon_uid=$(_user_uid "$SANDBOXD_ACCT" || true)
    if [ -z "$_daemon_uid" ]; then
        _err "cannot resolve '$SANDBOXD_ACCT' — unable to locate the operator's LIMA_HOME."
        exit 1
    fi
    # One state root per daemon account, and more than one daemon legitimately
    # runs on a host — the e2e harness account owns a tree beside the
    # production one. An operator can therefore hold VMs under a root that is
    # not this daemon's, and looking only under "$_daemon_uid" would report
    # "no VMs to stop" while they run. Search every root, preferring this
    # daemon's so its tree is reported first.
    _lima_homes=""
    for _root in "/var/lib/sandboxd/$_daemon_uid" /var/lib/sandboxd/*; do
        _candidate="$_root/$OPERATOR_UID/lima"
        [ -d "$_candidate" ] || continue
        case " $_lima_homes " in
            *" $_candidate "*) continue ;;
        esac
        _lima_homes="${_lima_homes:+$_lima_homes }$_candidate"
    done
    if [ -z "$_lima_homes" ]; then
        echo "  no LIMA_HOME for uid $OPERATOR_UID under /var/lib/sandboxd — no VMs to stop"
        return 0
    fi
    if ! command -v limactl >/dev/null 2>&1; then
        _err "limactl is not on PATH, so '$OPERATOR' VMs cannot be stopped."
        _err "  Refusing to continue: a running VM keeps the slot-socket fd it already"
        _err "  opened, and revoking membership would not evict it."
        exit 1
    fi
    for _lima_home in $_lima_homes; do
        for _inst_dir in "$_lima_home"/*/; do
            [ -d "$_inst_dir" ] || continue
            # A LIMA_HOME holds more than instances — "_config" carries the
            # SSH keypair and networks.yaml. The manifest is what makes a
            # directory an instance, so key on it rather than on the name.
            [ -f "$_inst_dir/lima.yaml" ] || continue
            _inst=$(basename "$_inst_dir")
            echo "  stopping VM '$_inst' ($_lima_home)"
            if [ "$DRY_RUN" -eq 0 ]; then
                sudo -u "$OPERATOR" env LIMA_HOME="$_lima_home" limactl stop --force "$_inst" \
                    >/dev/null 2>&1 || true
            fi
        done
    done
}

_no_live_slot_holder() {
    if [ -n "$STATE_FILE" ]; then
        _hits=$(_fixture_lines | awk -v u="$OPERATOR_UID" '$1 == "slot-holder" && $2 == u' | wc -l | tr -d ' ')
        if [ "$_hits" -gt 0 ]; then return 1; fi
        return 0
    fi
    [ -d "$VMNET_SOCKET_DIR" ] || return 0
    command -v lsof >/dev/null 2>&1 || return 0

    # Ask the listener, not the client. The connected end of an AF_UNIX socket
    # carries no path: lsof prints the client's fd as bare "->0x<peer>", so
    # matching a client's own output against a socket path — or against this
    # directory — cannot hit even while that client is attached. Measured on a
    # host where uid 528's QEMU held four slots: the client-side count was 0.
    # socket_vmnet's fds do carry the path, one row per accepted connection,
    # and the address in that row is the endpoint the client peers to. So
    # collect the endpoints from the listener side and look for them among the
    # operator's peer addresses.
    _endpoints=$(lsof -c socket_vmnet 2>/dev/null \
        | awk -v d="$VMNET_SOCKET_DIR/" '$5 == "unix" && index($NF, d) == 1 { print $6 }')

    # Every running slot job holds at least its own listening fd, so seeing no
    # endpoints at all while slot sockets exist means we are looking at a view
    # that cannot show them, not at an idle pool. Absence we cannot see is not
    # absence; refuse rather than certify it.
    if [ -z "$_endpoints" ]; then
        for _sock in "$VMNET_SOCKET_DIR"/slot-*.sock; do
            [ -e "$_sock" ] || continue
            return 2
        done
        return 0
    fi

    _peers=$(lsof -u "$OPERATOR_UID" 2>/dev/null \
        | awk '$5 == "unix" && substr($NF, 1, 2) == "->" { print substr($NF, 3) }')
    for _peer in $_peers; do
        for _endpoint in $_endpoints; do
            if [ "$_peer" = "$_endpoint" ]; then
                return 1
            fi
        done
    done
    return 0
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

_status() {
    _pool=$(_pool_size)
    echo "pool-size $_pool"
    _found=0
    for _g in $(_op_groups); do
        if [ -n "${OPERATOR:-}" ] && [ "$_g" != "$(_group_name_for "$OPERATOR")" ]; then
            continue
        fi
        _found=1
        _slots=$(_group_slots "$_g")
        _ops=$(_operator_members "$_g")
        _n=$(printf '%s' "$_ops" | wc -w | tr -d ' ')
        if [ "$_n" -eq 1 ] && [ -n "$_slots" ]; then
            _state="assigned"
        elif [ "$_n" -eq 1 ]; then
            # A group with an owner but no recorded range answers nothing. The
            # absence must read as a refusal rather than as the whole pool —
            # defaulting here is how a group nobody assigned slots to starts
            # looking like a group that owns all of them.
            _state="unassignable-no-range"
        elif [ "$_n" -eq 0 ]; then
            _state="unassignable-no-operator"
        else
            _state="unassignable-multiple-operators"
        fi
        printf 'group %s slots=%s operators=%s state=%s\n' \
            "$_g" "${_slots:--}" "${_ops:--}" "$_state"
    done
    [ "$_found" -eq 1 ] || echo "no per-operator slot groups on this host"
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

[ "$#" -ge 1 ] || _usage
CMD="$1"
shift

OPERATOR=""
SLOTS=""
FORCE=0
KEEP_DAEMON_ACCESS=0
POSITIONAL=""
SOCKET_DIR_ARG=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --operator) [ "$#" -ge 2 ] || _usage; OPERATOR="$2"; shift 2 ;;
        --slots)    [ "$#" -ge 2 ] || _usage; SLOTS="$2"; shift 2 ;;
        --pool-size) [ "$#" -ge 2 ] || _usage; POOL_SIZE="$2"; shift 2 ;;
        --state-file)
            [ "$#" -ge 2 ] || _usage
            STATE_FILE="$2"
            [ -f "$STATE_FILE" ] || { _err "no such state file: $STATE_FILE"; exit 1; }
            # A fixture describes a host that is not this one. Mutating the
            # real host from it would be nonsense, so this forces a dry run
            # rather than trusting the caller to pass both flags.
            DRY_RUN=1
            shift 2
            ;;
        --socket-dir)
            [ "$#" -ge 2 ] || _usage
            SOCKET_DIR_ARG="$2"
            shift 2
            ;;
        --dry-run)  DRY_RUN=1; shift ;;
        --force)    FORCE=1; shift ;;
        --keep-daemon-access) KEEP_DAEMON_ACCESS=1; shift ;;
        -h|--help)  _usage ;;
        -*)         _err "unknown option: $1"; _usage ;;
        *)          POSITIONAL="$1"; shift ;;
    esac
done

if [ -n "$SOCKET_DIR_ARG" ]; then
    # Deliberately not honoured by enroll or deenroll. Their residue check is
    # the last thing standing between a reclaimed range and silent sharing; a
    # flag that re-aims it at an empty directory would let it answer "no
    # holder" about a pool it never examined.
    [ "$CMD" = "check-holder" ] || {
        _err "--socket-dir applies to check-holder only"
        exit 1
    }
    VMNET_SOCKET_DIR="$SOCKET_DIR_ARG"
fi

case "$CMD" in
    enroll)
        _require_darwin
        _require_root "enroll --operator $OPERATOR"
        _enroll
        ;;
    deenroll)
        _require_darwin
        _require_root "deenroll --operator $OPERATOR"
        _deenroll
        ;;
    status)
        _require_darwin
        _status
        ;;
    group-name)
        [ -n "$OPERATOR" ] || _usage
        _g=$(_group_name_for "$OPERATOR")
        _reject_reserved_group "$_g"
        printf '%s\n' "$_g"
        ;;
    parse-range)
        [ -n "$POSITIONAL" ] || _usage
        _c=$(_range_canon "$POSITIONAL" || true)
        [ -n "$_c" ] || { _err "malformed slot range: '$POSITIONAL'"; exit 2; }
        printf '%s\n' "$_c"
        ;;
    check-holder)
        [ -n "$POSITIONAL" ] || _usage
        case "$POSITIONAL" in
            ''|*[!0-9]*) _err "check-holder takes a uid, not '$POSITIONAL'"; exit 2 ;;
        esac
        OPERATOR_UID="$POSITIONAL"
        _rc=0
        _no_live_slot_holder || _rc=$?
        case "$_rc" in
            0) echo "no live process of uid $OPERATOR_UID holds a slot socket" ;;
            1)
                _err "a live process owned by uid $OPERATOR_UID still holds a vmnet slot socket."
                exit 5
                ;;
            *)
                _err "cannot determine whether uid $OPERATOR_UID holds a vmnet slot socket."
                _err "  Slot sockets exist under $VMNET_SOCKET_DIR, but no socket_vmnet"
                _err "  endpoint was visible to this process, so a live holder and an idle"
                _err "  pool look identical from here. Re-run where those processes are"
                _err "  visible; this answers nothing as it stands."
                exit 6
                ;;
        esac
        ;;
    *)
        _err "unknown command: $CMD"
        _usage
        ;;
esac
