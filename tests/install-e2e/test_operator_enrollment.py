"""Per-operator vmnet slot enrollment and de-enrollment.

Every slot socket is guarded by one Unix group, and every enrolled operator is
in it. A slot socket is the entire admission control for its L2 segment, so one
shared group means any enrolled operator can place themselves on any other
operator's segment and be believed as its next hop — the victim's egress policy
is void, and nothing in the daemon, the session, or the deny-event stream
reflects it. ``scripts/darwin-operator-group.sh`` creates a group scoped to one
operator and records the slots they own.

These tests drive the script's ``--state-file`` seam, which answers every host
query from a fixture instead of Directory Services and forces ``--dry-run``. So
they need no macOS host, no sudo, no Tart guest and no VM, and they cannot
mutate anything. What they can assert is the part that is easy to get wrong and
invisible when it is: the **order** of the steps, and which situations are
refused rather than resolved.

Ordering is the subject rather than a detail. On enrollment the group and its
members exist before anything names them, because ``socket_vmnet`` given a
``--socket-group`` that does not resolve exits 1 at bind — a plist written
ahead of its group takes the slot down at the next boot rather than widening
it. On de-enrollment revocation strictly precedes reassignment, because
reclaiming a range while the departing operator keeps group membership hands
the slots to someone new while the old owner can still reach them, and nothing
at any layer detects that.

The live-host counterparts (a real ``dseditgroup -o checkmember`` against a
real second operator, and a real ``socket_vmnet`` refusal) are exercised by the
Tart-guest macOS install tests and by hand during provisioning; what is covered
here is the decision logic underneath them.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent.parent / "scripts" / "darwin-operator-group.sh"


def run(*args: str, state: Path | None = None) -> subprocess.CompletedProcess:
    cmd = ["/bin/sh", str(SCRIPT), *args]
    if state is not None:
        cmd += ["--state-file", str(state)]
    return subprocess.run(cmd, capture_output=True, text=True)


def steps(out: str) -> list[str]:
    """The ordered step names a run reports, e.g. ['create-group', ...]."""
    return [line.split()[2] for line in out.splitlines() if line.startswith("STEP ")]


def write_state(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "host.state"
    path.write_text(body)
    return path


# One operator, holding the whole pool, enrolled exactly as enrollment leaves it.
ENROLLED = """
pool-size 8
user alice 501
user bob 528
group _sandboxd-op-alice 320 0-7 alice,_sandboxd
group _sandboxd 310 - alice,_sandboxd-test
"""

# alice narrowed to the first half, so the second half is genuinely free.
PARTITIONED = """
pool-size 8
user alice 501
user bob 528
user svc 310
group _sandboxd-op-alice 320 0-3 alice,_sandboxd
"""


# ---------------------------------------------------------------------------
# range arithmetic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "given,expected",
    [
        ("0-7", "0-7"),
        ("4-7", "4-7"),
        ("5", "5"),
        ("3,0,1,2", "0-3"),        # unordered input canonicalizes
        ("0-3,6", "0-3,6"),
        ("0,2,4", "0,2,4"),
        ("0-1,4-5", "0-1,4-5"),
        ("0-3,2-5", "0-5"),        # overlapping input merges
    ],
)
def test_range_canonicalizes(given, expected):
    """Two spellings of one range must compare equal, or a re-run is not a no-op."""
    r = run("parse-range", given)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == expected


@pytest.mark.parametrize("given", ["7-3", "a-b", "0--3", "0-", "x"])
def test_malformed_range_refused(given):
    r = run("parse-range", given)
    assert r.returncode == 2, f"expected refusal for {given!r}: {r.stdout}{r.stderr}"


def test_group_name_is_scoped_and_cannot_collide_with_a_reserved_group():
    """The 'op-' infix keeps an operator named 'test' off the service group."""
    assert run("group-name", "--operator", "alice").stdout.strip() == "_sandboxd-op-alice"
    assert run("group-name", "--operator", "test").stdout.strip() == "_sandboxd-op-test"


# ---------------------------------------------------------------------------
# enrollment
# ---------------------------------------------------------------------------

def test_enroll_creates_the_group_before_anything_names_it(tmp_path):
    """The whole point of the ordering: no step names a group that does not exist yet.

    A range recorded against an unresolvable group is what a plist would later
    be generated from, and socket_vmnet refuses to start on one — exit 1 at
    bind, before vmnet.framework initializes, with no fallback to a default
    group. That fails closed rather than wide, and creating first keeps it from
    being reached at all.
    """
    state = write_state(tmp_path, "pool-size 8\nuser alice 501\n")
    r = run("enroll", "--operator", "alice", state=state)
    assert r.returncode == 0, r.stderr
    assert steps(r.stdout) == [
        "create-group",
        "add-member-operator",
        "add-member-daemon",
        "add-shared-group",
        "record-range",
        "verify",
    ]


def test_enroll_adds_the_daemon_account_to_every_per_operator_group(tmp_path):
    """Omitting it breaks every operator's sessions, not only the daemon's own.

    The gateway VM is created and started as the daemon uid and holds a NIC on
    every slot, so a daemon outside one operator's group fails ``limactl start``
    at the first socket entry — and no macOS session of any operator can be
    created or recovered.
    """
    state = write_state(tmp_path, "pool-size 8\nuser alice 501\n")
    r = run("enroll", "--operator", "alice", state=state)
    assert "add-member-daemon _sandboxd" in r.stdout


def test_enroll_keeps_the_operator_in_the_shared_group(tmp_path):
    """The per-operator group is a second group, not a replacement.

    The shared group gates the daemon socket and owns the 0750 socket
    directory; an operator moved out of it cannot traverse to a slot socket
    whatever group the socket itself carries.
    """
    state = write_state(tmp_path, "pool-size 8\nuser alice 501\n")
    r = run("enroll", "--operator", "alice", state=state)
    assert "add-shared-group _sandboxd" in r.stdout
    assert "revoke" not in r.stdout


def test_single_operator_host_gets_the_whole_pool(tmp_path):
    """Partitioning a pool nobody else uses would be a straight concurrency regression."""
    state = write_state(tmp_path, "pool-size 8\nuser alice 501\n")
    r = run("enroll", "--operator", "alice", state=state)
    assert "slots=0-7" in r.stdout


def test_reenrolling_unchanged_is_a_no_op(tmp_path):
    """Every step skips — not an error, and not a duplicate."""
    state = write_state(tmp_path, ENROLLED)
    r = run("enroll", "--operator", "alice", state=state)
    assert r.returncode == 0, r.stderr
    assert steps(r.stdout) == [
        "skip-group-exists",
        "skip-member-operator",
        "skip-member-daemon",
        "skip-shared-group",
        "skip-range-current",
        "verify",
    ]


def test_second_operator_gets_a_disjoint_range(tmp_path):
    state = write_state(tmp_path, PARTITIONED)
    r = run("enroll", "--operator", "bob", "--slots", "4-7", state=state)
    assert r.returncode == 0, r.stderr
    assert "group=_sandboxd-op-bob" in r.stdout
    assert "slots=4-7" in r.stdout


def test_overlapping_range_is_refused(tmp_path):
    """This is where 'revoke before reassign' stops being advice.

    A range still recorded against another operator's group cannot be handed
    out, so the only way to reassign it is to de-enroll its holder first.
    """
    state = write_state(tmp_path, PARTITIONED)
    r = run("enroll", "--operator", "bob", "--slots", "2-5", state=state)
    assert r.returncode == 3
    assert "_sandboxd-op-alice" in r.stderr


def test_second_operator_without_an_explicit_range_is_refused(tmp_path):
    """No automatic rebalancing: with someone else holding slots, say which."""
    state = write_state(tmp_path, PARTITIONED)
    r = run("enroll", "--operator", "bob", state=state)
    assert r.returncode == 3
    assert "--slots" in r.stderr


def test_slot_outside_the_pool_is_refused(tmp_path):
    state = write_state(tmp_path, PARTITIONED)
    r = run("enroll", "--operator", "bob", "--slots", "4-9", state=state)
    assert r.returncode == 2
    assert "outside" in r.stderr


def test_service_account_is_not_an_operator(tmp_path):
    """Excluded by an enumerable list rather than a name prefix.

    A prefix rule would silently absorb a future real operator whose name
    happens to start with an underscore, and this count is what decides
    whether a slot is assignable at all.
    """
    state = write_state(tmp_path, PARTITIONED)
    r = run("enroll", "--operator", "_sandboxd", "--slots", "4-7", state=state)
    assert r.returncode == 2
    assert "service account" in r.stderr


def test_sub_floor_uid_is_refused(tmp_path):
    """The daemon rejects a peer uid below the floor, so such an account is never
    an operator however it is enrolled here."""
    state = write_state(tmp_path, PARTITIONED)
    r = run("enroll", "--operator", "svc", "--slots", "4-7", state=state)
    assert r.returncode == 2
    assert "floor" in r.stderr


def test_unknown_account_is_refused(tmp_path):
    state = write_state(tmp_path, PARTITIONED)
    r = run("enroll", "--operator", "nobody", "--slots", "4-7", state=state)
    assert r.returncode == 2


# ---------------------------------------------------------------------------
# de-enrollment
# ---------------------------------------------------------------------------

DEENROLL = """
pool-size 8
user bob 528
group _sandboxd-op-bob 321 4-7 bob,_sandboxd
group _sandboxd 310 - bob,_sandboxd-test
"""


def test_deenroll_revokes_before_it_releases(tmp_path):
    """The ordering that keeps a reclaimed range from being silently shared.

    VMs are stopped first, while the operator is still enrolled and the daemon
    can still act on them. Revocation comes next. Only after the residue check
    passes is the range released — so at no point are the slots available to a
    new owner while the old one retains membership.
    """
    state = write_state(tmp_path, DEENROLL)
    r = run("deenroll", "--operator", "bob", state=state)
    assert r.returncode == 0, r.stderr
    assert steps(r.stdout) == [
        "stop-vms",
        "revoke-slot-group",
        "verify-no-live-holder",
        "release-range",
        "revoke-shared-group",
        "verify",
    ]


def test_deenroll_can_reclaim_a_range_without_removing_daemon_access(tmp_path):
    state = write_state(tmp_path, DEENROLL)
    r = run("deenroll", "--operator", "bob", "--keep-daemon-access", state=state)
    assert r.returncode == 0, r.stderr
    assert "keep-shared-group" in r.stdout
    assert "revoke-shared-group" not in r.stdout


def test_a_live_slot_holder_fails_closed_before_the_range_is_released(tmp_path):
    """Revocation is necessary and not sufficient, so this checks what it cannot reach.

    Group membership is checked at connect(2), not continuously: a detached
    QEMU keeps the fd it already opened, and a live login session keeps the
    supplementary groups it was granted at login. Either keeps the departing
    operator on the segment, so the range must not be handed onward.
    """
    state = write_state(tmp_path, DEENROLL + "slot-holder 528\n")
    r = run("deenroll", "--operator", "bob", state=state)
    assert r.returncode == 5
    assert steps(r.stdout) == ["stop-vms", "revoke-slot-group", "verify-no-live-holder"]
    assert "release-range" not in r.stdout


def test_a_half_done_deenrollment_shows_up_as_lost_capacity(tmp_path):
    """The state a failed de-enrollment leaves: revoked, but the range still recorded.

    The group now has no operator member, so its slots are unassignable. That
    is the behaviour to preserve rather than 'fix' — it surfaces as capacity
    nobody has, which is loud, instead of as shared access, which is silent.
    """
    half_done = """
pool-size 8
user bob 528
user carol 530
group _sandboxd-op-bob 321 4-7 _sandboxd
"""
    state = write_state(tmp_path, half_done)

    status = run("status", state=state)
    assert "state=unassignable-no-operator" in status.stdout

    # and the range cannot be handed to anyone else while it is in that state
    r = run("enroll", "--operator", "carol", "--slots", "4-7", state=state)
    assert r.returncode == 3

    # re-running de-enrollment completes it — the sequence is resumable
    resumed = run("deenroll", "--operator", "bob", state=state)
    assert resumed.returncode == 0, resumed.stderr
    assert "release-range" in resumed.stdout


def test_two_operators_in_one_slot_group_is_refused_not_resolved(tmp_path):
    """Picking the newer operator is exactly the 'fix' that hides a half-done
    de-enrollment. Two operators in one slot group share a segment, so the
    range is left unassignable and named."""
    two_ops = """
pool-size 8
user alice 501
user bob 528
group _sandboxd-op-alice 320 0-3 alice,bob,_sandboxd
"""
    state = write_state(tmp_path, two_ops)
    r = run("enroll", "--operator", "bob", "--slots", "4-7", state=state)
    assert r.returncode == 4
    assert "unassignable" in r.stderr

    status = run("status", state=state)
    assert "state=unassignable-multiple-operators" in status.stdout


def test_a_group_with_no_recorded_range_answers_refusal_not_the_whole_pool(tmp_path):
    """An absent range is not a default.

    A group with an owner but no recorded range answers nothing about which
    slots that owner holds. Reporting it as the whole pool is how a group
    nobody assigned slots to starts looking like a group that owns all of
    them — the same guess-instead-of-refuse shape this work exists to remove.
    """
    no_range = """
pool-size 8
user alice 501
group _sandboxd-op-alice 320 - alice,_sandboxd
"""
    state = write_state(tmp_path, no_range)
    r = run("status", state=state)
    assert "state=unassignable-no-range" in r.stdout, r.stdout
    assert "0-7" not in r.stdout


def test_deenrolling_an_operator_who_is_not_enrolled_is_a_no_op(tmp_path):
    state = write_state(tmp_path, "pool-size 8\nuser bob 528\n")
    r = run("deenroll", "--operator", "bob", state=state)
    assert r.returncode == 0
    assert "nothing to do" in r.stdout
    assert steps(r.stdout) == []


def test_deenrolling_the_invoking_operator_needs_force(tmp_path):
    """Revoking your own access is legitimate and very easy to do by accident."""
    self_state = """
pool-size 8
user alice 501
group _sandboxd-op-alice 320 0-7 alice,_sandboxd
"""
    state = write_state(tmp_path, self_state)
    cmd = ["/bin/sh", str(SCRIPT), "deenroll", "--operator", "alice",
           "--state-file", str(state)]
    refused = subprocess.run(cmd, capture_output=True, text=True,
                             env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SUDO_USER": "alice"})
    assert refused.returncode == 2
    assert "--force" in refused.stderr

    forced = subprocess.run(cmd + ["--force"], capture_output=True, text=True,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SUDO_USER": "alice"})
    assert forced.returncode == 0, forced.stderr


# ---------------------------------------------------------------------------
# what this phase deliberately does not do
# ---------------------------------------------------------------------------

def test_nothing_here_moves_a_socket_or_rewrites_a_plist():
    """Enforcement lands with VM ownership, not with assignment.

    Until then the daemon's own gateway VM must keep opening every slot, so a
    host whose sockets still carry the shared group has to keep working
    unchanged. Any reference here to the socket directory or the launchd plists
    must therefore be a read.
    """
    body = SCRIPT.read_text()
    for forbidden in ("chgrp", "chown", "launchctl", "plutil", "install -d"):
        assert forbidden not in body, (
            f"{forbidden!r} appears in darwin-operator-group.sh — this phase assigns "
            f"and audits slot ranges; it does not enforce them"
        )
