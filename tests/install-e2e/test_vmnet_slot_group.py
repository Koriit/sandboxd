"""Which group a vmnet slot socket must carry.

``scripts/darwin-vmnet-slot-group.sh`` answers one question for the plist
emitters: what goes in ``--socket-group=`` for slot N. That group is the entire
admission control for the slot's L2 segment — anyone in it can attach a VM, be
believed as the next hop by every guest already on the segment, and terminate
their TLS. So the property these tests are about is a **partition**: two
operators' slots must resolve to two different groups, and neither to a group
they are both in. One shared group across the pool is the defect, and it is
invisible from every other vantage point on the host.

The resolver reads Directory Services, so these drive it with a stand-in
``dscl`` on PATH. That makes them hermetic and host-independent — they assert
the decision logic, not this machine's enrollment.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent.parent / "scripts" / "darwin-vmnet-slot-group.sh"

FALLBACK = "_sandboxd"

# Group names a real `dscl . -list /Groups` returns alongside ours. Two of them
# share our prefix up to the 'op-' infix, which is what the infix is for.
NOISE = ["_sandbox", "_sandboxd", "_sandboxd-test", "everyone", "staff", "wheel"]


def fake_dscl(tmp_path: Path, ranges: dict[str, str], noise=NOISE) -> dict[str, str]:
    """Put a stand-in ``dscl`` on PATH answering -list /Groups and -read.

    ``ranges`` maps group name to its ``SandboxdSlots`` value; a group can be
    listed with no range by mapping it to ``""``.
    """
    data = tmp_path / "dscl-data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "groups").write_text("".join(g + "\n" for g in [*noise, *ranges]))
    for group, value in ranges.items():
        if value:
            (data / f"slots-{group}").write_text(
                f"dsAttrTypeNative:SandboxdSlots: {value}\n"
            )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    shim = bin_dir / "dscl"
    shim.write_text(
        "#!/bin/sh\n"
        f'd="{data}"\n'
        'case "$2" in\n'
        '  -list) cat "$d/groups" ;;\n'
        '  -read)\n'
        '    g=${3##*/}\n'
        '    if [ -f "$d/slots-$g" ]; then cat "$d/slots-$g"\n'
        # The shape a missing attribute really has: a diagnostic the caller
        # discards and a non-zero status the pipeline swallows.
        '    else echo "No such key: SandboxdSlots" >&2; exit 1\n'
        '    fi ;;\n'
        "esac\n"
        "exit 0\n"
    )
    shim.chmod(0o755)
    return {"PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin:/sbin"}


def resolve(slot: int, env: dict[str, str], fallback: str = FALLBACK):
    return subprocess.run(
        ["/bin/sh", str(SCRIPT), str(slot), fallback],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
    )


def resolve_pool(env: dict[str, str], size: int = 8) -> list[str]:
    out = []
    for slot in range(size):
        r = resolve(slot, env)
        assert r.returncode == 0, f"slot {slot}: {r.stderr}"
        out.append(r.stdout.strip())
    return out


# ---------------------------------------------------------------------------
# the partition
# ---------------------------------------------------------------------------

def test_each_operators_slots_resolve_to_that_operators_group(tmp_path):
    """The property the whole mechanism exists to produce.

    Before per-operator groups every slot in the pool resolved to one shared
    group, so this is the assertion that inverts: the pool splits along the
    recorded ranges, and no slot lands on the group both operators are in.
    """
    env = fake_dscl(tmp_path, {
        "_sandboxd-op-alice": "0-3",
        "_sandboxd-op-bob": "4-7",
    })

    groups = resolve_pool(env)
    assert groups == ["_sandboxd-op-alice"] * 4 + ["_sandboxd-op-bob"] * 4
    assert len(set(groups)) == 2, "the pool must not collapse onto one group"
    assert FALLBACK not in groups, (
        "a migrated pool must carry no slot on the shared group — that group is "
        "the one every operator is in"
    )


def test_a_ranges_last_element_resolves_like_every_other(tmp_path):
    """The end of a range is where a parser quietly loses one slot.

    macOS awk splits an extra empty field off a record's trailing newline, so a
    range read with ``RS=","`` yielded no upper bound for its final element and
    that element matched nothing. The slot then fell through to the fallback —
    the shared group every operator is in — while the other seven were
    correctly partitioned, and both the plist and ``status`` looked right.

    Canonicalization produces a trailing singleton routinely, and an operator
    holding exactly one slot is nothing but one.
    """
    env = fake_dscl(tmp_path / "pair", {
        "_sandboxd-op-alice": "0-3,7",
        "_sandboxd-op-bob": "4-6",
    })
    assert resolve(7, env).stdout.strip() == "_sandboxd-op-alice"
    assert resolve(6, env).stdout.strip() == "_sandboxd-op-bob"

    solo = fake_dscl(tmp_path / "solo", {"_sandboxd-op-carol": "5"})
    assert resolve(5, solo).stdout.strip() == "_sandboxd-op-carol"


def test_a_partition_is_not_required_to_be_contiguous(tmp_path):
    """Ranges are sets, and an operator's slots need not be adjacent."""
    env = fake_dscl(tmp_path, {
        "_sandboxd-op-alice": "0-1,4,6-7",
        "_sandboxd-op-bob": "2-3,5",
    })

    assert resolve_pool(env) == [
        "_sandboxd-op-alice", "_sandboxd-op-alice",
        "_sandboxd-op-bob", "_sandboxd-op-bob",
        "_sandboxd-op-alice",
        "_sandboxd-op-bob",
        "_sandboxd-op-alice", "_sandboxd-op-alice",
    ]


# ---------------------------------------------------------------------------
# the states that must not refuse
# ---------------------------------------------------------------------------

def test_an_unmigrated_host_falls_back_rather_than_refusing(tmp_path):
    """Every host that exists today is in this state, so refusing is an outage.

    No per-operator group records anything, so the answer is the shared group —
    exactly what the host already carries. The fallback is what makes the
    migration window survivable instead of a flag day.
    """
    env = fake_dscl(tmp_path, {})

    assert resolve_pool(env) == [FALLBACK] * 8


def test_a_slot_no_group_records_falls_back_while_its_neighbours_do_not(tmp_path):
    """A half-migrated pool resolves per slot, not per host."""
    env = fake_dscl(tmp_path, {"_sandboxd-op-alice": "0-3"})

    assert resolve_pool(env) == ["_sandboxd-op-alice"] * 4 + [FALLBACK] * 4


def test_a_group_with_no_recorded_range_claims_nothing(tmp_path):
    """Enrolled but unassigned must not read as 'owns the pool'."""
    env = fake_dscl(tmp_path, {"_sandboxd-op-alice": ""})

    assert resolve_pool(env) == [FALLBACK] * 8


# ---------------------------------------------------------------------------
# the state that must refuse
# ---------------------------------------------------------------------------

def test_a_contested_slot_is_refused_rather_than_picked(tmp_path):
    """Two claims on one slot is a half-finished de-enrollment, not a tie.

    The candidates are indistinguishable from here, so emitting either one
    hands an operator a segment that may not be theirs — silently, because the
    plist that results looks entirely ordinary.
    """
    env = fake_dscl(tmp_path, {
        "_sandboxd-op-alice": "0-4",
        "_sandboxd-op-bob": "4-7",
    })

    contested = resolve(4, env)
    assert contested.returncode == 2
    assert "_sandboxd-op-alice" in contested.stderr
    assert "_sandboxd-op-bob" in contested.stderr
    assert "refusing to pick one" in contested.stderr
    assert contested.stdout.strip() == "", (
        "a refusal must not also print a group — the caller substitutes stdout "
        "into --socket-group"
    )

    # The uncontested slots on either side of it still resolve.
    assert resolve(0, env).stdout.strip() == "_sandboxd-op-alice"
    assert resolve(7, env).stdout.strip() == "_sandboxd-op-bob"


# ---------------------------------------------------------------------------
# what must not be mistaken for an operator group
# ---------------------------------------------------------------------------

def test_a_service_group_is_not_mistaken_for_a_per_operator_group(tmp_path):
    """The 'op-' infix, doing the job it is there for.

    ``_sandboxd-test`` is the e2e harness's daemon account group and shares the
    prefix up to the infix. A filter written as ``_sandboxd-*`` would let a
    service group claim a range and put the pool back on a group that is not
    scoped to any operator.
    """
    env = fake_dscl(tmp_path, {
        "_sandboxd-test": "0-7",
        "_sandboxd": "0-7",
    })

    assert resolve_pool(env) == [FALLBACK] * 8


def test_the_resolver_answers_from_records_not_from_the_current_gid():
    """Reading the socket's gid here would make migration impossible.

    The gid says what the host enforces today and the records say what it
    should be. A resolver that consulted the gid would re-emit whatever the
    pool already carries, so a host on the shared group could never be moved
    off it — the emitters would faithfully reproduce the defect forever.
    """
    body = SCRIPT.read_text()
    # Not "slot-": the script's own filename contains it, which would make this
    # assertion fail on a correct resolver and say nothing about the gid.
    for forbidden in ("stat ", "/var/run/sandbox", ".sock", "ls -l"):
        assert forbidden not in body, (
            f"{forbidden!r} appears in darwin-vmnet-slot-group.sh — the resolver "
            f"must answer from the group records alone"
        )
