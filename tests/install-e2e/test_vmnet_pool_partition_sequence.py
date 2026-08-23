"""The order a vmnet pool is partitioned in, and why it cannot be rearranged.

Partitioning the pool takes four steps — split the group membership, regenerate
the slot plists, reload the launchd jobs, start the daemon — and only one order
of them works. The reason is not sequencing hygiene: ``--socket-group=`` is
written into a plist's argv as a **literal** when the plist is generated, and
nothing reads the group records again afterwards. Generate before the groups
exist and all eight plists name the shared fallback; enrolling afterwards
records ranges that no socket will ever carry.

That failure is silent from every vantage point except the sockets themselves.
The group records say the pool is partitioned, ``darwin-operator-group.sh
status`` agrees, and ``darwin-vmnet-drift.sh`` reports every slot in sync —
because the plist and the loaded argv genuinely do match, both carrying the
fallback. The host looks configured and is not partitioned, which is the
original defect wearing the fix's clothes.

So the ordering is not documentation, it is a property, and these tests pin it
in the two places that provision a host: the Makefile's dependency graph and
``install.sh``'s step sequence. They also pin the check that catches a pool
whose sockets and plists have parted ways — which has to take the group it
expects from the plist, because a constant cannot be right on both a migrated
and an unmigrated host.

Hermetic: no VM, no launchd, no Directory Services. Everything here reads the
provisioning sources or drives the plist generators, which are pure text.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
MAKEFILE = REPO / "Makefile"
INSTALL_SH = REPO / "scripts" / "install.sh"
EMITTER_CHECKER = REPO / "scripts" / "check-vmnet-uuid-equivalence.py"

# The step that creates a per-operator group and records its slot range, and
# the two that must follow it.
SPLIT_TARGET = "setup-darwin-operator-slot-group"
REGENERATE_TARGET = "setup-darwin-vmnet-plists"
RELOAD_TARGET = "setup-darwin-vmnet-daemons"


def installer_source() -> str:
    """``install.sh``'s text with its heredoc escaping undone.

    The installer body is emitted from an unquoted heredoc, so every ``$`` in
    it is written ``\\$``. Scanning for shell text without undoing that finds
    nothing and reports a clean result.
    """
    text = INSTALL_SH.read_text()
    assert "\\$" in text, (
        "install.sh no longer escapes '$' — the heredoc that required it is "
        "gone, and this normalization is now hiding what it used to reveal"
    )
    return text.replace("\\$", "$")


def make_prereqs(target: str, must_contain: str | None = None) -> list[str]:
    """Prerequisites of ``target``, following ``\\``-continuations.

    ``must_contain`` picks between same-named rules in different platform
    branches (``setup-dev-env`` is declared once per host OS).
    """
    text = MAKEFILE.read_text()
    found = []
    for match in re.finditer(rf"^{re.escape(target)}:(?!=)(.*)$", text, re.M):
        rest = match.group(1)
        end = match.end()
        while rest.rstrip().endswith("\\"):
            nl = text.index("\n", end) + 1
            eol = text.index("\n", nl)
            rest = rest.rstrip().rstrip("\\") + " " + text[nl:eol]
            end = eol
        found.append(rest.split())
    assert found, f"no rule named {target!r} in the Makefile"
    if must_contain is None:
        assert len(found) == 1, f"{target!r} is declared {len(found)} times; disambiguate"
        return found[0]
    matching = [p for p in found if must_contain in p]
    assert len(matching) == 1, (
        f"{len(matching)} declarations of {target!r} list {must_contain!r}"
    )
    return matching[0]


def recipe(target: str) -> str:
    """The recipe body of a Makefile rule — its tab-indented lines."""
    text = MAKEFILE.read_text()
    match = re.search(rf"^{re.escape(target)}:(?!=).*$", text, re.M)
    assert match, f"no rule named {target!r} in the Makefile"
    lines = []
    for line in text[match.end():].splitlines()[1:]:
        if line.startswith("\t") or not line.strip() or line.lstrip().startswith("#"):
            lines.append(line)
        else:
            break
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# why the order exists
# ---------------------------------------------------------------------------

def test_a_plist_names_its_group_literally_with_no_way_to_re_resolve_it():
    """The mechanism the whole ordering follows from.

    A launchd plist is data, not a program: there is no lookup, no expansion,
    no indirection. Whatever group the generator resolved goes in as bytes and
    stays there until something regenerates the file. That is why enrolling
    after generating changes nothing, and why the sockets — not the group
    records — are the only honest answer to "is this pool partitioned".
    """
    group = "_sandboxd-op-zeta"
    for emitter in ("make", "install-sh"):
        rendered = subprocess.run(
            [
                "python3", str(EMITTER_CHECKER),
                "--repo-root", str(REPO),
                "--emit-plist", "--emitter", emitter,
                "--slot", "0", "--socket-group", group,
            ],
            capture_output=True, text=True, check=True,
        ).stdout

        assert f"--socket-group={group} " in rendered, (
            f"the {emitter} emitter did not write the resolved group into the argv"
        )
        # A generated plist that could look the group up would make the
        # ordering a non-issue — and would be the only thing that could.
        for indirection in ("dscl", "$(", "`", "${"):
            assert indirection not in rendered, (
                f"the {emitter} emitter renders {indirection!r} into the plist; "
                f"if the group is resolved at load time rather than at generation "
                f"time, the provisioning order documented in "
                f"docs/guides/macos-operations.md is no longer load-bearing and "
                f"should be rewritten rather than left as folklore"
            )


# ---------------------------------------------------------------------------
# the order, in the two things that provision a host
# ---------------------------------------------------------------------------

def test_the_makefile_creates_the_group_before_any_plist_names_it():
    """The dependency edge that makes the sequence unskippable.

    Without it the two steps are independent and make is free to run them in
    either order — and the harmless-looking one produces a pool that reads as
    configured everywhere except the socket gids.
    """
    assert SPLIT_TARGET in make_prereqs(REGENERATE_TARGET), (
        f"{REGENERATE_TARGET} must depend on {SPLIT_TARGET}: a plist generated "
        f"before the group exists names the shared fallback permanently"
    )


def test_the_group_step_does_not_depend_on_the_plists_it_precedes():
    """The inverse edge is the tempting one, and it is a cycle.

    ``darwin-operator-group.sh`` defaults its pool size to the number of
    installed plists, which reads like a dependency on them. Declaring it
    inverts the order the mechanism needs — and on a first-ever install there
    are no plists to count. Passing the size explicitly is what keeps the
    graph acyclic and pointing the right way.
    """
    assert REGENERATE_TARGET not in make_prereqs(SPLIT_TARGET), (
        f"{SPLIT_TARGET} must not depend on {REGENERATE_TARGET} — that is the "
        f"ordering the pool cannot be partitioned in"
    )
    assert "--pool-size" in recipe(SPLIT_TARGET), (
        f"{SPLIT_TARGET} must pass --pool-size explicitly; without it the "
        f"script counts installed plists and the dependency comes back"
    )


def test_setup_dev_env_lists_the_split_ahead_of_the_regenerate():
    """Prerequisite order is not a guarantee, but a wrong one is a lie.

    make may build prerequisites in any order, so the edge above is what
    actually enforces this. Listing them backwards still matters: it is the
    reading order of the sequence for anyone who opens the file.
    """
    prereqs = make_prereqs("setup-dev-env", must_contain=REGENERATE_TARGET)
    assert prereqs.index(SPLIT_TARGET) < prereqs.index(REGENERATE_TARGET)
    assert prereqs.index(REGENERATE_TARGET) < prereqs.index(RELOAD_TARGET)


def test_the_installer_records_the_slot_range_before_it_generates_a_plist():
    """``install.sh`` runs steps in body order, so this is its whole ordering.

    Asserted on the range record rather than on the step name: the range is
    what the resolver reads, so a step that created the group and deferred the
    range would satisfy a name check and still generate eight fallback plists.
    """
    text = installer_source()
    steps = {m.group(1): m.start() for m in re.finditer(r'_step_begin "([^"]+)"', text)}
    for name in ("operator-group-add", "install-vmnet-plists", "bootstrap-vmnet-daemons"):
        assert name in steps, f"install.sh no longer has a {name!r} step"

    record = text.index("SandboxdSlots", steps["operator-group-add"])
    assert record < steps["install-vmnet-plists"], (
        "install.sh records an operator's slot range after generating the "
        "plists; the plists would name the shared fallback"
    )
    assert steps["install-vmnet-plists"] < steps["bootstrap-vmnet-daemons"], (
        "the plists must be on disk before launchd is asked to load them"
    )


# ---------------------------------------------------------------------------
# the check that sees a pool whose sockets and plists disagree
# ---------------------------------------------------------------------------

def test_the_post_bootstrap_check_expects_the_group_the_plist_names():
    """A constant cannot be right on both a migrated and an unmigrated host.

    This check compares the gid of the socket launchd created against the
    group its plist asked for. Written against the shared account instead, it
    passes on exactly the hosts that were never partitioned and fails the ones
    that were — and both provisioning paths treat that failure as fatal, so
    the migrated host is the one that cannot be installed.
    """
    installer = installer_source()
    make_body = recipe(RELOAD_TARGET)

    for label, body, wanted in (
        ("install.sh", installer, '"$_sock_group" != "$_want_group"'),
        ("Makefile", make_body, '"$$_sock_group" != "$$_want_group"'),
    ):
        assert "--socket-group=" in body, (
            f"{label} no longer reads --socket-group out of the plist"
        )
        assert wanted in body, (
            f"{label} must compare the socket's gid against the group its own "
            f"plist names, not against a constant"
        )

    # The specific wrong operands, named so the regression is recognisable if
    # it is reintroduced by reaching for the nearest available account name.
    assert '"$_sock_group" != "$_sandboxd_acct"' not in installer
    assert '"$$_sock_group" != "$$(DARWIN_SANDBOXD_ACCOUNT)"' not in make_body
