#!/usr/bin/env python3
"""Cross-emitter equivalence guard for the vmnet launchd plists.

Three independent emitters produce the same eight launchd plists:

  1. Rust:  sandboxd/sandbox-core/src/network.rs  (`render_vmnet_plist`)
  2. Make:  Makefile                              (`setup-darwin-vmnet-plists`)
  3. Shell: scripts/install.sh                    (`install-vmnet-plists` step)

They cannot share a literal: a `curl | sh` installer cannot read a file from the
repo, and `make` cannot read a Rust constant. So each declares the values it
needs and this script — run in CI on macOS — extracts all three from source and
fails when they disagree. That comparison, not a shared constant, is what keeps
them from drifting.

The three paths are also checked to still be *all* of them: every tracked file
is scanned for the signatures of a plist emitter, and one that matches without
being registered fails the run. Comparing three emitters proves nothing about a
fourth nobody registered.

What is compared
----------------

* **Emitter inventory** — that no unregistered file emits these plists, and
  that the known emitters still match the signatures used to find them.
* **Daemon account name** — `SANDBOXD_ACCOUNT` / `DARWIN_SANDBOXD_ACCOUNT` /
  `_sandboxd_acct`, plus the account `install.sh` actually *creates* via `dscl`.
  A plist naming an account nobody creates installs cleanly and then kills the
  whole pool at the next boot, when the root preamble's
  `install -d -o <account> …` fails and `&&`-short-circuits before socket_vmnet
  is exec'd.
* **Staged socket_vmnet path** — the binary the plists exec.
* **Pre-exec wrapper template** — the `/bin/sh -c` string embedded in each
  plist, normalized to placeholders so the three emitters' different
  interpolation syntaxes can be compared byte for byte.
* **Whole rendered plist** — the Makefile's and install.sh's plist generators
  are executed and their output compared. `--emit-plist` prints one emitter's
  rendering so a Rust test can compare it against `render_vmnet_plist`.
* **Slot network identifiers** — the per-slot UUIDv5 derived by all three from
  `SHA1(SANDBOXD_VMNET_NAMESPACE || slot_be_u16)`, checked against the values
  pinned in `test_vmnet_network_identifier_pinned_values`. If these diverge, L2
  inter-slot isolation silently breaks: the launchd daemons run different
  network identifiers than the daemon expects.

Usage
-----

    check-vmnet-uuid-equivalence.py [--repo-root DIR]
    check-vmnet-uuid-equivalence.py --emit-plist --emitter make|install-sh
                                    [--slot N] [--repo-root DIR]
"""

import argparse
import difflib
import hashlib
import pathlib
import re
import struct
import subprocess
import sys

# SANDBOXD_VMNET_NAMESPACE — must match the constant in network.rs.
NAMESPACE = bytes([
    0x6d, 0x4f, 0x6e, 0x2b, 0x95, 0x8a, 0x4f, 0x1a,
    0xa2, 0x31, 0x7e, 0x8c, 0xd0, 0x12, 0x3e, 0x5b,
])

# Pinned expected values from test_vmnet_network_identifier_pinned_values.
# Update this dict if the namespace or algorithm intentionally changes (and
# update the Rust test and Makefile at the same time — all three must agree).
EXPECTED = {
    0: "a25e1b72-b44a-573c-be93-fe2da03c5a96",
    1: "632c6b78-8256-579e-a88d-041b5adfd423",
    2: "a1a1fa3e-5809-5b63-9a1b-358845ec042b",
}

NETWORK_RS = "sandboxd/sandbox-core/src/network.rs"
MAKEFILE = "Makefile"
INSTALL_SH = "scripts/install.sh"

# ---------------------------------------------------------------------------
# Emitter inventory — discovery, not enumeration
# ---------------------------------------------------------------------------
#
# The three paths above are hardcoded, which is fine for *comparing* emitters
# but useless for noticing a fourth one. A new shell or Python path that writes
# these plists would simply not be read by this script, and the comparison
# would keep passing while the new emitter drifted freely. That is the same
# shape of failure this script exists to prevent: a green exit that means
# nothing.
#
# So the file list is also checked the other way round. Every tracked file is
# scanned for the signatures below, and anything that matches without being
# registered here is a failure telling the author to register it.

# A file that renders these plists gives itself away in one of two ways.
#
# `preamble` — the boot-time directory setup whose failure is the whole point
# of #85. Matched by shape, not by exact bytes, so a reordered flag or a
# changed mode still trips it.
#
# `plist-body` — building the launchd job itself: the vmnet label prefix and a
# ProgramArguments array in the same file. This catches an emitter that changed
# the preamble beyond recognition but still writes the job.
SIGNATURES = {
    "preamble": re.compile(r"install\s+-d\b[^\n]*/var/run/sandbox"),
}
SIG_VMNET_LABEL = re.compile(r"io\.sandboxd\.vmnet\.")
SIG_PROGRAM_ARGUMENTS = re.compile(r"ProgramArguments")

# Prose trees. Documentation about the pool quotes the preamble constantly —
# `docs/guides/troubleshooting.md` explains the exact `install -d` failure — and
# design notes reproduce whole plists. Scanning them would make this check
# nothing but noise, and an emitter is not going to live in a Markdown tree.
PROSE_DIRS = ("docs", ".tasks", ".claude")

# Every file allowed to match a signature, and why. Adding a path here is the
# deliberate act of registering an emitter; a reviewer sees it in the diff.
REGISTERED = {
    NETWORK_RS: "emitter: render_vmnet_plist",
    MAKEFILE: "emitter: setup-darwin-vmnet-plists",
    INSTALL_SH: "emitter: install-vmnet-plists step",
    "scripts/check-vmnet-uuid-equivalence.py": (
        "not an emitter: this script, which quotes the fragments it checks for"
    ),
    "sandboxd/sandbox-core/tests/vmnet_emitter_lint.rs": (
        "not an emitter: the test that runs this script and renders fixtures"
    ),
}

# The subset of the above that must actually still look like emitters. If one
# of these stops matching every signature, the signature has gone stale and the
# scan has quietly stopped detecting the thing it exists to detect.
REGISTERED_EMITTERS = (NETWORK_RS, MAKEFILE, INSTALL_SH)

# Canonical placeholders the three wrapper templates are normalized to.
#
# `{account}` and `{socket_group}` are separate on purpose and must stay
# separate. The account owns the 0750 socket *directory*, which every operator
# has to traverse to reach any slot; the socket group is the admission control
# for one slot's L2 segment. An emitter that collapses them back into one
# variable puts every enrolled operator on every operator's segment — the
# defect this split closed — and normalizing both to `{account}` here would
# make the three-way comparison agree that it had.
PH_ACCOUNT = "{account}"
PH_STAGED = "{staged}"
PH_UUID = "{uuid}"
PH_SOCKET = "{socket}"
PH_SOCKET_GROUP = "{socket_group}"

# The group name rendered into sample wrappers. Deliberately *not* the account:
# an emitter that collapsed `--socket-group` back onto the account would render
# byte-identically to a correct one if both placeholders expanded to the same
# string, and every comparison below would agree that nothing had changed.
SAMPLE_SOCKET_GROUP = "_sandboxd-op-sample"

# The slot -> group resolver, carried in two places because install.sh is
# delivered by `curl | bash` and cannot call a script from the repo.
SLOT_GROUP_SH = "scripts/darwin-vmnet-slot-group.sh"
RESOLVER_BEGIN = "# --- resolver (mirrored in scripts/install.sh) ---"
RESOLVER_END = "# --- end resolver ---"


class ExtractionError(Exception):
    """A declaration this script depends on is missing or has moved."""


def _search(pattern, text, what, source, flags=0):
    m = re.search(pattern, text, flags)
    if m is None:
        raise ExtractionError(
            f"{source}: could not find {what}.\n"
            f"  pattern: {pattern}\n"
            "  If the declaration moved or was renamed, update this script — it is\n"
            "  the only thing keeping the three emitters from drifting apart."
        )
    return m


# ---------------------------------------------------------------------------
# Extraction — one function per emitter, each returning a dict of the values
# that emitter declares.
# ---------------------------------------------------------------------------


def extract_rust(root: pathlib.Path) -> dict:
    text = (root / NETWORK_RS).read_text()

    account = _search(
        r'pub const SANDBOXD_ACCOUNT: &str = "([^"]+)";',
        text, "the SANDBOXD_ACCOUNT constant", NETWORK_RS,
    ).group(1)
    staged = _search(
        r'pub const STAGED_SOCKET_VMNET_PATH: &str = "([^"]+)";',
        text, "the STAGED_SOCKET_VMNET_PATH constant", NETWORK_RS,
    ).group(1)
    raw = _search(
        r'let exec_cmd = format!\(\s*"(.*?)"\s*\);',
        text, "the exec_cmd format! literal", NETWORK_RS, re.DOTALL,
    ).group(1)

    # A Rust `\`-newline continuation swallows the newline and the next line's
    # leading whitespace.
    wrapper = re.sub(r"\\\n[ \t]*", "", raw)
    # Substitute the named format arguments before un-doubling braces, so the
    # `{{`/`}}` of the codesign guard cannot be mistaken for a placeholder.
    wrapper = (
        wrapper.replace("{account}", "\0A\0")
        .replace("{socket_group}", "\0G\0")
        .replace("{STAGED_SOCKET_VMNET_PATH}", "\0S\0")
        .replace("{network_identifier}", "\0U\0")
        .replace("{socket_path}", "\0K\0")
        .replace("{{", "{")
        .replace("}}", "}")
    )
    wrapper = _to_placeholders(wrapper)

    return {"account": account, "staged": staged, "wrapper": wrapper}


def extract_makefile(root: pathlib.Path) -> dict:
    text = (root / MAKEFILE).read_text()

    account = _search(
        r"^DARWIN_SANDBOXD_ACCOUNT\s*:=\s*(\S+)\s*$",
        text, "the DARWIN_SANDBOXD_ACCOUNT assignment", MAKEFILE, re.MULTILINE,
    ).group(1)
    staged = _search(
        r"^DARWIN_SOCKET_VMNET_STAGED\s*:=\s*(\S+)\s*$",
        text, "the DARWIN_SOCKET_VMNET_STAGED assignment", MAKEFILE, re.MULTILINE,
    ).group(1)
    raw = _search(
        r'^\s*exec_cmd="(.*)";\s*\\\s*$',
        text, "the exec_cmd shell assignment", MAKEFILE, re.MULTILINE,
    ).group(1)

    wrapper = (
        raw.replace("$$socket_group", "\0G\0")
        .replace("$$acct", "\0A\0")
        .replace("$$staged_binary", "\0S\0")
        .replace("$$network_id", "\0U\0")
        .replace("$$socket_path", "\0K\0")
    )
    return {
        "account": account,
        "staged": staged,
        "wrapper": _to_placeholders(wrapper),
        "skeleton": _extract_makefile_skeleton(text),
    }


def extract_install_sh(root: pathlib.Path) -> dict:
    text = (root / INSTALL_SH).read_text()

    account = _search(
        r'^_sandboxd_acct="([^"]+)"',
        text, "the _sandboxd_acct assignment", INSTALL_SH, re.MULTILINE,
    ).group(1)
    staged = _search(
        r'^_svmnet_staged="([^"]+)"',
        text, "the _svmnet_staged assignment", INSTALL_SH, re.MULTILINE,
    ).group(1)
    raw = _search(
        r'^\s*_exec_cmd="(.*)"\s*$',
        text, "the _exec_cmd assignment", INSTALL_SH, re.MULTILINE,
    ).group(1)

    wrapper = (
        raw.replace("\\$_socket_group", "\0G\0")
        .replace("\\$_sandboxd_acct", "\0A\0")
        .replace("\\$_svmnet_staged", "\0S\0")
        .replace("\\$_network_id", "\0U\0")
        .replace("\\$_socket_path", "\0K\0")
    )

    # The account install.sh *creates*. Every dscl record it creates must name
    # the same variable the plists name; a literal here is exactly how the two
    # drifted apart in the first place. The leading backslash is the unquoted
    # heredoc's escape — the privileged child sees a plain `$`.
    created = sorted({
        m.lstrip("\\")
        for m in re.findall(r"dscl \. -create \"/(?:Users|Groups)/([^\"]+)\"", text)
    })

    return {
        "account": account,
        "staged": staged,
        "wrapper": _to_placeholders(wrapper),
        "created_accounts": created,
        "skeleton": _extract_install_sh_skeleton(text),
    }


def _to_placeholders(s: str) -> str:
    return (
        s.replace("\0A\0", PH_ACCOUNT)
        .replace("\0S\0", PH_STAGED)
        .replace("\0U\0", PH_UUID)
        .replace("\0K\0", PH_SOCKET)
        .replace("\0G\0", PH_SOCKET_GROUP)
    )


def _extract_makefile_skeleton(text: str) -> str:
    """The plist-XML generator program embedded in setup-darwin-vmnet-plists.

    Recovers the program text the child shell would hand to `python3 -c`: make
    collapses `$$` to `$`, then the double-quoted shell word turns `\\"` into `"`.
    """
    raw = _search(
        r'^\s*python3 -c "(import sys; label,exec_cmd.*?)" "\$\$label"',
        text, "the plist-XML python3 generator", MAKEFILE, re.MULTILINE | re.DOTALL,
    ).group(1)
    return raw.replace("$$", "$").replace('\\"', '"')


def _extract_install_sh_skeleton(text: str) -> str:
    """The plist-XML generator program embedded in the install-vmnet-plists step.

    Recovers the program text the privileged child would hand to `python3 -c`:
    the unquoted heredoc leaves `\\"` and `\\$` intact, then the child's
    double-quoted shell word resolves them to `"` and `$`.
    """
    raw = _search(
        r'^[ \t]*python3 -c "\n(import sys\n.*?)\n" "\\\$_label"',
        text, "the plist-XML python3 generator", INSTALL_SH, re.MULTILINE | re.DOTALL,
    ).group(1)
    return raw.replace('\\"', '"').replace("\\$", "$")


# ---------------------------------------------------------------------------
# Derivation and rendering
# ---------------------------------------------------------------------------


def derive_uuid(slot: int) -> str:
    """Derive the UUIDv5 network-identifier for a given slot index.

    Algorithm (matches all three emitters):
      1. SHA1(NAMESPACE || slot_as_big_endian_u16)
      2. Take first 16 bytes
      3. Set version = 5 (top nibble of byte 6)
      4. Set variant = RFC 4122 (top 2 bits of byte 8 = 10xx xxxx)
      5. Format as 8-4-4-4-12 lowercase hex
    """
    h = hashlib.sha1(NAMESPACE + struct.pack(">H", slot)).digest()
    b = bytearray(h[:16])
    b[6] = (b[6] & 0x0F) | 0x50   # version 5
    b[8] = (b[8] & 0x3F) | 0x80   # RFC 4122 variant
    return "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
        *b
    )


def render_wrapper(
    template: str, account: str, staged: str, slot: int, socket_group: str
) -> str:
    """Expand a normalized wrapper template for one slot."""
    return (
        template.replace(PH_ACCOUNT, account)
        .replace(PH_SOCKET_GROUP, socket_group)
        .replace(PH_STAGED, staged)
        .replace(PH_UUID, derive_uuid(slot))
        .replace(PH_SOCKET, f"/var/run/sandbox/vmnet/slot-{slot}.sock")
    )


def render_plist(skeleton: str, wrapper: str, slot: int) -> str:
    """Run an emitter's own XML generator and return the plist it produces."""
    label = f"io.sandboxd.vmnet.{slot}"
    proc = subprocess.run(
        [sys.executable, "-c", skeleton, label, wrapper, str(slot), derive_uuid(slot)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise ExtractionError(
            f"the extracted plist generator failed for slot {slot}:\n{proc.stderr}"
        )
    return proc.stdout


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_uuids(slots) -> int:
    print("=== UUID equivalence check ===")
    failures = 0
    for slot in slots:
        computed = derive_uuid(slot)
        expected = EXPECTED.get(slot)
        if expected is not None and computed != expected:
            print(
                f"FAIL slot {slot}: computed {computed!r} but expected {expected!r} "
                "(from the Rust pinned test). The namespace bytes or the algorithm "
                "has diverged — update network.rs, the Makefile, install.sh AND this "
                "script together.",
                file=sys.stderr,
            )
            failures += 1
        else:
            print(f"OK   slot {slot}: {computed}")
    if not failures:
        print(f"All {len(slots)} slot UUIDs match the Rust pinned values.")
    return failures


def check_three_way(rust: dict, make: dict, sh: dict) -> int:
    failures = 0

    print()
    print("=== Daemon account name ===")
    names = {NETWORK_RS: rust["account"], MAKEFILE: make["account"], INSTALL_SH: sh["account"]}
    for source, value in names.items():
        print(f"     {source}: {value}")
    if len(set(names.values())) != 1:
        print(
            "FAIL: the three emitters name different accounts. Every vmnet plist's "
            "root preamble runs `install -d -o <account> …` at each boot; an account "
            "that no emitter creates takes the whole socket_vmnet pool down at the "
            "next reboot, long after the run that installed the plist reported "
            "success.",
            file=sys.stderr,
        )
        failures += 1
    else:
        print(f"OK   all three emitters name '{rust['account']}'")

    print()
    print("=== Account created by the installer ===")
    created = sh["created_accounts"]
    print(f"     {INSTALL_SH} creates: {', '.join(created) if created else '(none)'}")
    # The daemon account is the one the plists name, so it is required. The
    # per-operator slot group is a different record with a different purpose —
    # no plist names it yet, and it is allowed rather than expected because a
    # host may be installed for no operator at all.
    #
    # What the check is really about is the *spelling*: every record must be
    # created through a variable. A literal is how the account the installer
    # created and the account the plists named came apart in the first place,
    # and that failure did not surface until the next boot.
    literals = [c for c in created if not c.startswith("$")]
    unknown = [c for c in created if c not in ("$_sandboxd_acct", "$_osg")]
    if literals:
        print(
            f"FAIL: {INSTALL_SH} creates dscl records from literals: {literals}. "
            "Every record must be spelled with the variable the rest of the script "
            "uses — a literal is how the created account and the account the plists "
            "name came apart before, and it did not surface until the next boot.",
            file=sys.stderr,
        )
        failures += 1
    elif "$_sandboxd_acct" not in created:
        print(
            f"FAIL: {INSTALL_SH} no longer creates '$_sandboxd_acct' via dscl. "
            "The installer must create the same account its plists name.",
            file=sys.stderr,
        )
        failures += 1
    elif unknown:
        print(
            f"FAIL: {INSTALL_SH} creates unrecognized dscl records: {unknown}. "
            "Add them here deliberately — an installer quietly gaining identities "
            "is what this check exists to notice.",
            file=sys.stderr,
        )
        failures += 1
    else:
        print(f"OK   the installer creates the account it declares ('{sh['account']}')")

    print()
    print("=== Staged socket_vmnet path ===")
    staged = {NETWORK_RS: rust["staged"], MAKEFILE: make["staged"], INSTALL_SH: sh["staged"]}
    for source, value in staged.items():
        print(f"     {source}: {value}")
    if len(set(staged.values())) != 1:
        print("FAIL: the three emitters exec different binaries.", file=sys.stderr)
        failures += 1
    else:
        print(f"OK   all three emitters exec '{rust['staged']}'")

    print()
    print("=== Pre-exec wrapper template ===")
    wrappers = {NETWORK_RS: rust["wrapper"], MAKEFILE: make["wrapper"], INSTALL_SH: sh["wrapper"]}
    if len(set(wrappers.values())) != 1:
        print("FAIL: the three wrapper templates differ.", file=sys.stderr)
        for source, value in wrappers.items():
            print(f"  {source}:\n    {value}", file=sys.stderr)
        failures += 1
    else:
        print("OK   all three wrapper templates are byte-identical (normalized):")
        print(f"     {rust['wrapper']}")

    return failures


def _candidate_files(root: pathlib.Path):
    """Every file worth scanning, relative to `root`.

    Prefers git, which excludes build output and captured test logs for free —
    `build/` and `tests/install-e2e/logs/` are both gitignored, and both hold
    files that match the signatures without being emitters (a copy of the
    installer, and captured `launchctl print` transcripts). Untracked files are
    included as long as they are not ignored, so a new emitter trips this
    before it is even staged. Falls back to a filesystem walk when `root` is
    not a git repository, which is how the Rust lint drives this script against
    a perturbed temporary copy.
    """
    try:
        names = []
        for extra in (["ls-files", "-z"], ["ls-files", "--others", "--exclude-standard", "-z"]):
            out = subprocess.run(
                ["git", "-C", str(root), *extra],
                capture_output=True, text=True, check=True,
            ).stdout
            names.extend(n for n in out.split("\0") if n)
        if names:
            return names
    except (OSError, subprocess.CalledProcessError):
        pass

    names = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in (".git", "target", ".venv", "node_modules") for part in rel.parts):
            continue
        names.append(str(rel))
    return names


def discover_plist_emitters(root: pathlib.Path) -> dict:
    """Map each file that looks like a plist emitter to the signatures it matched."""
    found = {}
    for name in _candidate_files(root):
        if name.split("/", 1)[0] in PROSE_DIRS:
            continue
        try:
            text = (root / name).read_text()
        except (OSError, UnicodeDecodeError):
            continue
        matched = [label for label, rx in SIGNATURES.items() if rx.search(text)]
        if SIG_VMNET_LABEL.search(text) and SIG_PROGRAM_ARGUMENTS.search(text):
            matched.append("plist-body")
        if matched:
            found[name] = sorted(matched)
    return found


def check_emitter_inventory(root: pathlib.Path) -> int:
    """Fail on any unregistered emitter, and on any signature that has gone stale."""
    print()
    print("=== Emitter inventory (discovered, not enumerated) ===")
    found = discover_plist_emitters(root)
    for name in sorted(found):
        role = REGISTERED.get(name, "UNREGISTERED")
        print(f"     {name}: {', '.join(found[name])}  [{role}]")

    failures = 0

    unregistered = sorted(set(found) - set(REGISTERED))
    if unregistered:
        print(
            "FAIL: these files look like they emit the vmnet launchd plists but are "
            "not registered in this script:\n"
            + "".join(f"  - {name} ({', '.join(found[name])})\n" for name in unregistered)
            + "  Nothing compares an unregistered emitter against the others, so it can "
            "name a\n"
            "  different account or exec a different binary and every check here will "
            "still\n"
            "  pass. Add each to REGISTERED with the reason — as an emitter if it writes "
            "the\n"
            "  plists (and give it an extract_* function so it is actually compared), or "
            "with\n"
            "  a note saying why it merely mentions them.",
            file=sys.stderr,
        )
        failures += 1

    # The other direction: a signature that no longer matches a known emitter
    # is a scan that has stopped scanning. Without this, narrowing a signature
    # into uselessness would make the check above pass trivially.
    expected_signatures = set(SIGNATURES) | {"plist-body"}
    for name in REGISTERED_EMITTERS:
        if not (root / name).exists():
            continue  # perturbed-copy runs carry only a subset of the tree
        missing = expected_signatures - set(found.get(name, []))
        if missing:
            print(
                f"FAIL: {name} is a known emitter but no longer matches "
                f"{sorted(missing)}. Either the emitter changed shape or the signature "
                "was narrowed; in both cases this scan can no longer find a fourth "
                "emitter and must be repaired, not relaxed.",
                file=sys.stderr,
            )
            failures += 1

    if not failures:
        print(
            f"OK   {len(found)} file(s) match an emitter signature, all registered; "
            f"all {len(REGISTERED_EMITTERS)} known emitters still match every signature"
        )
    return failures


def check_wrapper_structure(template: str, account: str, staged: str) -> int:
    """The wrapper must still contain the parts that make it safe.

    The fragments are checked against the template extracted from source, not
    against a copy pinned in this file — a check against its own constant would
    pass no matter what the emitters did.
    """
    print()
    print("=== Wrapper structure ===")
    sample = render_wrapper(template, account, staged, 0, SAMPLE_SOCKET_GROUP)
    required = [
        f"install -d -o {account} -g {account} -m 0750 /var/run/sandbox &amp;&amp;",
        f"install -d -o {account} -g {account} -m 0750 /var/run/sandbox/vmnet &amp;&amp;",
        f"codesign --verify --strict {staged}",
        "refusing to exec",
        f"exec {staged}",
        "--vmnet-mode=host",
        # The group, never the account. These two are the whole point of the
        # split: the account owns the traversable 0750 directory, the group is
        # admission control for one slot's segment.
        f"--socket-group={SAMPLE_SOCKET_GROUP}",
    ]
    failures = 0
    for fragment in required:
        if fragment not in sample:
            print(f"FAIL: expected fragment not found in wrapper:\n  {fragment!r}", file=sys.stderr)
            failures += 1
        else:
            print(f"OK   fragment present: {fragment[:60]!r}{'...' if len(fragment) > 60 else ''}")
    if not failures:
        print(f"Sample wrapper (slot 0):\n  {sample}")
    return failures


def extract_resolver(path: pathlib.Path, source: str, deescape: bool) -> str:
    """The slot -> group resolver, between its two marker comments."""
    text = path.read_text()
    begin = RESOLVER_BEGIN.replace("\\", "")
    start = text.find(begin)
    if start < 0:
        raise ExtractionError(
            f"{source}: could not find the resolver's opening marker.\n"
            f"  marker: {begin}\n"
            "  The two copies can only be compared if both are delimited."
        )
    end = text.find(RESOLVER_END, start)
    if end < 0:
        raise ExtractionError(f"{source}: the resolver's closing marker is missing.")
    body = text[start + len(begin):end]
    # install.sh carries its copy inside an unquoted heredoc, so every `$` is
    # written `\$`. The privileged child sees a plain `$`; compare what it sees.
    return body.replace("\\$", "$") if deescape else body


def check_resolver_copies(root: pathlib.Path) -> int:
    """The two copies of the slot -> group resolver must be identical.

    A drifted copy is not a cosmetic problem. The installer's copy decides
    which group each slot socket is handed to on a production host; if it
    resolves differently from the canonical one, a slot is handed to the wrong
    operator's group and the segment is open to them, with every other layer
    still reporting the intended owner.
    """
    print()
    print("=== Slot -> group resolver copies ===")
    try:
        canonical = extract_resolver(root / SLOT_GROUP_SH, SLOT_GROUP_SH, deescape=False)
        installed = extract_resolver(root / INSTALL_SH, INSTALL_SH, deescape=True)
    except (ExtractionError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if canonical != installed:
        print(
            f"FAIL: the resolver in {INSTALL_SH} has drifted from {SLOT_GROUP_SH}.",
            file=sys.stderr,
        )
        for line in difflib.unified_diff(
            canonical.splitlines(), installed.splitlines(),
            fromfile=SLOT_GROUP_SH, tofile=INSTALL_SH, lineterm="",
        ):
            print(f"  {line}", file=sys.stderr)
        return 1

    print(f"OK   {INSTALL_SH} carries {SLOT_GROUP_SH} verbatim ({len(canonical)} bytes)")
    return 0


def check_rendered_plists(make: dict, sh: dict, account: str, staged: str, slots) -> int:
    """Run both shell emitters' own XML generators and compare their output."""
    print()
    print("=== Rendered plist equality (Makefile vs install.sh) ===")
    failures = 0
    for slot in slots:
        make_plist = render_plist(
            make["skeleton"],
            render_wrapper(make["wrapper"], account, staged, slot, SAMPLE_SOCKET_GROUP),
            slot,
        )
        sh_plist = render_plist(
            sh["skeleton"],
            render_wrapper(sh["wrapper"], account, staged, slot, SAMPLE_SOCKET_GROUP),
            slot,
        )
        if make_plist != sh_plist:
            print(f"FAIL slot {slot}: the two generators render different plists.", file=sys.stderr)
            print(f"  {MAKEFILE}:\n{make_plist}", file=sys.stderr)
            print(f"  {INSTALL_SH}:\n{sh_plist}", file=sys.stderr)
            failures += 1
        else:
            print(f"OK   slot {slot}: byte-identical ({len(make_plist)} bytes)")
    return failures


# ---------------------------------------------------------------------------


def default_repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root", type=pathlib.Path, default=default_repo_root(),
        help="repository root to read the three emitters from (default: this script's repo)",
    )
    parser.add_argument(
        "--emit-plist", action="store_true",
        help="print one emitter's rendered plist to stdout instead of running the checks",
    )
    parser.add_argument(
        "--emitter", choices=("make", "install-sh"), default="make",
        help="which emitter --emit-plist should render with (default: make)",
    )
    parser.add_argument("--slot", type=int, default=0, help="slot index for --emit-plist")
    parser.add_argument(
        "--socket-group", default=SAMPLE_SOCKET_GROUP,
        help="group name --emit-plist renders into --socket-group=",
    )
    parser.add_argument("--slots", type=int, default=8, help="how many slots to check")
    args = parser.parse_args()

    root = args.repo_root.resolve()

    try:
        rust = extract_rust(root)
        make = extract_makefile(root)
        sh = extract_install_sh(root)
    except (ExtractionError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if args.emit_plist:
        # Render with the emitter's *own* account and staged path, not the
        # Rust ones: a caller comparing this against network.rs's renderer
        # should see a difference when the emitter names something else.
        emitter = make if args.emitter == "make" else sh
        try:
            sys.stdout.write(
                render_plist(
                    emitter["skeleton"],
                    render_wrapper(
                        emitter["wrapper"],
                        emitter["account"],
                        emitter["staged"],
                        args.slot,
                        args.socket_group,
                    ),
                    args.slot,
                )
            )
        except ExtractionError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        return 0

    slots = list(range(args.slots))
    failures = check_uuids(slots)
    failures += check_emitter_inventory(root)
    failures += check_three_way(rust, make, sh)
    failures += check_resolver_copies(root)
    failures += check_wrapper_structure(rust["wrapper"], rust["account"], rust["staged"])
    try:
        failures += check_rendered_plists(make, sh, rust["account"], rust["staged"], slots)
    except ExtractionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        failures += 1

    print()
    if failures:
        print(f"{failures} check(s) failed.", file=sys.stderr)
        return 1
    print("All vmnet emitter equivalence checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
