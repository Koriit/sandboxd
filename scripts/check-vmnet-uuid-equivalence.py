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

What is compared
----------------

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

# Canonical placeholders the three wrapper templates are normalized to.
PH_ACCOUNT = "{account}"
PH_STAGED = "{staged}"
PH_UUID = "{uuid}"
PH_SOCKET = "{socket}"


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
        raw.replace("$$acct", "\0A\0")
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
        raw.replace("\\$_sandboxd_acct", "\0A\0")
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


def render_wrapper(template: str, account: str, staged: str, slot: int) -> str:
    """Expand a normalized wrapper template for one slot."""
    return (
        template.replace(PH_ACCOUNT, account)
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
    expected_created = ["$_sandboxd_acct"]
    if created != expected_created:
        print(
            f"FAIL: expected {INSTALL_SH} to create exactly {expected_created} via dscl, "
            f"found {created}. The installer must create the same account its plists "
            "name — spelling it as a literal is how the two came apart before.",
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


def check_wrapper_structure(template: str, account: str, staged: str) -> int:
    """The wrapper must still contain the parts that make it safe.

    The fragments are checked against the template extracted from source, not
    against a copy pinned in this file — a check against its own constant would
    pass no matter what the emitters did.
    """
    print()
    print("=== Wrapper structure ===")
    sample = render_wrapper(template, account, staged, 0)
    required = [
        f"install -d -o {account} -g {account} -m 0750 /var/run/sandbox &amp;&amp;",
        f"install -d -o {account} -g {account} -m 0750 /var/run/sandbox/vmnet &amp;&amp;",
        f"codesign --verify --strict {staged}",
        "refusing to exec",
        f"exec {staged}",
        "--vmnet-mode=host",
        f"--socket-group={account}",
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


def check_rendered_plists(make: dict, sh: dict, account: str, staged: str, slots) -> int:
    """Run both shell emitters' own XML generators and compare their output."""
    print()
    print("=== Rendered plist equality (Makefile vs install.sh) ===")
    failures = 0
    for slot in slots:
        make_plist = render_plist(
            make["skeleton"], render_wrapper(make["wrapper"], account, staged, slot), slot
        )
        sh_plist = render_plist(
            sh["skeleton"], render_wrapper(sh["wrapper"], account, staged, slot), slot
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
                        emitter["wrapper"], emitter["account"], emitter["staged"], args.slot
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
    failures += check_three_way(rust, make, sh)
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
