"""install.sh inline constants must match scripts/lib.sh byte-for-byte.

scripts/lib.sh is the canonical source of truth for the cosign pin
(version + per-arch sha256). install.sh carries an inline copy of those
constants because `curl install.sh | bash` has no adjacent lib.sh to
source — the bash process is reading from stdin. The inline copy is a
bootstrap that the in-tree resolver overrides when a local lib.sh
exists.

This test guards against silent drift: any cosign bump that updates
lib.sh without updating install.sh (or vice-versa) fails the build.

Spec 5 § 3.1.9 prescribes "Any future cosign pin bump touches exactly
one file — scripts/lib.sh." This test reduces install.sh to a regenerated
mirror: edit lib.sh, run this test, copy any mismatch into install.sh
in one diff.
"""

from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent.parent / "scripts"

CONSTANTS = ("COSIGN_VERSION", "COSIGN_SHA256_AMD64", "COSIGN_SHA256_ARM64")


def _parse(path: Path) -> dict[str, str]:
    """Extract `<NAME>="<VALUE>"` assignments from a shell file."""
    text = path.read_text()
    out: dict[str, str] = {}
    for name in CONSTANTS:
        m = re.search(rf'^{name}="([^"]+)"', text, flags=re.MULTILINE)
        if not m:
            raise AssertionError(f"{path.name} missing {name} assignment")
        out[name] = m.group(1)
    return out


def test_install_sh_constants_match_lib_sh():
    lib = _parse(SCRIPTS / "lib.sh")
    install = _parse(SCRIPTS / "install.sh")
    for name in CONSTANTS:
        assert lib[name] == install[name], (
            f"drift on {name}: lib.sh={lib[name]!r} install.sh={install[name]!r}\n"
            f"scripts/lib.sh is canonical — sync install.sh's inline copy to match."
        )
