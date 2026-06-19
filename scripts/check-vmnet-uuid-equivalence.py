#!/usr/bin/env python3
"""Cross-language UUID equivalence guard for vmnet slot network identifiers.

Computes the per-slot `--vmnet-network-identifier` UUID for a range of slot
indices via the same algorithm used by both the Rust code (`network.rs`
`vmnet_slot_network_identifier`) and the Makefile's `setup-darwin-vmnet-plists`
Python one-liner, then asserts they are identical.

Both implementations use:
  SHA1(SANDBOXD_VMNET_NAMESPACE || slot.to_be_bytes_u16())
  then set version=5 (top nibble of byte 6) and variant=RFC4122 (top 2 bits
  of byte 8), formatted as 8-4-4-4-12 lowercase hex.

The SANDBOXD_VMNET_NAMESPACE bytes are the same in both places:
  [0x6d, 0x4f, 0x6e, 0x2b, 0x95, 0x8a, 0x4f, 0x1a,
   0xa2, 0x31, 0x7e, 0x8c, 0xd0, 0x12, 0x3e, 0x5b]

Expected values (from `test_vmnet_network_identifier_pinned_values` in
sandbox-core/src/network.rs) used as the ground truth for this script.
If this script and the Rust test disagree on an expected value, the Rust
test (which is run in CI by `make test`) is authoritative — fix this
script's EXPECTED dict to match.

If either implementation's output diverges from EXPECTED, L2 inter-slot
isolation silently breaks because the launchd daemons run different
network-identifier UUIDs than the daemon expects.
"""

import hashlib
import struct
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


def derive_uuid(slot: int) -> str:
    """Derive the UUIDv5 network-identifier for a given slot index.

    Algorithm (matches both Rust and Makefile Python one-liner):
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


def main() -> int:
    failures = 0
    slots_to_check = list(range(8))  # default pool size; extend if needed

    for slot in slots_to_check:
        computed = derive_uuid(slot)
        expected = EXPECTED.get(slot)

        if expected is not None and computed != expected:
            print(
                f"FAIL slot {slot}: Python computed {computed!r} "
                f"but expected {expected!r} (from Rust pinned test). "
                "The namespace bytes or algorithm has diverged — "
                "update network.rs, the Makefile, AND this script together.",
                file=sys.stderr,
            )
            failures += 1
        else:
            print(f"OK   slot {slot}: {computed}")

    if failures:
        print(
            f"\n{failures} slot(s) failed UUID equivalence check.",
            file=sys.stderr,
        )
        return 1

    print(f"\nAll {len(slots_to_check)} slot UUIDs match the Rust pinned values.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
