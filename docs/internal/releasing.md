# Releasing

A release is a git tag `vX.Y.Z` pushed to `master`. The tag push fires
`.github/workflows/release.yml`, which builds the `x86_64` and `aarch64`
tarballs, signs them (sigstore keyless OIDC), attaches a SLSA
build-provenance attestation, and uploads everything to the GitHub
Release. There is no separate "publish" button — pushing the tag *is*
the release.

## Bump the workspace version before tagging

There is **one** version for the whole workspace. Every crate inherits
it via `version.workspace = true`, so the single source of truth is the
`[workspace.package].version` field in the workspace root
`sandboxd/Cargo.toml`. Releasing:

1. Edit `sandboxd/Cargo.toml` → `[workspace.package]` → `version =
   "X.Y.Z"`. That one line is the entire bump — do **not** add per-crate
   `version` fields back to the members.
2. Refresh `Cargo.lock`: from `sandboxd/`, run any cargo command
   (`cargo check --workspace` or `cargo metadata`) so the member
   `version` entries update.
3. Commit on `master` (the release process commits to `master`
   directly, not a branch), then `git tag vX.Y.Z` and
   `git push origin master vX.Y.Z`.

## Why the version is centralised

The version is each crate's compile-time `CARGO_PKG_VERSION`, and three
things must agree on it byte-for-byte:

- The release workflow sanity-checks the pushed tag against
  `[workspace.package].version` in `sandboxd/Cargo.toml` and aborts on
  mismatch (`release.yml`, "Resolve version" step).
- The daemon composes the `sandbox-gateway:<version>` and
  `sandboxd-lite:<version>` image tags from its `CARGO_PKG_VERSION` at
  runtime (it refuses `:latest`). `make gateway-image` / `make
  lite-image` tag from the same `[workspace.package].version`. If the
  daemon, the gateway image, and the tarball `MANIFEST` disagree,
  `sandbox session create` can't find its gateway image.
- `sandbox-core::guest::SANDBOX_GUEST_VERSION` (stamped into
  `sessions.guest_binary_version`) is just `CARGO_PKG_VERSION` — the
  guest binary shares the one workspace version, so there is no separate
  guest-version bookkeeping.

Because every crate inherits the single `[workspace.package].version`, a
half-bumped workspace is structurally impossible: bump that one field
and the daemon, every helper, the images, and the guest stamp all move
together.
