# Releasing

A release is a git tag `vX.Y.Z` pushed to `master`. The tag push fires
`.github/workflows/release.yml`, which builds the `x86_64` and `aarch64`
tarballs, signs them (sigstore keyless OIDC), attaches a SLSA
build-provenance attestation, and uploads everything to the GitHub
Release. There is no separate "publish" button — pushing the tag *is*
the release.

## Bump the workspace version before tagging

The tag must match the crate version or the workflow's first step fails.
Steps:

1. Bump the `version` field to `X.Y.Z` in **every** workspace member's
   `Cargo.toml` — all 9 crates, in lockstep, never just one:
   `sandboxd`, `sandbox-cli`, `sandbox-core`, `sandbox-guest`,
   `sandbox-event-emitter`, `sandbox-lima-helper`, `sandbox-route-helper`,
   `sandbox-nft-allow-logger`, `sandbox-nft-deny-logger`. (The `version`
   is each crate's own field — there is no inherited `workspace.package`
   version.)
2. Refresh `Cargo.lock`: from `sandboxd/`, run any cargo command
   (`cargo check --workspace` or `cargo metadata`) so the 9 member
   `version` entries update. Confirm the lock diff touches *only* those
   9 lines — no external-dependency churn.
3. Commit on `master` (the release process commits to `master`
   directly, not a branch), then `git tag vX.Y.Z` and
   `git push origin master vX.Y.Z`.

## Why all 9 must match

- The workflow sanity-checks the pushed tag against
  `sandboxd/sandboxd/Cargo.toml`'s `version` and aborts on mismatch
  (`release.yml`, "Resolve version" step).
- The version is the daemon's compile-time `CARGO_PKG_VERSION`, which at
  runtime composes the `sandbox-gateway:<version>` and
  `sandboxd-lite:<version>` image tags (the daemon refuses `:latest`).
  `make gateway-image` / `make lite-image` tag from `sandbox-core`'s
  version. If the daemon, the gateway image, and the tarball `MANIFEST`
  disagree on the version string, `sandbox session create` can't find
  its gateway image.

So a half-bumped workspace (some crates `0.1.2`, others `0.1.0`) is a
latent break even when it compiles. Bump all 9 or none.
