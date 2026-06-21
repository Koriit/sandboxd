# Releasing

A release is a git tag `vX.Y.Z` pushed to `master`. The tag push fires
`.github/workflows/release.yml`, which builds the Linux and macOS release
tarballs, signs them (sigstore keyless OIDC), attaches SLSA build-provenance
attestations, and uploads everything to the GitHub Release. There is no
separate "publish" button — pushing the tag *is* the release.

## Released artifacts per tag

Three tarballs are produced per release:

| Tarball | Runner | Contents |
|---|---|---|
| `sandboxd-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz` | `ubuntu-22.04` | `bin/{sandboxd,sandbox,sandbox-route-helper,sandbox-lima-helper,sandbox-guest}`, `systemd/sandboxd.service`, `images/sandbox-gateway-linux-amd64-X.Y.Z.tar` |
| `sandboxd-X.Y.Z-aarch64-unknown-linux-gnu.tar.gz` | `ubuntu-22.04-arm` | Same layout, `images/sandbox-gateway-linux-arm64-X.Y.Z.tar` |
| `sandboxd-X.Y.Z-aarch64-apple-darwin.tar.gz` | `macos-14` | `bin/{sandboxd,sandbox,sandbox-agent,sandbox-guest}` (Mach-Os ad-hoc-signed; `sandbox-guest` is a linux/arm64 ELF), `launchd/{io.sandboxd.daemon.plist,io.sandboxd.agent.plist}`, `images/sandbox-gateway-linux-arm64-X.Y.Z.tar` |

Each tarball is accompanied by a `.sigstore` cosign bundle and a SLSA
build-provenance attestation.

### macOS tarball notes

- The three host binaries (`sandboxd`, `sandbox`, `sandbox-agent`) are
  arm64 Mach-Os, ad-hoc-signed with `codesign -s -`. AMFI requires a valid
  code signature on every Mach-O before `execve()` — the ad-hoc signature
  satisfies this requirement without an Apple Developer ID.
- `sandbox-guest` is a linux/arm64 ELF produced by a dockerized cross-compile
  (`make build-guest-linux-aarch64`). It is NOT signed — ELF files are not
  subject to AMFI.
- The macOS runner does not build gateway images. The linux-arm64 gateway
  image tarball is produced by the `ubuntu-22.04-arm` cell and passed to the
  `macos-14` cell via GitHub Actions workflow artifacts (`actions/upload-artifact`
  + `actions/download-artifact`). This is the canonical cross-cell handoff
  mechanism — the macOS tarball includes only the linux-arm64 gateway image,
  because the gateway Lima VM always runs linux/arm64.
- No `sandbox-route-helper` or `sandbox-lima-helper` in the macOS tarball.
  `sandbox-route-helper` runs inside the gateway Lima VM (shipped in the gateway
  image). `sandbox-lima-helper` is a Linux setcap helper and does not apply to
  macOS.

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
