# Release & Install Infrastructure — Design

**Date:** 2026-05-11
**Status:** Approved
**Scope:** GitHub Actions release pipeline (tagged-version builds, sigstore attestations, multi-arch tarballs); self-contained per-arch release tarball layout (daemon + CLI + route-helper + gateway image + systemd unit + MANIFEST); `install.sh` and `uninstall.sh` curl|bash bootstrap scripts hosted on GitHub Pages; idempotent state-inspection design; `/var/lib/sandbox/.install-state.json` forensic record; `/var/log/sandbox-install.log` structured journal; Lima-based E2E harness for install/uninstall on real Linux VMs.

---

## 0 · Sequence context

This spec is **Spec 4 of a five-spec arc** that prepares `sandboxd` for an end-user
install / uninstall / update story. The arc:

1. **Spec 1** — Helper identity assertion (committed at
   `.tasks/specs/2026-05-11-helper-identity-assertion-design.md`, SHA `246bbdd`)
2. **Spec 2** — API session isolation + guest version compatibility (committed
   revised at `.tasks/specs/2026-05-11-api-session-isolation-guest-compat-design.md`,
   SHA `7c026aa`)
3. **Spec 3** — Daemon productionization (committed revised at
   `.tasks/specs/2026-05-11-daemon-productionization-design.md`, SHA `7284c44`)
4. **Spec 4 (this one)** — Release & install infrastructure
5. **Spec 5** — Update infrastructure (`sandbox update` CLI, config migration
   framework, backups, lock file)

Spec 4 strictly depends on Spec 3: the system artifacts Spec 4 ships and installs
are the artifacts Spec 3 specified — the `sandbox` system user (Spec 3 § 3), the
systemd unit at `/etc/systemd/system/sandboxd.service` (Spec 3 § 4.1), the state
layout under `/var/lib/sandbox/` with the modes from Spec 3 § 5, the
version-pinned `sandbox-gateway:<DAEMON_VERSION>` image (Spec 3 § 8.5), the
`sandbox-route-helper` with file capabilities (Spec 3 § 6.2 C9), and the
`qemu-bridge-helper` setuid + `/etc/qemu/bridge.conf` substrate inherited from
the existing dev-mode Makefile.

Spec 4 strictly precedes Spec 5: `sandbox update` cannot exist before there is
an install for it to operate on. Spec 5 reuses Spec 4's release pipeline
verbatim — the same tarball, the same MANIFEST, the same cosign verification
chain — to fetch the *new* version's artifacts during an update. The boundary
between Spec 4 and Spec 5 is that **install.sh produces an installation from
scratch on a clean host; `sandbox update` mutates an existing installation in
place.** Idempotency is the bridge: each step in both scripts inspects state
and skips if already at the desired state, so re-running install.sh on a
partially-installed box and running update on a fully-installed box use the
same primitives.

What this spec **does not** cover (§ 11 enumerates this in full): the
`sandbox update` CLI, the config migration framework that applies V001+ to
`/etc/sandboxd/users.conf` during an update, backup mechanics, the lock-file
mutex that prevents concurrent updates, any change to the daemon binary
itself, or release notes / CHANGELOG prose.

## 1 · Motivation

Today the only way to get sandboxd onto a Linux host is to clone the repository
and run `make setup-dev-env` (`Makefile:210`). That target is the developer's
one-shot per-host setup — it installs the cap'd route-helper at the canonical
path, writes `/etc/qemu/bridge.conf`, writes `/etc/sandboxd/users.conf` with the
developer's own UID in `allow_users`, and setuids `qemu-bridge-helper`. The
prerequisites are the entire developer toolchain: Rust 1.88, Go (the gateway
image's CoreDNS plugin), Docker, Python (for the e2e venv), and a clone of the
source tree. The output is a daemon process that runs *as the developer's UID*,
with state under `~/.local/share/sandboxd/`.

End-user / operator deployment needs three properties dev mode does not provide:

- **No source-tree dependency.** Operators receive a binary artifact and place
  it; they do not compile Rust, build CoreDNS plugins, or know what
  `cross` is. The audience identified during the spec-arc brainstorm is the
  ops engineer at a healthcare site rolling sandboxd onto a handful of dev
  machines — not the daemon's author.
- **Auditability.** Every step that elevates privilege is explicit and visible.
  No hidden `sudo`, no opaque package post-install scripts, no daemons started
  out from under the operator's nose. The `make setup-dev-env` target already
  honors this contract (`Makefile:181-198` — every `[sudo]` line is printed
  before the actual `sudo -k` invocation); Spec 4 carries the convention into
  the published install path.
- **Trust.** The artifact the operator extracts must be provably the artifact
  the project built. The chain of custody is: operator → GitHub Pages cert →
  install.sh script → cosign verification of the release tarball's sigstore
  attestation → attestation identity = the project's GitHub Actions workflow
  via OIDC. No long-lived signing keys to rotate, no PGP keyring to seed; the
  authority is "did GitHub Actions in `Koriit/sandboxd` produce this tarball at
  a tagged commit." This is the same trust shape `kubectl`'s release process,
  `helm`'s, and `cosign`'s own use; it is the lowest-friction high-assurance
  option available today.

Spec 3 produced a deployment **shape** (the `sandbox` user, the unit, the state
dir, the `sandbox doctor` diagnostic surface). Spec 4 produces the **pipeline**
that puts that shape onto a host and the inverse that takes it off. The output
of Spec 4 is operator-runnable; the developer's `make setup-dev-env` continues
to work alongside, unchanged (§ 9).

## 2 · The release tarball

### 2.1 · Naming convention

```
sandboxd-<version>-<arch>.tar.gz
```

where `<arch>` is a Rust target triple. Examples:

- `sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz`
- `sandboxd-1.0.0-aarch64-unknown-linux-gnu.tar.gz`

The triple form (vs. a shorter `amd64`/`arm64`) is deliberate: it matches the
target string the operator will see if they ever invoke `cargo build --target`
themselves, it disambiguates `linux-gnu` from a hypothetical `linux-musl`
build (we ship glibc-linked binaries today; the triple makes that explicit),
and it forecloses ambiguity if the project later adds Darwin or BSD targets
that share the `arm64` informal name.

`<version>` is the daemon's semver from `sandboxd/sandboxd/Cargo.toml`'s
`version` field. All workspace crates carry the same version (currently
`"0.1.0"` across `sandbox-core`, `sandboxd`, `sandbox-cli`,
`sandbox-route-helper`, `sandbox-guest`, `sandbox-event-emitter`,
`sandbox-nft-allow-logger`, `sandbox-nft-deny-logger`) and bump together
at release time. Spec 3 § 7.4 fixes this constraint: `make build` runs
`cargo build --workspace`, and the CLI's strict-equality `/version` check
(Spec 3 § 7.1) demands that the daemon and CLI installed on the same host
share a version string. The tarball reflects that: one version, one tarball
per arch, both binaries inside.

### 2.2 · Tarball contents

The tarball expands to a single top-level directory matching its basename:

```
sandboxd-1.0.0-x86_64-unknown-linux-gnu/
├── MANIFEST                                       # JSON; see § 2.3
├── bin/
│   ├── sandboxd                                   # daemon, mode 0755 in tar
│   ├── sandbox                                    # CLI, mode 0755 in tar
│   └── sandbox-route-helper                       # helper (caps applied by install.sh § 4.4.15)
├── libexec/
│   └── (intentionally empty — install.sh places sandbox-route-helper
│        at /usr/local/libexec/sandboxd/ from bin/sandbox-route-helper)
├── systemd/
│   └── sandboxd.service                           # canonical copy from sandboxd/contrib/systemd/
├── images/
│   └── sandbox-gateway-1.0.0.tar                  # `docker save` output; ~200-400 MB
└── attestations/
    ├── sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz.sigstore
    │                                              # cosign attestation bundle for the outer tarball
    └── sandbox-gateway-1.0.0.tar.sigstore         # cosign attestation bundle for the gateway image tarball
```

Three properties of the layout:

1. **No lite image tarball.** Spec 3 § 8.4 specifies that
   `sandboxd-lite:<DAEMON_VERSION>` is built **by the daemon itself**, on
   demand, on first session create — its Dockerfile is embedded via
   `include_str!` (`sandbox-core/src/backend/container.rs:144`) and depends only
   on public Debian packages plus the workspace's `sandbox-guest` binary, which
   is already present in the release tarball as part of the daemon's static
   data. Shipping a `docker save`d lite image tarball would duplicate ~200 MB
   of layer data that the daemon can reconstruct locally in seconds. The
   trade-off pays for itself the first time a host has the daemon installed
   but has never created a container-backend session.
2. **Gateway image is shipped, not built on demand.** Spec 3 § 8.5 specifies
   that `sandbox-gateway:<DAEMON_VERSION>` is **not** rebuilt by the daemon —
   its build pulls Envoy / mitmproxy / CoreDNS from upstream registries and
   compiles a Go binary plus two Rust nft-loggers from the workspace
   (`networking/gateway/Dockerfile` is multi-stage with a `golang:1.22` builder
   stage and Rust builders for the deny/allow loggers). Reproducing that build
   on every install host would require Docker plus the source tree plus
   network access to upstream registries. Shipping the image as a `docker
   save`d tar removes all of that.
3. **The `libexec/` directory is empty in the tarball.** It exists only to
   document that route-helper's final destination is
   `/usr/local/libexec/sandboxd/sandbox-route-helper` (matching
   `ROUTE_HELPER_INSTALL_PATH` at `sandboxd/sandboxd/src/main.rs:363` and the
   dev-mode Makefile's `ROUTE_HELPER_PROD_PATH := /usr/local/libexec/sandboxd/sandbox-route-helper`
   at `Makefile:204`). Putting the binary itself under `bin/` in the tarball
   simplifies the install script (one `install -m 0755 bin/<x> <dst>` call
   per binary) at the cost of a one-line layout note in this section.

Tar entries use `tar` defaults: mode bits as written, owner `root:root` (the
release workflow creates the tarball as the workflow user; `tar` strips
ownership for unprivileged extracts; install.sh resets ownership with
`install -o root -g root`). Symlinks: none.

### 2.3 · MANIFEST format

The MANIFEST is JSON, in keeping with the project's "config files are JSON"
convention from `CLAUDE.md`. The tradeoff vs. KEY=VALUE: JSON requires `jq` (or
a Python one-liner) to parse from shell, but the install script will already
depend on `jq` for inspecting the install-state file (§ 4.5). One dependency
covers both surfaces. KEY=VALUE would avoid `jq` but force the install script
to ship a regex parser, and the MANIFEST grows fields over time (build
provenance, additional binaries) which JSON tolerates better than ad-hoc
key=value.

Format (example, with comments stripped for the on-disk file):

```json
{
  "version": "1.0.0",
  "arch": "x86_64-unknown-linux-gnu",
  "build_sha": "0123456789abcdef0123456789abcdef01234567",
  "build_time": "2026-05-11T14:23:11Z",
  "artifacts": {
    "sandboxd": {
      "path": "bin/sandboxd",
      "sha256": "sha256hexsha256hex..."
    },
    "sandbox": {
      "path": "bin/sandbox",
      "sha256": "..."
    },
    "sandbox-route-helper": {
      "path": "bin/sandbox-route-helper",
      "sha256": "..."
    },
    "gateway-image": {
      "path": "images/sandbox-gateway-1.0.0.tar",
      "sha256": "...",
      "docker_tag": "sandbox-gateway:1.0.0"
    },
    "systemd-unit": {
      "path": "systemd/sandboxd.service",
      "sha256": "..."
    }
  }
}
```

Required top-level keys: `version`, `arch`, `build_sha`, `build_time`,
`artifacts`. Each entry in `artifacts` has `path` (relative to the tarball
root) and `sha256` (lowercase hex). `gateway-image` additionally carries
`docker_tag` so install.sh knows what tag to expect after `docker load`.

Forward-compat for the MANIFEST: install.sh consults only the documented
fields and tolerates additional keys (the existing `jq '.artifacts.X.sha256
// empty'` pattern in shell handles missing fields without erroring). New
optional fields can land without breaking older install.sh; required fields
graduate from optional through the same lifecycle as Spec 3 § 0's JSON-blob
forward-compat rule (write under `Option<T>` first, require in a later release
once every supported install.sh version reads them).

### 2.4 · Tarball size — sanity

Approximate sizes for a release-profile build (`cargo build --workspace
--release`):

| Component             | Size (approx) |
|-----------------------|---------------|
| `sandboxd` binary     | 30–80 MB      |
| `sandbox` CLI         | 5–15 MB       |
| `sandbox-route-helper`| 5–15 MB       |
| `sandboxd.service`    | <1 KB         |
| `sandbox-gateway-<v>.tar` | 200–400 MB |
| MANIFEST + attestations | <100 KB    |
| **Total (compressed)** | **~250–500 MB** |

The total is dominated by the gateway image's debian-slim base + Envoy + mitmproxy
+ CoreDNS binary layers. That is the cost of shipping the image vs. building it
on demand (which Spec 3 § 8.5 rules out for the gateway). A 500 MB tarball
downloads in under two minutes on a 30 Mbit/s connection — acceptable for a
single-shot operator install.

The lite image's omission (§ 2.2.1) saves a further 100–200 MB; we accept the
trade-off (the daemon rebuilds it on first session create) because it is the
only image whose build is fully self-contained in the daemon binary.

## 3 · GitHub Actions release workflow

The release workflow lives at `.github/workflows/release.yml`, parallel to the
existing `.github/workflows/ci.yml` (push/PR Rust build+test) and
`.github/workflows/docs.yml` (Astro site → GitHub Pages on push to `main`).
It runs independently of both; the trigger is tag-based, not branch-based.

### 3.1 · Trigger

```yaml
on:
  push:
    tags:
      - 'v[0-9]+.[0-9]+.[0-9]+'           # e.g. v1.0.0, v1.2.3
      - 'v[0-9]+.[0-9]+.[0-9]+-*'         # e.g. v1.0.0-rc1, v1.0.0-alpha.2
```

The release process is: bump every crate's `version` field (`sandboxd/*/Cargo.toml`)
to `X.Y.Z`, commit on `main`, tag `vX.Y.Z`, push the tag. The workflow fires on
the tag push and builds against the tagged commit. Pre-release tags
(`-rc1`, `-alpha.2`) are supported by the second pattern so release-candidate
testing can use the same pipeline. The workflow does **not** fire on branch
pushes, on PRs, or on releases edited in the GitHub UI.

### 3.2 · Matrix

Two parallel jobs, one per supported arch. The arch is also the tarball's
`<arch>` component (§ 2.1) and the `MANIFEST.arch` value (§ 2.3).

```yaml
jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            runner: ubuntu-22.04
          - target: aarch64-unknown-linux-gnu
            runner: ubuntu-22.04-arm   # GitHub-hosted ARM64 Linux runner; GA since 2025
    runs-on: ${{ matrix.runner }}
```

`fail-fast: false` so an aarch64 build failure doesn't cancel a successful
x86_64 build mid-flight — the release is published partial (single arch
attached, second arch missing) which is recoverable; a fast-fail would orphan
sigstore attestations.

**Native vs. cross.** GitHub-hosted ARM64 Linux runners (`ubuntu-22.04-arm`,
`ubuntu-24.04-arm`) are generally available as of 2025 on every plan tier; we
build natively on them rather than cross-compile. Native build avoids the
`cross`-toolchain class of glibc-version mismatches (where a cross-built
binary refuses to run on a target host with an older glibc than the
cross-toolchain shipped). Spec 4 § 10.1 flags the fallback (`cross`, or a
self-hosted aarch64 runner) if GitHub's hosted ARM runner becomes unavailable
or unusable.

### 3.3 · Steps (per arch)

The complete per-arch job, with rationale inline:

```yaml
    permissions:
      contents: write       # for attaching artifacts to the GitHub Release
      id-token: write       # for sigstore keyless signing via GH Actions OIDC
      attestations: write   # for actions/attest-build-provenance
    steps:
      - name: Checkout (at the tag)
        uses: actions/checkout@v4
        with:
          fetch-depth: 0    # full history; build_sha needs the resolved commit

      - name: Resolve version
        id: version
        run: |
          tag="${GITHUB_REF#refs/tags/}"          # vX.Y.Z[-prerelease]
          ver="${tag#v}"                          # X.Y.Z[-prerelease]
          echo "tag=$tag"  >> "$GITHUB_OUTPUT"
          echo "ver=$ver"  >> "$GITHUB_OUTPUT"
          # Sanity-check: the Cargo.toml version must match the tag.
          # Pull `sandboxd/sandboxd/Cargo.toml`'s version field and compare.
          cargo_ver=$(awk -F'"' '/^version/ { print $2; exit }' \
              sandboxd/sandboxd/Cargo.toml)
          if [ "$cargo_ver" != "$ver" ]; then
            echo "::error::tag $tag does not match Cargo.toml version $cargo_ver" >&2
            exit 1
          fi

      - name: Install Rust toolchain (pinned)
        uses: dtolnay/rust-toolchain@stable
        with:
          # Read from rust-toolchain.toml in the workspace; ensures CI and
          # release use the same channel (currently 1.88.0, see
          # sandboxd/rust-toolchain.toml).
          toolchain: '1.88.0'
          components: clippy, rustfmt

      - name: Cache cargo registry and build
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            sandboxd/target
          key: release-${{ matrix.target }}-${{ hashFiles('sandboxd/**/Cargo.lock') }}

      - name: Build workspace (release profile)
        working-directory: sandboxd
        run: cargo build --workspace --release --target ${{ matrix.target }}

      - name: Build gateway image
        # Note: `make gateway-image` invokes `docker build -t sandbox-gateway -f
        # networking/gateway/Dockerfile .` (Makefile:139-140). Spec 3 § 8.3
        # changes this target to tag with $(GATEWAY_VERSION) — the same as the
        # daemon's Cargo.toml version. We invoke the (post-Spec-3) target and
        # then re-tag for clarity below.
        env:
          GATEWAY_VERSION: ${{ steps.version.outputs.ver }}
        run: |
          make gateway-image
          docker tag sandbox-gateway:${GATEWAY_VERSION} \
                     sandbox-gateway:${GATEWAY_VERSION}-${{ matrix.target }}
          docker save sandbox-gateway:${GATEWAY_VERSION} \
              -o sandbox-gateway-${GATEWAY_VERSION}.tar

      - name: Assemble tarball
        env:
          VER: ${{ steps.version.outputs.ver }}
          ARCH: ${{ matrix.target }}
          BUILD_SHA: ${{ github.sha }}
        run: |
          stage="sandboxd-${VER}-${ARCH}"
          mkdir -p "$stage"/{bin,libexec,systemd,images,attestations}
          install -m 0755 \
              sandboxd/target/${ARCH}/release/sandboxd \
              "$stage/bin/sandboxd"
          install -m 0755 \
              sandboxd/target/${ARCH}/release/sandbox \
              "$stage/bin/sandbox"
          install -m 0755 \
              sandboxd/target/${ARCH}/release/sandbox-route-helper \
              "$stage/bin/sandbox-route-helper"
          install -m 0644 \
              sandboxd/contrib/systemd/sandboxd.service \
              "$stage/systemd/sandboxd.service"
          mv sandbox-gateway-${VER}.tar \
             "$stage/images/sandbox-gateway-${VER}.tar"
          # Generate MANIFEST (§ 2.3 shape).
          python3 - <<'PY' "$stage" "$VER" "$ARCH" "$BUILD_SHA"
          import hashlib, json, os, sys, datetime
          stage, ver, arch, build_sha = sys.argv[1:5]
          def sha256(p):
              h = hashlib.sha256()
              with open(p, "rb") as f:
                  for blk in iter(lambda: f.read(1 << 20), b""):
                      h.update(blk)
              return h.hexdigest()
          artifacts = {
              "sandboxd":               {"path": "bin/sandboxd"},
              "sandbox":                {"path": "bin/sandbox"},
              "sandbox-route-helper":   {"path": "bin/sandbox-route-helper"},
              "gateway-image":          {"path": f"images/sandbox-gateway-{ver}.tar",
                                          "docker_tag": f"sandbox-gateway:{ver}"},
              "systemd-unit":           {"path": "systemd/sandboxd.service"},
          }
          for a in artifacts.values():
              a["sha256"] = sha256(os.path.join(stage, a["path"]))
          manifest = {
              "version":     ver,
              "arch":        arch,
              "build_sha":   build_sha,
              "build_time":  datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
              "artifacts":   artifacts,
          }
          with open(os.path.join(stage, "MANIFEST"), "w") as f:
              json.dump(manifest, f, indent=2, sort_keys=True)
          PY
          tar -czf "${stage}.tar.gz" "$stage"

      - name: Install cosign (pinned)
        uses: sigstore/cosign-installer@v3.7.0   # pinned by major+minor
        with:
          cosign-release: 'v2.4.1'                # pinned exact

      - name: Sign tarball (keyless OIDC)
        env:
          VER:  ${{ steps.version.outputs.ver }}
          ARCH: ${{ matrix.target }}
        run: |
          cosign sign-blob --yes \
              --bundle "sandboxd-${VER}-${ARCH}.tar.gz.sigstore" \
              "sandboxd-${VER}-${ARCH}.tar.gz"

      - name: Build provenance attestation
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: 'sandboxd-${{ steps.version.outputs.ver }}-${{ matrix.target }}.tar.gz'

      - name: Upload artifacts to GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ steps.version.outputs.tag }}
          fail_on_unmatched_files: true
          files: |
            sandboxd-${{ steps.version.outputs.ver }}-${{ matrix.target }}.tar.gz
            sandboxd-${{ steps.version.outputs.ver }}-${{ matrix.target }}.tar.gz.sigstore
```

A second top-level job (`publish-install-script`, see § 4.1) runs after both
matrix jobs succeed and publishes `scripts/install.sh` + `scripts/uninstall.sh`
to GitHub Pages so `https://Koriit.github.io/sandboxd/install.sh` resolves to
the latest version of the script.

### 3.4 · Pinned versions

The workflow pins every external action and tool by version (and where
practical, by SHA), so a release built today is reproducible-to-the-extent-
the-toolchain-allows from the same tag tomorrow:

| Component                         | Pin                                                                                  |
|-----------------------------------|--------------------------------------------------------------------------------------|
| Rust toolchain                    | `1.88.0` (from `sandboxd/rust-toolchain.toml`; matches `ci.yml`'s `@stable` once 1.88 is the stable channel; pin explicitly to remove the floating-`stable` dependency) |
| `actions/checkout`                | `v4` (line up with `ci.yml:13`)                                                      |
| `actions/cache`                   | `v4` (line up with `ci.yml:22`)                                                      |
| `dtolnay/rust-toolchain`          | `@stable` with explicit `toolchain: '1.88.0'`                                        |
| `sigstore/cosign-installer`       | `@v3.7.0` (action), installing `cosign v2.4.1` (binary)                              |
| `actions/attest-build-provenance` | `@v1`                                                                                |
| `softprops/action-gh-release`     | `@v2`                                                                                |
| Docker engine                     | whatever the GitHub-hosted runner ships (24.x at time of writing); not pinned, but documented in § 10.1 as a known release-reproducibility caveat |

The pin discipline carries through to install.sh's embedded cosign-binary
checksum (§ 4.4.8) so an air-gapped install verifying offline gets the same
binary the release pipeline used.

### 3.5 · Permissions

The workflow's top-level `permissions:` block is the minimum required:

```yaml
permissions:
  contents: write       # action-gh-release: upload tarball + sigstore bundle
  id-token: write       # sigstore keyless: short-lived OIDC token from GH Actions
  attestations: write   # actions/attest-build-provenance: write to repo's attestations API
```

No `packages: write` (we do not push to GHCR), no `pages: write` on the build
job (Pages publication is a separate job — see § 4.1 — and runs with only
`pages: write` + `id-token: write`).

### 3.6 · Build provenance / SLSA

`actions/attest-build-provenance@v1` generates a SLSA Build Level 3 provenance
attestation alongside the tarball — `{tarball-name}.intoto.jsonl` — bound to
the workflow that produced it. The attestation is uploaded to GitHub's
attestation API and discoverable via `gh attestation verify`. install.sh
verifies the provenance with cosign:

```sh
cosign verify-blob \
    --bundle "${tarball}.sigstore" \
    --certificate-identity-regexp "^https://github.com/Koriit/sandboxd/\.github/workflows/release\.yml@" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${tarball}"
```

The `--certificate-identity-regexp` is anchored to the workflow file path so
a tarball signed by *any other workflow in the repo* would be rejected.
The `^` and trailing `@` are load-bearing — they prevent a workflow at a
different file path from passing. The OIDC issuer is fixed; sigstore's
Fulcio CA only accepts GH-Actions OIDC tokens signed by that issuer.

Spec 4 ships the cosign verification command verbatim in install.sh § 4.4.10.

## 4 · `install.sh`

### 4.1 · Hosting

`https://Koriit.github.io/sandboxd/install.sh`, served from the existing
GitHub Pages deployment.

The current `.github/workflows/docs.yml` deploys the Astro site under
`site/dist` to Pages via `actions/upload-pages-artifact@v3` +
`actions/deploy-pages@v4` (`docs.yml:55, 69`). install.sh and uninstall.sh
ride this pipeline: a new directory `site/public/` (Astro's
conventional location for files copied verbatim into `dist/`) holds the
scripts, so each `docs.yml` build copies them into the Pages output. The
URL `https://Koriit.github.io/sandboxd/install.sh` resolves directly to the
deployed file.

The canonical authored copies live in the repo at `scripts/install.sh` and
`scripts/uninstall.sh`. A pre-commit hook (or a `make install-scripts-sync`
target) copies them to `site/public/` so the Pages deployment picks them up.
Spec 4 commits this convention; Spec 4's implementation may choose between:

- **Symlink** `site/public/install.sh` → `../../scripts/install.sh` (works
  on Linux, Astro's build follows symlinks at copy time);
- **Build-time copy** in the docs workflow: `cp scripts/install.sh site/public/`
  as a step in `docs.yml` before `npm run build`.

Either is acceptable; the spec leaves the implementation to discretion. The
release workflow does **not** re-publish the scripts (they ride the docs
deploy); a release of new daemon binaries does not need to change the
install script's URL. install.sh fetches the *tarball* from a release; the
script itself updates only when its source in `scripts/install.sh` changes
and `main` is pushed.

### 4.2 · Invocation patterns

Documented for operator-facing use:

```sh
# Latest tagged release
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash

# A specific version
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | \
    bash -s -- --version 1.1.0

# Air-gapped (operator already has the tarball locally)
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | \
    bash -s -- --from /path/to/sandboxd-1.1.0-x86_64-unknown-linux-gnu.tar.gz

# Air-gapped + local sigstore bundle (no network at all)
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | \
    bash -s -- \
      --from /path/to/sandboxd-1.1.0-x86_64-unknown-linux-gnu.tar.gz \
      --cosign-bundle /path/to/sandboxd-1.1.0-x86_64-unknown-linux-gnu.tar.gz.sigstore

# Non-interactive (no prompts; refuse destructive choices)
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash -s -- --yes

# Pre-existing install: the script detects /usr/local/bin/sandboxd, reads its
# version, and if it differs from target, refuses with a hint pointing at
# `sandbox update` (Spec 5).
```

All flags:

| Flag                    | Argument        | Effect                                                                                              |
|-------------------------|-----------------|-----------------------------------------------------------------------------------------------------|
| `--version`             | semver string   | Pin install to that release tag. Default: latest GitHub Release.                                    |
| `--from`                | local file path | Use the local tarball instead of downloading. The path must point at a `sandboxd-<v>-<arch>.tar.gz`. |
| `--cosign-bundle`       | local file path | Use the local sigstore bundle instead of downloading. Requires `--from`.                            |
| `--source-url`          | URL             | Override the base URL for tarball download. Default: GitHub Releases. For mirrors or self-hosting.  |
| `--yes`                 | (none)          | Skip every confirmation prompt. Required for fully non-interactive installs. Refuses to overwrite anything install.sh would normally prompt for. |
| `--verbose`             | (none)          | Echo every command before invocation; pass `set -x` semantics into critical sections.               |
| `--quiet`               | (none)          | Suppress non-error output. Errors and failure-recovery hints still print.                           |
| `--no-color`            | (none)          | Force plain text. Overrides TTY auto-detection (§ 4.7).                                              |
| `--help`                | (none)          | Print usage and exit 0.                                                                              |

Unknown flags cause a usage-error exit with code 2.

### 4.3 · Idempotency principle

Every step in install.sh inspects current state and skips if the state already
matches the desired end state. The pattern is:

```sh
inspect_current_state
if state == desired_state; then
    log_skip "step=X reason=already-done"
    return 0
fi
sudo -k <action>
verify_state_now_matches_desired
log_ok "step=X status=ok"
```

Three properties this gives us:

1. **Re-running install.sh after a partial failure resumes exactly where it
   left off.** No `--resume` flag. The script always re-runs every step; the
   inspection in each step makes already-complete work a no-op.
2. **A clean install on a clean host walks every step.** No state-file is
   required as input; the install state file (§ 4.5) is *output*, not input.
3. **The contract composes with `sandbox update` (Spec 5).** Update runs the
   same primitives — install binaries, reload systemd, restart service — but
   on an already-installed host. Idempotency means the steps are
   safe-to-re-run by design.

The mirror principle holds for uninstall.sh (§ 5): each removal inspects "is
this artifact still here?" and skips if absent.

`sudo -k` invalidates the timestamp on the sudo credential, forcing
re-authentication for the next privileged step. This matches the dev-mode
Makefile convention (`Makefile:236, 239, 287, 291, 350, 353, ...`) and makes
each elevation visible — an operator who walks away mid-install must
re-authenticate to continue, foreclosing a class of "I forgot what I was
running" mistakes.

### 4.4 · Step-by-step flow

Every step the script performs, in order. For each step: what it does, the
exact commands, the inspection that achieves idempotency, and the log line
written to `/var/log/sandbox-install.log` (format § 4.6). Privileged steps
use `sudo -k`; the script aborts on the first failure that the step's
recovery hint cannot address.

#### 1. Arg parsing

Parse the flags in § 4.2 with a hand-rolled POSIX `case` loop (no GNU
getopt — install.sh is POSIX, not bash-specific, so it runs on minimal
distros). Set defaults: `VERSION=latest`, `FROM=`, `COSIGN_BUNDLE=`,
`SOURCE_URL=https://github.com/Koriit/sandboxd/releases/download`, `YES=0`,
`VERBOSE=0`, `QUIET=0`, `NO_COLOR=0`.

Validate: `--cosign-bundle` without `--from` is a usage error.

Log line: `step=parse_args version=<v> from=<path-or-->`

#### 2. OS detection

Refuse on anything other than Linux. macOS and BSDs have different package
layouts, no systemd, no `/dev/kvm`, and (on BSDs) different qemu
ecosystems — none of which sandboxd targets.

```sh
case "$(uname -s)" in
  Linux) ;;
  *) die "sandboxd installs on Linux only (got: $(uname -s))" ;;
esac
```

Log line: `step=os_detect os=Linux status=ok`

#### 3. Arch detection

```sh
case "$(uname -m)" in
  x86_64)  ARCH=x86_64-unknown-linux-gnu ;;
  aarch64) ARCH=aarch64-unknown-linux-gnu ;;
  *)       die "unsupported architecture: $(uname -m)" ;;
esac
```

When the tarball is later fetched, install.sh compares `MANIFEST.arch` to
`$ARCH` and refuses on mismatch. This catches the "I gave install.sh an
x86_64 tarball on an aarch64 host" mistake (and prevents a confusing later
failure when the binary fails to exec).

Log line: `step=arch_detect arch=<triple> status=ok`

#### 4. TTY detection + color setup

```sh
if [ -t 1 ] && [ "$NO_COLOR" -eq 0 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'
    YELLOW='\033[0;33m'; BLUE='\033[0;34m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; RESET=''
fi
```

The convention matches the existing Makefile (`Makefile:7-13`): empty escape
codes when stdout is not a TTY, so file/journal capture sees plain text.

Log line: `step=tty_detect tty=<yes|no> color=<yes|no> status=ok`

#### 5. Pre-existing install detection

```sh
if [ -x /usr/local/bin/sandboxd ]; then
    existing_ver=$(/usr/local/bin/sandboxd --version 2>/dev/null | awk '{print $2}')
    if [ "$existing_ver" = "$TARGET_VER" ]; then
        log_ok "step=preexist version=$existing_ver action=skip"
        emit "$GREEN✓$RESET sandboxd $existing_ver is already installed"
        exit 0
    fi
    emit "$YELLOW!$RESET sandboxd $existing_ver is already installed."
    emit "  install.sh installs from scratch only."
    emit "  To upgrade or downgrade, run:"
    emit "      sudo sandbox update --version $TARGET_VER"
    emit "  (Spec 5; not yet available — re-run install.sh once update lands.)"
    log_warn "step=preexist version=$existing_ver target=$TARGET_VER action=refuse"
    exit 1
fi
```

When `sandbox update` (Spec 5) is the canonical upgrade path. install.sh's
job is fresh install; trying to make it do upgrades duplicates logic that
belongs in update. The detection threshold is `/usr/local/bin/sandboxd`
existing and being executable; a half-installed state (binary present,
unit missing) is treated as fresh-install (the unit-install step is
idempotent and writes the unit on top of nothing).

Note that the dev-mode developer's daemon under `~/.local/share/sandboxd/`
is **not** detected here (it does not install a binary at
`/usr/local/bin/sandboxd`). § 9 documents the dev-mode coexistence rules.

Log line: `step=preexist version=<v-or-none> action=<skip|refuse|continue>`

#### 6. Prerequisite check

For each prerequisite, probe and add to a `missing` list. Print the
shopping list at the end and refuse if non-empty.

| Prerequisite             | Probe                                                             |
|--------------------------|-------------------------------------------------------------------|
| Linux kernel ≥ 5.8       | `uname -r` parsed; refuse below 5.8 (Lima requires it).            |
| Docker (rootful)         | `command -v docker && docker info 2>/dev/null | grep -q "^Server:"` |
| Lima                     | `command -v limactl`                                              |
| QEMU                     | `command -v qemu-system-${arch_for_qemu}`                         |
| OVMF firmware            | `[ -f /usr/share/OVMF/OVMF_CODE.fd ] || [ -f /usr/share/edk2/ovmf/OVMF_CODE.fd ] || ...` |
| `setcap`                 | `command -v setcap` (`libcap2-bin` package on Debian-likes)        |
| `jq`                     | `command -v jq`                                                   |
| `curl`                   | `command -v curl`                                                 |

`arch_for_qemu` is `x86_64` on x86_64 hosts and `aarch64` on aarch64. If any
are missing, install.sh prints the package names per detected distro family
(reading `/etc/os-release`'s `ID` and `ID_LIKE`):

```
✗ missing prerequisites:
    - docker:      apt install docker.io       # or follow https://docs.docker.com/engine/install/
    - lima:        apt install lima            # or download from https://github.com/lima-vm/lima/releases
    - jq:          apt install jq
  Install these, then re-run install.sh.
```

Log line: `step=prereq missing=<comma-separated-or-none> status=<ok|fail>`

#### 7. Disk space pre-flight

Approximate footprint: 50 MB at `/usr/local/`, 200 MB at `/var/lib/sandbox/`
(grows with sessions), 500 MB at `/var/lib/docker/` (image layers). Probe
free space at each and refuse with a clear number if short:

```sh
free_kb_at() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }
need /usr/local       50000     # 50 MB
need /var/lib/sandbox 200000    # 200 MB; bind to / if /var/lib does not yet exist
need /var/lib/docker  500000    # 500 MB
```

If `/var/lib/sandbox/` does not yet exist (it won't on a clean host),
substitute the closest existing ancestor (`/var/lib`, then `/var`, then `/`).

Log line: `step=disk_check usr_free=NMB var_free=NMB status=<ok|fail>`

#### 8. Cosign bootstrap

cosign is **auto-downloaded** to `/tmp/sandbox-install-<pid>/cosign` rather
than required pre-installed on the host. Rationale:

- Operator UX: a healthcare-site operator who hasn't seen cosign before
  doesn't need to know what it is. install.sh handles it.
- Trust surface: install.sh pins cosign's binary sha256 inline (§ 7.3). If the
  cosign binary the operator already has on the host is unpinned, the chain
  of trust is wider than necessary; download-then-verify is narrower.

The pinned version is **cosign v2.4.1** (the latest stable at the time of
writing). The script downloads from
`https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64`
(or `-arm64`), verifies the sha256 against an embedded constant, and uses
it for the next step.

```sh
COSIGN_VERSION="v2.4.1"
case "$ARCH" in
  x86_64-unknown-linux-gnu)  COSIGN_BIN=cosign-linux-amd64 ;;
  aarch64-unknown-linux-gnu) COSIGN_BIN=cosign-linux-arm64 ;;
esac
COSIGN_SHA256_AMD64="<embedded; pinned at script-write time per § 7.3>"
COSIGN_SHA256_ARM64="<embedded; pinned at script-write time per § 7.3>"

tmpdir=$(mktemp -d /tmp/sandbox-install.XXXXXX)
trap "rm -rf $tmpdir" EXIT

curl -fsSL -o "$tmpdir/cosign" \
    "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${COSIGN_BIN}"
actual=$(sha256sum "$tmpdir/cosign" | awk '{print $1}')
expected="$( case "$ARCH" in
    x86_64-*)  echo "$COSIGN_SHA256_AMD64" ;;
    aarch64-*) echo "$COSIGN_SHA256_ARM64" ;;
  esac )"
if [ "$actual" != "$expected" ]; then
    die "cosign checksum mismatch (expected $expected got $actual)"
fi
chmod +x "$tmpdir/cosign"
COSIGN="$tmpdir/cosign"
```

Air-gapped installs (`--from <local-tarball>`) still need cosign for offline
verification. If `--from` is supplied **and** no network is available, the
script falls back to looking for cosign at `/usr/local/bin/cosign` (operator-
provided); if not found, refuses with a clear message about staging the
binary alongside the tarball. This is the only step that has a non-trivial
fallback in the air-gapped path; the cosign-bundle verification itself does
not require network (§ 4.4.10 uses cosign's offline mode).

Log line: `step=cosign_bootstrap version=v2.4.1 source=<download|local> status=ok`

#### 9. Tarball fetch

If `--from <path>`, copy the tarball into the staging dir; if no `--from`,
fetch from GitHub Releases:

```sh
if [ -n "$FROM" ]; then
    [ -f "$FROM" ] || die "tarball not found: $FROM"
    cp "$FROM" "$tmpdir/release.tar.gz"
else
    if [ "$VERSION" = "latest" ]; then
        # Resolve latest tag via GH's API. No auth needed for public repo.
        VERSION=$(curl -fsSL https://api.github.com/repos/Koriit/sandboxd/releases/latest \
            | jq -r '.tag_name' | sed 's/^v//')
    fi
    TAG="v${VERSION}"
    TARBALL_NAME="sandboxd-${VERSION}-${ARCH}.tar.gz"
    curl -fsSL --retry 3 --retry-delay 2 -o "$tmpdir/release.tar.gz" \
        "${SOURCE_URL}/${TAG}/${TARBALL_NAME}"
fi
```

`curl -fsSL` fails on HTTP error (`-f`), is silent on success (`-s`),
shows errors (`-S` — added if not `--quiet`), and follows redirects (`-L`).
`--retry 3` covers transient GitHub CDN flakes.

For the sigstore bundle: same pattern, fetched from
`${SOURCE_URL}/${TAG}/${TARBALL_NAME}.sigstore` unless `--cosign-bundle` is
provided.

Log line: `step=tarball_fetch source=<url-or-local> version=<v> size=NKB status=ok`

#### 10. Sigstore verification

The trust step. Run cosign in `verify-blob` mode with the OIDC identity
regex anchored to the project's release workflow:

```sh
"$COSIGN" verify-blob \
    --bundle "$tmpdir/release.tar.gz.sigstore" \
    --certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "$tmpdir/release.tar.gz"
```

Exit 0 ⇒ the tarball is signed by GitHub Actions OIDC for the
`Koriit/sandboxd` repo's release workflow. Any other identity (a different
repo, a different workflow file, a manually-signed blob) ⇒ exit non-zero ⇒
install.sh dies. The regex anchors prevent partial matches; the OIDC issuer
is the only one Fulcio accepts for GH-Actions OIDC tokens.

For air-gapped installs (`--cosign-bundle <local>`), cosign reads the
bundle from disk and the Rekor transparency-log lookup is offline (the
bundle contains the necessary entry). The verification does not require
network.

Log line: `step=sigstore_verify bundle=<path> identity=<matched-regex> status=<ok|fail>`

#### 11. Tarball extraction

Extract to the staging dir:

```sh
tar -xzf "$tmpdir/release.tar.gz" -C "$tmpdir"
stage="$tmpdir/sandboxd-${VERSION}-${ARCH}"
[ -d "$stage" ] || die "tarball did not contain expected top-level directory"
```

Then verify MANIFEST:

```sh
manifest="$stage/MANIFEST"
[ -f "$manifest" ] || die "tarball missing MANIFEST"
mver=$(jq -r '.version' "$manifest")
march=$(jq -r '.arch'    "$manifest")
[ "$mver"  = "$VERSION" ] || die "MANIFEST version mismatch: tarball says $mver, expected $VERSION"
[ "$march" = "$ARCH"    ] || die "MANIFEST arch mismatch: tarball says $march, expected $ARCH"
# Verify every artifact sha256 in MANIFEST against the extracted file.
jq -r '.artifacts | to_entries[] | "\(.value.sha256)  \(.value.path)"' "$manifest" \
    | (cd "$stage" && sha256sum -c --status -)
```

The `sha256sum -c` is the inner integrity check: each declared sha256 must
match the extracted file. cosign verified the tarball as a whole; the
MANIFEST per-file checks pin individual files, defending against an attacker
who somehow obtained a signing identity but tampered with extracted
contents post-verification (currently unreachable, but cheap to enforce).

Log line: `step=extract version=<v> arch=<arch> manifest_ok=true status=ok`

#### 12. Create `sandbox` system user

Idempotent: skip if the user already exists.

```sh
if getent passwd sandbox >/dev/null; then
    log_ok "step=useradd action=skip reason=exists"
    SANDBOX_USER_CREATED=0
else
    sudo -k useradd \
        --system \
        --user-group \
        --no-create-home \
        --home-dir /var/lib/sandbox \
        --shell /usr/sbin/nologin \
        --comment "sandboxd — isolated environment broker" \
        sandbox
    log_ok "step=useradd status=ok"
    SANDBOX_USER_CREATED=1
fi

# usermod -aG is idempotent: adding an already-member is a no-op exit-0.
sudo -k usermod -aG docker sandbox
sudo -k usermod -aG kvm    sandbox
log_ok "step=usermod_groups groups=docker,kvm status=ok"
```

Construction matches Spec 3 § 3.1 verbatim. `SANDBOX_USER_CREATED` is
recorded in the install-state file (§ 4.5) so uninstall.sh knows whether
to `userdel` (we created it) vs. leave alone (it existed before we
started).

Log line: `step=useradd action=<create|skip> we_created=<0|1> status=ok`

#### 13. Add invoking operator to the `sandbox` group

```sh
operator="${SUDO_USER:-}"
if [ -z "$operator" ] || [ "$operator" = "root" ]; then
    emit "$YELLOW!$RESET install.sh was not invoked via sudo (or invoked as root)."
    emit "  Skipping operator-group-add. To add operators later:"
    emit "      sudo usermod -aG sandbox <operator-username>"
    log_warn "step=operator_add operator=none action=skip"
    OPERATORS_ADDED=
else
    # Check membership before adding to keep the log honest.
    if id -nG "$operator" 2>/dev/null | tr ' ' '\n' | grep -qx sandbox; then
        log_ok "step=operator_add operator=$operator action=skip reason=already-member"
        OPERATORS_ADDED=""
    else
        sudo -k usermod -aG sandbox "$operator"
        log_ok "step=operator_add operator=$operator status=ok"
        OPERATORS_ADDED="$operator"
    fi
fi
```

The script trusts `$SUDO_USER` (set by sudo to the invoking user's name) as
the operator identity. If install.sh was run as root directly (no sudo, no
`$SUDO_USER`), the script skips this step with a clear instruction — the
operator must add themselves manually because we don't have an identity to
add. `OPERATORS_ADDED` enters the install-state record.

Group membership takes effect on next login; the script's final-steps
message (§ 4.4.24) reminds the operator to `newgrp sandbox` or relog.

Log line: `step=operator_add operator=<user-or-none> action=<add|skip> status=ok`

#### 14. Install binaries

Each binary is installed via `install -m 0755 -o root -g root` for the
public binaries (`sandboxd`, `sandbox`) and the same modes for the
helper. The destination paths match Spec 3 / the existing Makefile:

| Source                              | Destination                                                  |
|-------------------------------------|--------------------------------------------------------------|
| `$stage/bin/sandboxd`               | `/usr/local/bin/sandboxd`                                    |
| `$stage/bin/sandbox`                | `/usr/local/bin/sandbox`                                     |
| `$stage/bin/sandbox-route-helper`   | `/usr/local/libexec/sandboxd/sandbox-route-helper`           |

Idempotency: compare the staged file's sha256 to the on-disk file's sha256
before installing. If they match, skip.

```sh
install_binary() {
    src="$1"; dst="$2"; mode="$3"
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        log_ok "step=install_binary path=$dst action=skip reason=identical"
        return 0
    fi
    sudo -k install -D -m "$mode" -o root -g root "$src" "$dst"
    log_ok "step=install_binary path=$dst sha256=$(sha256sum "$dst" | awk '{print $1}') status=ok"
}

install_binary "$stage/bin/sandboxd"             /usr/local/bin/sandboxd                            0755
install_binary "$stage/bin/sandbox"              /usr/local/bin/sandbox                             0755
install_binary "$stage/bin/sandbox-route-helper" /usr/local/libexec/sandboxd/sandbox-route-helper   0755
```

`install -D` creates the parent dir `/usr/local/libexec/sandboxd/` on first
install. Mode of the parent dir defaults to `install`'s creation default
(0755).

Log line: `step=install_binary path=<dst> sha256=<hex> action=<install|skip> status=ok`

#### 15. Setcap on route-helper

Idempotent: getcap first; setcap only if missing or wrong.

```sh
helper=/usr/local/libexec/sandboxd/sandbox-route-helper
current=$(getcap "$helper" 2>/dev/null | sed -e "s|^.*= ||")
expected='cap_net_admin,cap_sys_admin=eip'
if [ "$current" = "$expected" ]; then
    log_ok "step=setcap action=skip reason=already-set"
else
    sudo -k setcap "$expected" "$helper"
    new=$(getcap "$helper" | sed -e "s|^.*= ||")
    [ "$new" = "$expected" ] || die "setcap verification failed: got '$new'"
    log_ok "step=setcap caps=$expected status=ok"
fi
```

This mirrors the dev-mode Makefile's `install-route-helper-prod-cap`
target (`Makefile:226-241`).

Log line: `step=setcap caps=cap_net_admin,cap_sys_admin=eip action=<set|skip> status=ok`

#### 16. Probe for `qemu-bridge-helper`

The helper's path differs across distros:

| Distro family   | Typical path                                              |
|-----------------|-----------------------------------------------------------|
| Debian / Ubuntu | `/usr/lib/qemu/qemu-bridge-helper`                        |
| RHEL / Fedora   | `/usr/libexec/qemu-bridge-helper`                         |
| Arch            | `/usr/lib/qemu/qemu-bridge-helper`                        |
| Custom install  | `/usr/local/lib/qemu/qemu-bridge-helper`                  |

Probe in order; record the first that exists. Spec 3 § 9 deliberately
removed the daemon's runtime reference to this path — QEMU resolves it via
its compile-time `libexecdir` — but install.sh still needs to probe it for
the setuid step (§ 4.4.17). The probed path **goes into the install-state
file** so uninstall.sh can revert exactly what install.sh changed:

```sh
BRIDGE_HELPER=
for candidate in \
    /usr/lib/qemu/qemu-bridge-helper \
    /usr/libexec/qemu-bridge-helper \
    /usr/local/lib/qemu/qemu-bridge-helper
do
    if [ -x "$candidate" ]; then
        BRIDGE_HELPER="$candidate"
        break
    fi
done
[ -n "$BRIDGE_HELPER" ] || die "qemu-bridge-helper not found at any known path; install qemu-system-${arch_for_qemu} or qemu-utils"
log_ok "step=bridge_helper_probe path=$BRIDGE_HELPER status=ok"
```

Log line: `step=bridge_helper_probe path=<absolute-path> status=ok`

#### 17. Setuid on `qemu-bridge-helper`

Idempotent: skip if already setuid. Record in install state whether we set it.

```sh
if [ -u "$BRIDGE_HELPER" ]; then
    log_ok "step=bridge_helper_setuid action=skip reason=already-setuid"
    WE_SET_BRIDGE_HELPER_SETUID=0
else
    sudo -k chmod u+s "$BRIDGE_HELPER"
    log_ok "step=bridge_helper_setuid path=$BRIDGE_HELPER status=ok"
    WE_SET_BRIDGE_HELPER_SETUID=1
fi
```

The flag matters for uninstall: only revert if we set it (some distros
ship the helper non-setuid intentionally for users not running QEMU bridges;
we should not impose our policy on QEMU's other users on shared hosts).

Log line: `step=bridge_helper_setuid path=<p> action=<set|skip> we_set=<0|1>`

#### 18. Install `/etc/qemu/bridge.conf`

Pattern is "additive, never destructive" — matches the dev-mode Makefile's
`setup-bridge-conf` target (`Makefile:337-356`) but with a stricter
rule: install.sh writes `allow sb-*` (the production scope), not
`allow all` (the dev-box convenience). The reasoning: production install
should not authorize bridges named for unrelated workloads; sandboxd's
bridges are namespaced `sb-<id>` and the rule restricts to that.

```sh
target_rule='allow sb-*'
ADDED_BRIDGE_CONF_RULES=
if [ -f /etc/qemu/bridge.conf ]; then
    if grep -qxE 'allow (all|sb-\*)' /etc/qemu/bridge.conf; then
        log_ok "step=bridge_conf action=skip reason=already-authorized"
    else
        # Append the rule; never rewrite existing lines.
        echo "$target_rule" | sudo -k tee -a /etc/qemu/bridge.conf >/dev/null
        ADDED_BRIDGE_CONF_RULES="$target_rule"
        log_ok "step=bridge_conf action=append rule='$target_rule' status=ok"
    fi
else
    sudo -k mkdir -p /etc/qemu
    echo "$target_rule" | sudo -k tee /etc/qemu/bridge.conf >/dev/null
    sudo -k chmod 0644 /etc/qemu/bridge.conf
    ADDED_BRIDGE_CONF_RULES="$target_rule"
    log_ok "step=bridge_conf action=create rule='$target_rule' status=ok"
fi
```

`ADDED_BRIDGE_CONF_RULES` enters install-state so uninstall.sh removes only
the rules install.sh added — not lines an operator added for other QEMU
workloads on the same host.

Log line: `step=bridge_conf action=<append|create|skip> rule='<r>' status=ok`

#### 19. Install `/etc/sandboxd/users.conf`

Pattern: if the file does not exist, create it from `contrib/users.conf.example`
(see `/home/olek/Projects/claude-sandbox/contrib/users.conf.example`) with
`_schema_version: 1` (the post-Spec-1 schema). Production install uses the
daemon's `sandbox` user (Spec 1 § 4.2 / V001) — the V001 migration is part
of `sandbox update`'s migration framework (Spec 5), but install.sh ships a
file already at schema version 1, so V001 has no work to do on a fresh
install.

If the file exists, leave it alone — operators may have customized it.

```sh
WE_CREATED_USERS_CONF=0
if [ -f /etc/sandboxd/users.conf ]; then
    log_ok "step=users_conf action=skip reason=exists"
else
    sudo -k mkdir -p /etc/sandboxd
    operator_for_pool="${OPERATORS_ADDED:-sandbox}"
    cat > "$tmpdir/users.conf" <<EOF
{
  "_schema_version": 1,
  "subnets": [
    {
      "comment": "Production pool — daemon-owning user is 'sandbox' (Spec 1 V001 convention); installing operator is also listed for direct-CLI helper invocations.",
      "cidr": "10.209.0.0/20",
      "allow_users": ["sandbox", "$operator_for_pool"]
    }
  ]
}
EOF
    sudo -k install -m 0644 -o root -g root "$tmpdir/users.conf" /etc/sandboxd/users.conf
    WE_CREATED_USERS_CONF=1
    log_ok "step=users_conf action=create pool=10.209.0.0/20 allow_users='sandbox,$operator_for_pool' status=ok"
fi
```

Mode is `0644` so the daemon (running as `sandbox`) can read it; the
helper, which runs as `root` post-setcap, also reads it. Write access is
root-only.

Log line: `step=users_conf action=<create|skip> we_created=<0|1> status=ok`

#### 20. `docker load` the gateway image

Idempotent: skip if the tag already exists.

```sh
tag="sandbox-gateway:${VERSION}"
if docker image inspect "$tag" >/dev/null 2>&1; then
    log_ok "step=docker_load image=$tag action=skip reason=already-loaded"
else
    sudo -k docker load -i "$stage/images/sandbox-gateway-${VERSION}.tar"
    docker image inspect "$tag" >/dev/null \
        || die "docker load did not produce expected tag $tag"
    log_ok "step=docker_load image=$tag status=ok"
fi
```

The `sudo -k docker load` is required: install.sh runs as the operator (via
sudo for privileged steps), but the operator may not be in the `docker`
group yet. Loading via sudo bypasses the group check. After install, the
daemon (as `sandbox`) loads images via its `docker` group membership.

Log line: `step=docker_load image=<tag> action=<load|skip> status=ok`

#### 21. Install systemd unit

```sh
unit_src="$stage/systemd/sandboxd.service"
unit_dst="/etc/systemd/system/sandboxd.service"
if [ -f "$unit_dst" ] && cmp -s "$unit_src" "$unit_dst"; then
    log_ok "step=install_unit action=skip reason=identical"
else
    sudo -k install -m 0644 -o root -g root "$unit_src" "$unit_dst"
    log_ok "step=install_unit path=$unit_dst sha256=$(sha256sum "$unit_dst" | awk '{print $1}') status=ok"
fi
```

The unit content is fixed at Spec 3 § 4.1; install.sh ships it verbatim
from the tarball. Operator customizations live in drop-ins under
`/etc/systemd/system/sandboxd.service.d/` (Spec 3 § 4.3) which install.sh
does not touch.

Log line: `step=install_unit path=<p> sha256=<hex> action=<install|skip>`

#### 22. `systemctl daemon-reload`

Always run, after installing the unit:

```sh
sudo -k systemctl daemon-reload
log_ok "step=daemon_reload status=ok"
```

Idempotent by design: systemctl is happy to reload on no-op.

Log line: `step=daemon_reload status=ok`

#### 23. Write `/var/lib/sandbox/.install-state.json`

This step records every fact uninstall.sh and operators need to audit the
install. Write to a temp file first, then move into place with the correct
owner/mode (the daemon's `sandbox:sandbox`):

```sh
state_path=/var/lib/sandbox/.install-state.json
sudo -k mkdir -p /var/lib/sandbox
sudo -k chown sandbox:sandbox /var/lib/sandbox
sudo -k chmod 0750 /var/lib/sandbox

python3 - <<PY > "$tmpdir/install-state.json"
import json, datetime, os, sys
state = {
    "installed_version":             os.environ["VERSION"],
    "installed_arch":                os.environ["ARCH"],
    "installed_at":                  datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "installed_by_operator":         os.environ.get("SUDO_USER") or "(direct-root)",
    "operators_added_to_group":      [os.environ["OPERATORS_ADDED"]] if os.environ.get("OPERATORS_ADDED") else [],
    "we_set_bridge_helper_setuid":   bool(int(os.environ["WE_SET_BRIDGE_HELPER_SETUID"])),
    "bridge_helper_path_at_install": os.environ["BRIDGE_HELPER"],
    "we_created_sandbox_user":       bool(int(os.environ["SANDBOX_USER_CREATED"])),
    "we_created_users_conf":         bool(int(os.environ["WE_CREATED_USERS_CONF"])),
    "we_added_bridge_conf_rules":    [r for r in os.environ.get("ADDED_BRIDGE_CONF_RULES", "").split("\n") if r],
    "users_conf_sha256_at_install":  None,  # populated below if we created it
    "tarball_sha256":                os.environ.get("TARBALL_SHA256"),
    "manifest_build_sha":            os.environ.get("MANIFEST_BUILD_SHA"),
}
if state["we_created_users_conf"]:
    import hashlib
    h = hashlib.sha256()
    with open("/etc/sandboxd/users.conf", "rb") as f:
        h.update(f.read())
    state["users_conf_sha256_at_install"] = h.hexdigest()
json.dump(state, sys.stdout, indent=2, sort_keys=True)
print()
PY

sudo -k install -m 0640 -o sandbox -g sandbox "$tmpdir/install-state.json" "$state_path"
log_ok "step=install_state path=$state_path status=ok"
```

The file is owned by `sandbox:sandbox` mode `0640`: operators in the
`sandbox` group can read it (useful for `sandbox doctor` extensions in
future Specs), but only the daemon's user and root can write it. The
daemon **never reads** the file (Spec 3 § 5.1's principle); it is forensic
metadata for uninstall and audit only.

Log line: `step=install_state path=<p> status=ok`

#### 24. Print next-steps

```sh
emit ""
emit "$GREEN✓$RESET sandboxd $VERSION installed."
emit ""
emit "Next:"
if [ -n "$OPERATORS_ADDED" ]; then
    emit "  1. Activate group membership: $BLUE log out and back in,$RESET or $BLUE run: newgrp sandbox $RESET"
fi
emit "  2. Start the daemon:           $BLUE sudo systemctl enable --now sandboxd $RESET"
emit "  3. Verify the install:         $BLUE sandbox doctor $RESET"
emit ""
emit "Install state recorded at: /var/lib/sandbox/.install-state.json"
emit "Install log:               /var/log/sandbox-install.log"
exit 0
```

The numbered steps are gated by what install.sh did; if no operators were
added (root-direct install), step 1 is omitted. Color-coding uses the
TTY-aware variables from § 4.4.4.

Log line: `step=done version=<v> status=ok`

### 4.5 · The install state file

`/var/lib/sandbox/.install-state.json` is **forensic-only**. The daemon
never opens it, never depends on its existence, never reads its contents.
It exists solely so:

- `uninstall.sh` knows which artifacts it created (vs. pre-existing) and
  reverses only its own changes;
- operators can audit "what did install do?" without re-reading the install
  log;
- a future support-bundle generator can capture it for forensics.

Schema (matches the structure built in § 4.4.23):

```json
{
  "bridge_helper_path_at_install": "/usr/libexec/qemu-bridge-helper",
  "installed_arch":               "x86_64-unknown-linux-gnu",
  "installed_at":                 "2026-05-11T14:23:11Z",
  "installed_by_operator":        "alice",
  "installed_version":            "1.0.0",
  "manifest_build_sha":           "0123456789abcdef...",
  "operators_added_to_group":     ["alice"],
  "tarball_sha256":               "...",
  "users_conf_sha256_at_install": "...",
  "we_added_bridge_conf_rules":   ["allow sb-*"],
  "we_created_sandbox_user":      true,
  "we_created_users_conf":        true,
  "we_set_bridge_helper_setuid":  true
}
```

Forward-compat rule: the file's contents may grow fields across releases.
uninstall.sh reads every field with `jq '.field // null'` so missing fields
are tolerated. New fields are always optional in the JSON sense (have a
defined fallback when consumed); removing a field is a breaking change
that requires a documented migration.

The "could-not-be-inferred-from-filesystem" criterion for inclusion:

| Field                              | Could uninstall infer from filesystem? | Why it must be recorded |
|------------------------------------|----------------------------------------|--------------------------|
| `we_created_sandbox_user`          | No                                     | A pre-existing `sandbox` user (e.g. from a different tool) should not be deleted by uninstall. |
| `we_set_bridge_helper_setuid`      | No                                     | If a distro ships the helper setuid by default, reverting it would break unrelated QEMU users. |
| `bridge_helper_path_at_install`    | Yes-ish                                | uninstall could re-probe, but install-time path may have moved; record once for fidelity. |
| `we_created_users_conf`            | No                                     | Operator may have created their own users.conf before install. |
| `users_conf_sha256_at_install`     | No                                     | uninstall backs up the file if it has been modified since install; needs the install-time hash to detect modification. |
| `we_added_bridge_conf_rules`       | Partially                              | uninstall removes specifically the lines we added, not operator-added lines. |
| `operators_added_to_group`         | No                                     | `gpasswd -d` requires the list of users whose membership we granted. |
| `installed_version`, `_arch`       | Yes (from binary `--version`)          | Convenience for audit. |
| `installed_at`, `_by_operator`     | No                                     | Forensic record. |
| `tarball_sha256`, `manifest_build_sha` | No                                | Audit chain back to the release artifact. |

### 4.6 · Install log format

`/var/log/sandbox-install.log` is created by install.sh as root on first
run (`sudo -k touch /var/log/sandbox-install.log && sudo -k chmod 0640
/var/log/sandbox-install.log` early in the script), appended to by every
subsequent step.

Format: one record per line, `key=value` pairs separated by spaces, prefixed
by ISO8601 UTC timestamp. The shape is grep-friendly and shell-writable:

```
2026-05-11T14:23:11Z install.sh step=useradd action=create we_created=1 status=ok pid=12345
2026-05-11T14:23:12Z install.sh step=operator_add operator=alice status=ok pid=12345
2026-05-11T14:23:12Z install.sh step=install_binary path=/usr/local/bin/sandboxd sha256=abc... action=install status=ok pid=12345
2026-05-11T14:23:13Z install.sh step=setcap caps=cap_net_admin,cap_sys_admin=eip action=set status=ok pid=12345
2026-05-11T14:23:13Z install.sh step=bridge_helper_setuid path=/usr/libexec/qemu-bridge-helper action=set we_set=1 status=ok pid=12345
```

Conventions:

- Timestamp is always the first token, ISO8601 UTC.
- The script name (`install.sh` or `uninstall.sh`) is the second token so a
  single log file can hold both.
- `pid=` is the script's PID; useful when concurrent re-runs (shouldn't
  happen, but possible) need disambiguation. The lock-file mutex that
  would prevent concurrent runs is Spec 5 territory.
- `status=ok` or `status=fail`; the latter is followed by an `error=`
  field with a short description.
- Values containing spaces are single-quoted: `rule='allow sb-*'`.

The log is `0640 root:adm` on Debian-likes (where `adm` is the standard
log-readable group); we set it `0640 root:root` to avoid distro-coupling
the script and let operators relax it via `chown root:adm` themselves if
they integrate with rsyslog or journald.

Rotation: install.sh writes append-only and never rotates. The log will
grow only on re-runs (idempotent re-runs produce many `action=skip` lines).
A pragmatic 1 MB cap is generous for a script that runs maybe a handful
of times in a host's lifetime; rotation is left to logrotate. § 10.4
records this as a known operator-responsibility item.

### 4.7 · Color/TTY output

Reserve four colors:

| Color  | Meaning   | Example                                                        |
|--------|-----------|----------------------------------------------------------------|
| Green  | success   | `✓ sandboxd 1.0.0 installed.`                                  |
| Red    | failure   | `✗ tarball checksum mismatch.`                                 |
| Yellow | warning   | `! install.sh was not invoked via sudo.`                       |
| Blue   | info / cmd | `Next: sudo systemctl enable --now sandboxd`                  |

Detection (already given in § 4.4.4): `[ -t 1 ]` and `--no-color` not set.
When stdout is piped to a file or another process, colors are suppressed.
This matches the convention from the existing `Makefile:7-13` so the
installed system feels consistent.

No emoji. ASCII prefixes only (`✓`, `✗`, `!` are technically Unicode, but
they're single-codepoint and render in the standard mono fonts every
terminal ships with).

## 5 · `uninstall.sh`

Same hosting (`https://Koriit.github.io/sandboxd/uninstall.sh`), same
idempotency principle (§ 4.3), same color/log conventions (§§ 4.6, 4.7).

### 5.1 · Flags

| Flag           | Effect                                                                                       |
|----------------|----------------------------------------------------------------------------------------------|
| `--purge`      | Remove `/var/lib/sandbox/`, delete the `sandbox` user, revoke operator group memberships. Prompts unless `--yes`. |
| `--force`      | Proceed even if sessions are active (default: refuse).                                       |
| `--yes`        | Skip all confirmation prompts.                                                                |
| `--verbose`    | Echo every command before invocation.                                                         |
| `--quiet`      | Suppress non-error output.                                                                    |
| `--no-color`   | Force plain text.                                                                             |
| `--help`       | Print usage and exit 0.                                                                       |

### 5.2 · Step-by-step flow

#### 1. Arg parsing

Same shape as install.sh § 4.4.1. Defaults: `PURGE=0`, `FORCE=0`, `YES=0`.

Log line: `step=parse_args purge=<0|1> force=<0|1>`

#### 2. Refuse if sessions are active

Connect to the daemon's socket and ask whether any sessions exist. If yes,
refuse unless `--force`.

```sh
sock=/run/sandbox/sandboxd.sock
if [ -S "$sock" ]; then
    # `sandbox session ls --output json` is the documented session list.
    # If the daemon is reachable and lists ≥1 session, refuse.
    active=$(sandbox session ls --output json 2>/dev/null | jq 'length // 0')
    if [ "${active:-0}" -gt 0 ] && [ "$FORCE" -eq 0 ]; then
        die "Active sessions exist ($active). Stop them first:
    sandbox session ls
    sandbox session rm <id>
Or use --force to proceed anyway."
    fi
fi
```

`--force` skips the check; this is for "the daemon is broken and I just
want sandboxd off" scenarios. Active sessions left running after `--force`
uninstall will leak resources (containers, VMs); the script prints a clear
warning.

Log line: `step=session_check active=<n> force=<0|1> status=<ok|refuse>`

#### 3. Read install state

```sh
state=/var/lib/sandbox/.install-state.json
if [ -r "$state" ]; then
    # All fields read defensively via `jq // <default>`.
    WE_CREATED_SANDBOX_USER=$(jq -r '.we_created_sandbox_user // false'      "$state")
    WE_SET_BH_SETUID=$(jq -r '.we_set_bridge_helper_setuid // false'         "$state")
    BH_PATH=$(jq -r '.bridge_helper_path_at_install // ""'                   "$state")
    WE_CREATED_USERS_CONF=$(jq -r '.we_created_users_conf // false'          "$state")
    USERS_CONF_SHA_AT_INSTALL=$(jq -r '.users_conf_sha256_at_install // ""'  "$state")
    ADDED_BRIDGE_RULES=$(jq -r '.we_added_bridge_conf_rules // [] | .[]'     "$state")
    OPS_ADDED=$(jq -r '.operators_added_to_group // [] | .[]'                "$state")
    HAVE_STATE=1
else
    log_warn "step=read_state path=$state status=missing fallback=best-effort"
    HAVE_STATE=0
fi
```

Best-effort fallback (`HAVE_STATE=0`): uninstall removes only what it can
detect from the filesystem — the binaries, the unit, the helper caps,
`/etc/sandboxd/` if empty — and leaves anything ambiguous (the `sandbox`
user, the bridge.conf rules, the bridge-helper setuid bit). It prints a
clear summary of what was skipped and why.

Log line: `step=read_state have_state=<0|1> status=ok`

#### 4. Stop and disable systemd unit

```sh
if systemctl is-enabled sandboxd 2>/dev/null | grep -qE 'enabled|static'; then
    sudo -k systemctl disable --now sandboxd
    log_ok "step=systemctl_disable status=ok"
elif systemctl is-active sandboxd 2>/dev/null | grep -q active; then
    sudo -k systemctl stop sandboxd
    log_ok "step=systemctl_stop status=ok"
else
    log_ok "step=systemctl_disable action=skip reason=not-active"
fi
```

`disable --now` stops the unit and disables auto-start. Idempotent: if
the unit isn't enabled, fall through to a plain `stop`; if it isn't
active either, skip.

Log line: `step=systemctl_disable action=<disable|stop|skip> status=ok`

#### 5. Remove systemd unit

```sh
unit=/etc/systemd/system/sandboxd.service
if [ -f "$unit" ]; then
    sudo -k rm -f "$unit"
    sudo -k systemctl daemon-reload
    log_ok "step=remove_unit path=$unit status=ok"
else
    log_ok "step=remove_unit action=skip reason=absent"
fi
```

Drop-ins under `/etc/systemd/system/sandboxd.service.d/` are **left intact**
on a non-purge uninstall — operators may have invested time in
customizing them. `--purge` removes the entire `.service.d/` directory
(§ 5.2.11). The contract matches Spec 3 § 4.3's promise that drop-ins
survive base-unit replacements; the symmetric promise here is that they
survive uninstall unless explicitly purged.

Log line: `step=remove_unit path=<p> action=<rm|skip> status=ok`

#### 6. Revert `qemu-bridge-helper` setuid

Only if install state says we set it:

```sh
if [ "$HAVE_STATE" -eq 1 ] && [ "$WE_SET_BH_SETUID" = "true" ] && [ -n "$BH_PATH" ] && [ -e "$BH_PATH" ]; then
    if [ -u "$BH_PATH" ]; then
        sudo -k chmod u-s "$BH_PATH"
        log_ok "step=revert_setuid path=$BH_PATH status=ok"
    else
        log_ok "step=revert_setuid action=skip reason=already-not-setuid"
    fi
else
    log_ok "step=revert_setuid action=skip reason=we-did-not-set-it"
fi
```

This is the core "did we change this?" gate. A distro that ships
qemu-bridge-helper setuid by default would have `we_set_bridge_helper_setuid=false`
in install state; we leave it alone. Best-effort mode (no install state)
also leaves it alone — reverting a setuid bit blindly could break other
QEMU users on the host.

Log line: `step=revert_setuid path=<p> action=<unset|skip> status=ok`

#### 7. Remove `/etc/qemu/bridge.conf` rules

Only the lines we added:

```sh
if [ "$HAVE_STATE" -eq 1 ] && [ -f /etc/qemu/bridge.conf ]; then
    tmp=$(mktemp)
    sudo -k cat /etc/qemu/bridge.conf > "$tmp"
    for rule in $ADDED_BRIDGE_RULES; do
        # grep -v matches whole lines. Quote $rule because it may
        # contain shell-specials (`sb-*` is literal here, not a glob).
        grep -vxF -- "$rule" "$tmp" > "${tmp}.new" || true
        mv "${tmp}.new" "$tmp"
    done
    if [ ! -s "$tmp" ]; then
        # File is now empty — remove it entirely.
        sudo -k rm -f /etc/qemu/bridge.conf
        log_ok "step=bridge_conf action=remove_file reason=empty"
    elif ! cmp -s "$tmp" /etc/qemu/bridge.conf; then
        sudo -k install -m 0644 -o root -g root "$tmp" /etc/qemu/bridge.conf
        log_ok "step=bridge_conf action=removed_lines count=$(echo "$ADDED_BRIDGE_RULES" | wc -l)"
    else
        log_ok "step=bridge_conf action=skip reason=no-matching-lines"
    fi
    rm -f "$tmp" "${tmp}.new"
fi
```

`grep -vxF -- "$rule"` removes lines that exactly match the recorded rule,
treating the pattern as a fixed string. The whole-line match (`x`) prevents
accidental partial-match removal.

Log line: `step=bridge_conf action=<remove_file|removed_lines|skip> status=ok`

#### 8. Remove `/etc/sandboxd/users.conf` (with backup if modified)

```sh
if [ "$HAVE_STATE" -eq 1 ] && [ "$WE_CREATED_USERS_CONF" = "true" ] && [ -f /etc/sandboxd/users.conf ]; then
    current_sha=$(sha256sum /etc/sandboxd/users.conf | awk '{print $1}')
    if [ "$current_sha" != "$USERS_CONF_SHA_AT_INSTALL" ]; then
        # Modified since install — back it up before removing.
        backup_dir="${HOME}/sandboxd-uninstall-backup-$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p "$backup_dir"
        sudo -k cp /etc/sandboxd/users.conf "$backup_dir/users.conf"
        log_warn "step=backup_users_conf to=$backup_dir/users.conf reason=modified-since-install"
        emit "$YELLOW!$RESET /etc/sandboxd/users.conf was modified since install."
        emit "  Backup saved to: $backup_dir/users.conf"
    fi
    sudo -k rm -f /etc/sandboxd/users.conf
    log_ok "step=remove_users_conf status=ok"
fi
# Also remove the /etc/sandboxd/ dir if empty.
if [ -d /etc/sandboxd ] && [ -z "$(sudo -k ls -A /etc/sandboxd)" ]; then
    sudo -k rmdir /etc/sandboxd
    log_ok "step=remove_users_conf_dir status=ok"
fi
```

The backup destination is the *invoking operator's* home directory
(`$HOME`), not root's home — operators look in their own home for
post-uninstall artifacts. `$SUDO_USER`'s `getent passwd` entry's home dir
would be more correct; use it if `$HOME` is undefined (e.g. someone ran
this from a service context).

Log line: `step=remove_users_conf backup=<path-or-none> status=ok`

#### 9. Remove route-helper caps (then the binary)

Removing the binary auto-removes file caps; explicit `setcap -r` is
redundant but documented for clarity. The binary removal is § 5.2.10
below; this step is a no-op recorded for log symmetry with install.

```sh
helper=/usr/local/libexec/sandboxd/sandbox-route-helper
if [ -x "$helper" ]; then
    log_ok "step=helper_caps action=defer reason=will-remove-binary"
fi
```

Log line: `step=helper_caps action=defer`

#### 10. Remove binaries

```sh
for bin in /usr/local/bin/sandboxd \
           /usr/local/bin/sandbox \
           /usr/local/libexec/sandboxd/sandbox-route-helper; do
    if [ -f "$bin" ]; then
        sudo -k rm -f "$bin"
        log_ok "step=remove_binary path=$bin status=ok"
    else
        log_ok "step=remove_binary path=$bin action=skip reason=absent"
    fi
done
# Remove the libexec subdir if empty.
if [ -d /usr/local/libexec/sandboxd ] && [ -z "$(ls -A /usr/local/libexec/sandboxd)" ]; then
    sudo -k rmdir /usr/local/libexec/sandboxd
fi
```

Log line: `step=remove_binary path=<p> action=<rm|skip> status=ok`

#### 11. `--purge` only

Strongly destructive: removes state, deletes the user, revokes group
memberships. Wrap in a confirmation prompt unless `--yes`:

```sh
if [ "$PURGE" -eq 1 ]; then
    if [ "$YES" -eq 0 ]; then
        emit "$RED!$RESET --purge will delete:"
        emit "    /var/lib/sandbox/  (sessions DB, per-session CA material, audit logs)"
        emit "    the 'sandbox' system user (if install.sh created it)"
        if [ -n "$OPS_ADDED" ]; then
            emit "    'sandbox' group membership for: $OPS_ADDED"
        fi
        emit "    /etc/systemd/system/sandboxd.service.d/  (drop-in customizations)"
        printf "Type 'PURGE' to confirm: "
        read -r confirm
        [ "$confirm" = "PURGE" ] || die "Aborted."
    fi

    # State dir.
    if [ -d /var/lib/sandbox ]; then
        sudo -k rm -rf /var/lib/sandbox
        log_ok "step=purge_state status=ok"
    fi

    # User + group.
    if [ "$HAVE_STATE" -eq 1 ] && [ "$WE_CREATED_SANDBOX_USER" = "true" ] && getent passwd sandbox >/dev/null; then
        sudo -k userdel sandbox
        log_ok "step=userdel status=ok"
        # `userdel` removes the user's primary group; if the group is named
        # `sandbox` and was created by useradd --user-group, it's gone now.
        if getent group sandbox >/dev/null; then
            sudo -k groupdel sandbox
            log_ok "step=groupdel status=ok"
        fi
    fi

    # Drop-ins.
    if [ -d /etc/systemd/system/sandboxd.service.d ]; then
        sudo -k rm -rf /etc/systemd/system/sandboxd.service.d
        log_ok "step=remove_drop_ins status=ok"
    fi

    # Group memberships of operators we added.
    if [ "$HAVE_STATE" -eq 1 ] && [ -n "$OPS_ADDED" ]; then
        for op in $OPS_ADDED; do
            if id -nG "$op" 2>/dev/null | tr ' ' '\n' | grep -qx sandbox; then
                sudo -k gpasswd -d "$op" sandbox
                log_ok "step=group_revoke operator=$op status=ok"
            fi
        done
    fi

    # Gateway image. Removed only under --purge because docker image data is
    # not "state" in the install sense; rebuilds are expensive.
    if docker image inspect "sandbox-gateway:$(jq -r '.installed_version' "$state" 2>/dev/null || echo none)" >/dev/null 2>&1; then
        sudo -k docker image rm "sandbox-gateway:$(jq -r '.installed_version' "$state" 2>/dev/null)"
        log_ok "step=docker_rmi status=ok"
    fi
fi
```

The confirmation token is `PURGE` (typed exactly) rather than `y` or
`yes` — a typo-protector against muscle-memory `y\n`. `--yes` skips it
for automation; documented as a foot-gun in § 10.5.

Log line: `step=purge ... status=ok` (multiple lines)

#### 12. Final state report

```sh
emit ""
emit "$GREEN✓$RESET sandboxd uninstalled."
emit ""
emit "Removed:"
for line in "$REMOVED_ITEMS"; do emit "  - $line"; done
if [ "$PURGE" -eq 0 ]; then
    emit ""
    emit "$YELLOW Kept (run with --purge to remove):$RESET"
    emit "  - /var/lib/sandbox/ (state, sessions DB, audit logs)"
    emit "  - 'sandbox' system user and group"
    emit "  - sandbox-gateway docker image"
fi
emit ""
emit "Uninstall log: /var/log/sandbox-install.log"
exit 0
```

Log line: `step=done status=ok`

## 6 · Lima-based E2E test harness

### 6.1 · Why Lima

Spec 4 reuses sandboxd's existing Lima dependency to provision clean
Linux VMs per test. Three properties pay off:

- **Avoids polluting the developer's host.** Each test gets a fresh VM;
  install.sh and uninstall.sh leave no residue on the dev's actual machine.
- **Tests real Linux distros.** Stock Ubuntu, Debian, Fedora — different
  qemu-bridge-helper paths, different systemd journald defaults,
  different Python versions for the MANIFEST generator (which install.sh
  shells out to). Mocked-distro testing missed all of these.
- **Reuses the existing CI gate shape.** The e2e workflow under
  `tests/e2e/` and the `make test-e2e-matrix` target (Makefile:120-122)
  already drive Lima for backend-coverage tests. The install harness is
  a parallel use of the same infrastructure.

The harness adds no new build dependencies: Lima is already required for
`make test-e2e-matrix`.

### 6.2 · Harness shape

A new test directory at `tests/install-e2e/`. Each test is a Python test
file (pytest, matching the existing `tests/e2e/` convention) that:

```python
# tests/install-e2e/test_install_fresh_ubuntu_22.py (illustrative)

@pytest.mark.parametrize("distro_template", ["ubuntu-22.04"])
def test_install_fresh_then_doctor_passes(distro_template, tmp_path,
                                          release_tarball_x86_64):
    """Fresh VM, install.sh runs, sandbox doctor reports green."""
    vm_name = f"sandboxd-install-test-{uuid.uuid4().hex[:8]}"
    try:
        # 1. Spin up clean VM.
        run(["limactl", "start", "--name", vm_name, "--tty=false",
             f"template://{distro_template}"])

        # 2. Copy install.sh + the locally-built release tarball into the VM.
        lima_cp(vm_name, INSTALL_SH_PATH, "/tmp/install.sh")
        lima_cp(vm_name, release_tarball_x86_64,
                f"/tmp/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz")

        # 3. Run install.sh in the VM as a regular user via sudo.
        lima_shell(vm_name, "sudo bash /tmp/install.sh "
                            "--from /tmp/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz "
                            "--yes")

        # 4. Assert post-conditions.
        assert lima_shell(vm_name, "test -x /usr/local/bin/sandboxd").returncode == 0
        assert lima_shell(vm_name, "test -f /etc/systemd/system/sandboxd.service").returncode == 0
        assert lima_shell(vm_name, "id sandbox").returncode == 0
        assert lima_shell(vm_name, "getcap /usr/local/libexec/sandboxd/sandbox-route-helper").stdout \
               == "cap_net_admin,cap_sys_admin=eip\n"

        # 5. Start the daemon and run sandbox doctor.
        lima_shell(vm_name, "sudo systemctl enable --now sandboxd")
        wait_for_socket(vm_name, "/run/sandbox/sandboxd.sock", timeout=30)
        doctor = lima_shell(vm_name, "sudo -u $SUDO_USER sandbox doctor")
        assert doctor.returncode == 0
        assert "checks passed, 0 failed" in doctor.stdout

        # 6. Now uninstall.
        lima_cp(vm_name, UNINSTALL_SH_PATH, "/tmp/uninstall.sh")
        lima_shell(vm_name, "sudo bash /tmp/uninstall.sh --yes")

        # 7. Assert clean teardown.
        assert lima_shell(vm_name, "test -x /usr/local/bin/sandboxd").returncode != 0
        assert lima_shell(vm_name, "test -f /etc/systemd/system/sandboxd.service").returncode != 0
        # /var/lib/sandbox/ kept (no --purge).
        assert lima_shell(vm_name, "test -d /var/lib/sandbox").returncode == 0
    finally:
        run(["limactl", "delete", "--force", vm_name])
```

`release_tarball_x86_64` is a session-scoped pytest fixture that produces
the local-build tarball once per test session. The fixture's build logic
mirrors the release workflow's `assemble tarball` step (§ 3.3) but locally
on the host: build the workspace at the workspace's current version,
`make gateway-image`, `docker save`, tar.

### 6.3 · Test matrix

At minimum the four high-coverage cases enumerated below; the matrix is
parametrized so adding a distro is a one-line change.

| Test                                                         | Distros                              | Path coverage                                          |
|--------------------------------------------------------------|--------------------------------------|---------------------------------------------------------|
| `test_install_fresh_then_doctor_passes`                      | ubuntu-22.04, debian-12              | Happy path; doctor reports all green                    |
| `test_install_fresh_then_doctor_passes_rhel_paths`           | fedora-40                            | Bridge-helper at `/usr/libexec/`; different OVMF path   |
| `test_install_idempotent_double_run`                         | ubuntu-22.04                         | Re-run install.sh; all steps log `action=skip`         |
| `test_install_partial_failure_recovery`                      | ubuntu-22.04                         | Kill install.sh mid-step N, re-run, verify continuation |
| `test_uninstall_after_install_clean`                         | ubuntu-22.04                         | No-purge uninstall leaves state dir intact              |
| `test_uninstall_with_purge_removes_user_and_state`           | ubuntu-22.04                         | Full purge; `getent passwd sandbox` returns empty       |
| `test_uninstall_double_run_idempotent`                       | ubuntu-22.04                         | Second uninstall is a no-op                             |
| `test_install_air_gapped`                                    | ubuntu-22.04 (with network disabled) | `--from <local>` + `--cosign-bundle <local>` path       |
| `test_install_refuses_wrong_arch_tarball`                    | ubuntu-22.04 (x86_64 VM)             | aarch64 tarball, expect die-with-clear-error            |
| `test_install_refuses_when_preexisting`                      | ubuntu-22.04                         | install.sh; install.sh again; second refuses + points at update |

### 6.4 · CI integration

A new workflow `.github/workflows/install-e2e.yml`:

```yaml
name: Install E2E

on:
  push:
    branches: [main]
    paths:
      - 'scripts/install.sh'
      - 'scripts/uninstall.sh'
      - 'tests/install-e2e/**'
      - '.github/workflows/install-e2e.yml'
  pull_request:
    branches: [main]
    paths:
      - 'scripts/install.sh'
      - 'scripts/uninstall.sh'
      - 'tests/install-e2e/**'
  workflow_dispatch:

jobs:
  install-e2e:
    # Lima requires KVM / nested virtualization. GitHub-hosted runners do
    # not expose /dev/kvm; we ride on the same `[self-hosted, kvm]` runner
    # label `e2e-matrix` (ci.yml:95) uses. § 10.2 flags this dependency.
    runs-on: [self-hosted, kvm]
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - uses: dtolnay/rust-toolchain@stable
        with:
          toolchain: '1.88.0'
      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: ~/.cargo sandboxd/target
          key: install-e2e-${{ hashFiles('sandboxd/**/Cargo.lock') }}
      - name: Build local release tarball
        run: ./tests/install-e2e/build-local-tarball.sh
      - name: Run install/uninstall harness
        run: |
          cd tests/install-e2e
          python -m venv .venv
          .venv/bin/pip install -r requirements.txt
          .venv/bin/python -m pytest -v --timeout=900
```

The `[self-hosted, kvm]` runner is the same one `ci.yml:95` (the
`e2e-matrix` job) already targets. The dependency on that runner being
provisioned is shared with the existing E2E matrix; we don't create a
new infrastructure dependency.

PR-time scope is `--paths`-filtered to scripts-only changes; non-script PRs
do not pay the cost. Merge-to-main runs unconditionally on script changes.

`shellcheck` lint runs in `ci.yml` (not install-e2e.yml) as a fast pre-flight
on every PR — see § 8.

## 7 · Trust bootstrap

The install chain has multiple links; an operator should be able to audit
each.

### 7.1 · Trust chain (end-to-end)

```
operator types: curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash
  ↓
  GitHub Pages TLS cert (issued by Let's Encrypt to *.github.io)
  ↓
  install.sh content from GH Pages (deployed by docs.yml from
   site/public/install.sh ← scripts/install.sh in repo)
  ↓
  install.sh downloads cosign with PINNED sha256 (§ 4.4.8); on mismatch, refuse.
  ↓
  install.sh downloads release tarball from GitHub Releases over TLS.
  ↓
  cosign verifies the tarball's sigstore bundle:
    - --certificate-oidc-issuer = https://token.actions.githubusercontent.com
    - --certificate-identity-regexp = ^https://github.com/Koriit/sandboxd/
      .github/workflows/release.yml@
  ↓
  sigstore attestation identity = the project's GitHub Actions release
  workflow's OIDC token, which is short-lived (per workflow run) and
  Fulcio-signed.
  ↓
  install.sh extracts the tarball and verifies every artifact's sha256
  against the MANIFEST.
  ↓
  Each file is exactly the file the release workflow produced at the
  tagged commit.
```

Every link is auditable:

- **Pages TLS:** standard web TLS; same trust chain as github.com.
- **install.sh source:** the operator can `curl ... | less` before piping
  to `bash` (recommended in § 7.2). The script is ~500 lines of POSIX
  shell; reviewable in 10 minutes.
- **cosign binary:** the pinned sha256 is in the script. The operator can
  compute the same hash from cosign's published release and compare.
- **Tarball signing identity:** anyone can independently
  `cosign verify-blob` a downloaded tarball with the same identity regex
  and confirm.
- **MANIFEST hashes:** documented in MANIFEST file in plain JSON.

### 7.2 · Auditability for paranoid operators

The recommended flow for operators who want to read what they're about to
run:

```sh
# 1. Pull the script and review it.
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | less
# (read the script; check the cosign sha256 against
#  https://github.com/sigstore/cosign/releases/v2.4.1; check the
#  certificate-identity-regexp; check the version string)

# 2. If satisfied, run it.
curl -fsSL https://Koriit.github.io/sandboxd/install.sh | bash
```

For air-gapped review on a build host:

```sh
# Download the script + tarball + bundle on an internet-connected host.
curl -fsSL -o install.sh https://Koriit.github.io/sandboxd/install.sh
curl -fsSL -o sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz \
    https://github.com/Koriit/sandboxd/releases/download/v1.0.0/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz
curl -fsSL -o sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz.sigstore \
    https://github.com/Koriit/sandboxd/releases/download/v1.0.0/sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz.sigstore

# Transfer to the air-gapped host.

# On the air-gapped host, with cosign pre-staged at /usr/local/bin/cosign:
bash install.sh \
    --from sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz \
    --cosign-bundle sandboxd-1.0.0-x86_64-unknown-linux-gnu.tar.gz.sigstore
```

The script's POSIX-shell shape (no bash-isms) is deliberate so it runs on
Debian's `dash`-default-`sh` shells.

### 7.3 · Cosign version pinning

The pinned cosign version lives in install.sh as a header constant:

```sh
COSIGN_VERSION="v2.4.1"
COSIGN_SHA256_AMD64="b7a8c1d8e9f0...   # 64 hex chars; pinned at script-write time"
COSIGN_SHA256_ARM64="..."
```

The hashes are obtained at script-write time from cosign's release
artifacts: `https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64.sha256`.

Bumping the cosign version is a manual maintenance task. The cosign
release cadence is slow (one release every few months), so the friction
is bounded. Process to bump:

1. Pick the latest stable cosign release.
2. Read its published sha256 (cosign signs its own release; verify via
   the project's existing cosign keyring or the previous version's
   cosign — chained trust).
3. Edit `scripts/install.sh`: bump `COSIGN_VERSION` and the two sha256
   constants.
4. PR, merge; the next `docs.yml` build deploys the updated script.
5. Existing already-installed hosts are unaffected (install.sh is for
   fresh install; bumps don't propagate retroactively).

No cosign auto-bump mechanism (e.g. a renovate-bot config). Auto-updating
the trust root is the wrong shape — every bump should be a deliberate
human decision.

## 8 · Test plan (scripts themselves)

The scripts have three layers of test coverage:

### 8.1 · Lima E2E (§ 6)

Primary correctness gate. Spec 4 ships the harness in § 6.

### 8.2 · Shellcheck

Static analysis on every shell script in CI. Add a `shellcheck` step to
`ci.yml`:

```yaml
      - name: Shellcheck
        run: shellcheck -s sh -S style scripts/install.sh scripts/uninstall.sh
```

`-s sh` enforces POSIX (rejects bashisms). `-S style` includes stylistic
warnings (mainly: quote your variables). Both scripts must pass without
suppression directives.

### 8.3 · Idempotency unit tests

Inside the Lima harness (§ 6.3 `test_install_idempotent_double_run`):

1. Fresh VM; run install.sh once → exit 0; harvest install log.
2. Run install.sh a second time → exit 0; harvest install log.
3. Parse the second-run log; assert every step's `action` is `skip` (i.e.
   no privileged change happened on the second run).
4. Assert no `sudo` prompt fired (the script's `sudo -k` invocations would
   block on stdin if any non-no-op step ran without `--yes`; the test
   harness runs without a controlling TTY, so a real `sudo` ask would
   error rather than block — that's the assertion).

### 8.4 · Partial-failure recovery

Cover several failure points in install.sh:

| Test                                          | Inject failure at              | Expected recovery                                  |
|-----------------------------------------------|--------------------------------|----------------------------------------------------|
| `test_recovery_after_useradd_failure`         | step 12 (`useradd` returns non-zero) | Re-run after fixing the cause; step 12 detects user now exists and skips; rest of install completes. |
| `test_recovery_after_binary_install_failure` | step 14 (mid-binary install) | Re-run; previously-installed binaries detected by sha256; uninstalled binaries get installed. |
| `test_recovery_after_setcap_failure`         | step 15 (`setcap` returns non-zero) | Re-run; helper present but caps missing; setcap runs again. |
| `test_recovery_after_docker_load_failure`    | step 20 (docker load fails)    | Re-run; image now present, step 20 detects and skips. |

Each test mid-failure leaves the install in a known partial state; the
re-run uses the idempotency-skip path to bring it to completion.

### 8.5 · Uninstall double-run

Mirror of § 8.3 for uninstall.sh:

1. Fresh VM, no sandboxd installed. Run uninstall.sh → exit 0; every step
   logs `action=skip`.
2. Install, then uninstall, then uninstall again. Second uninstall logs
   only skips.

### 8.6 · Air-gapped install path

The air-gapped flow has its own test in § 6.3 (`test_install_air_gapped`).
Inside the VM, disable network access between the cosign-download step
and the rest of install.sh; verify that `--from` + `--cosign-bundle`
completes the install without any network egress (Lima's network policy
or simple `iptables -A OUTPUT -j REJECT` suffice for the network
disable).

## 9 · Backward compatibility — dev mode

Spec 4 does not break `make setup-dev-env`. Developers continue to install
via make. The two install paths coexist on different artifacts:

| Artifact                                                       | Dev mode (`make setup-dev-env`)                | Spec 4 install path                              |
|----------------------------------------------------------------|-----------------------------------------------|---------------------------------------------------|
| `sandboxd` binary                                              | Run from `sandboxd/target/release/sandboxd`   | Installed at `/usr/local/bin/sandboxd`            |
| `sandbox` CLI binary                                           | Run from `sandboxd/target/release/sandbox`   | Installed at `/usr/local/bin/sandbox`             |
| `sandbox-route-helper`                                         | `/usr/local/libexec/sandboxd/sandbox-route-helper` (Makefile:204) | Same path |
| systemd unit                                                   | Not installed (dev runs daemon by hand)       | `/etc/systemd/system/sandboxd.service`           |
| state dir                                                      | `~/.local/share/sandboxd/`                    | `/var/lib/sandbox/`                               |
| socket                                                         | `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock`     | `/run/sandbox/sandboxd.sock`                      |
| `sandbox` user                                                 | Not created                                   | Created                                            |
| `/etc/sandboxd/users.conf`                                     | Created (developer in `allow_users`)          | Created (`sandbox` + invoking operator in `allow_users`) |
| `/etc/qemu/bridge.conf`                                        | `allow all` (dev convenience)                 | `allow sb-*` (production scope)                   |
| qemu-bridge-helper setuid                                      | Set by `setup-bridge-helper-setuid`           | Set by install.sh § 4.4.17                        |

install.sh's pre-existing-install detection (§ 4.4.5) refuses if
`/usr/local/bin/sandboxd` exists. The dev-mode developer's daemon is
typically run from `sandboxd/target/release/sandboxd` (or `cargo run`),
not installed at `/usr/local/bin/sandboxd`, so the check passes for a
dev box and install.sh proceeds — but the resulting system install
**conflicts** with the dev mode's running daemon: both want
`/etc/sandboxd/users.conf` (install.sh leaves the existing file alone if
present, § 4.4.19), both want `qemu-bridge-helper` setuid (idempotent,
fine), and only one daemon at a time can hold `/var/lib/sandbox/` (the
system service uses it; the dev daemon uses `~/.local/share/sandboxd/`).
Practical impact: install.sh on a dev box succeeds, but the dev's running
`cargo run` daemon should be stopped before `sudo systemctl start
sandboxd`, or the two daemons compete for the same socket/state (they
won't — different paths — but the operator's CLI may connect to the
wrong one).

Recommended migration path for a dev who wants to switch to the system
install:

1. Stop the dev daemon (Ctrl-C the `cargo run`, or `kill $(pgrep
   sandboxd)`).
2. Optionally migrate `~/.local/share/sandboxd/sessions.db` to
   `/var/lib/sandbox/sessions.db`: `sudo install -m 0600 -o sandbox -g
   sandbox ~/.local/share/sandboxd/sessions.db /var/lib/sandbox/`. Note
   this is a manual operation; Spec 4 does not automate it (a "migrate
   from dev mode" subcommand is a Spec 5+ concern, deferred).
3. Run install.sh.
4. `sudo systemctl enable --now sandboxd`.
5. Update shell init to export
   `SANDBOX_SOCKET=/run/sandbox/sandboxd.sock` (or rely on the system
   `/etc/profile.d/sandbox.sh` Spec 3 § 5.3 anticipates — install.sh
   does not ship that file in v1; logged in Spec 4 § 10.6 as a
   follow-up).

The dev mode itself is unchanged. § 12.5 of Spec 3 covers the
CLI ↔ daemon version handshake; in dev, the dev's freshly-built CLI and
freshly-built daemon share `CARGO_PKG_VERSION`, so the strict-equality
check passes.

## 10 · Risks and open questions

### 10.1 · GitHub-hosted aarch64 runners

The release workflow's aarch64 build sits on `ubuntu-22.04-arm`, a
GitHub-hosted ARM64 runner GA'd in 2025. If GitHub deprecates or rate-
limits this runner on the project's plan, fallbacks (ordered by
preference):

1. **`ubuntu-24.04-arm`** — newer hosted ARM runner; same trade-offs.
2. **Self-hosted aarch64 runner** on a Mac M-series or a cloud
   aarch64 instance. Adds infrastructure cost.
3. **`cross`-based cross-compile from x86_64** — produces an aarch64
   binary on an amd64 runner. Works for the Rust workspace; **does not
   work for the gateway image** (multi-stage Docker build with a Go
   stage; cross-arch Docker requires `buildx` and `qemu-user-static`,
   doable but adds significant pipeline complexity). If we have to fall
   back to cross-compile, the gateway image becomes either single-arch
   (x86_64-only release) or built via Docker buildx multi-platform.

The spec defaults to native and notes the fallback so a future
release-pipeline maintainer can swap in without re-design.

### 10.2 · KVM-enabled CI runners for the Lima harness

`install-e2e.yml` requires the `[self-hosted, kvm]` runner label that
`ci.yml:95` already depends on. The repo currently lists this
requirement in `ci.yml`'s comments ("Until that runner is provisioned,
the job will queue without scheduling and the matrix coverage will not
run on push-to-main"). Spec 4 inherits this dependency. If the
self-hosted KVM runner is not provisioned, `install-e2e.yml` queues
without scheduling, just like `e2e-matrix`. The merge-to-main gate is
unimpacted by this state; PRs touching `scripts/install.sh` block on a
runner that may not be live.

Mitigation if the runner remains unprovisioned: developers can run the
Lima harness locally on a host with KVM (`cd tests/install-e2e &&
python -m pytest`). The CI gate documents the dependency but doesn't
forcibly run it.

§ 6.4 records the runner requirement at the workflow level. Spec 4
does not propose provisioning the runner itself (that's an
infrastructure handoff, separate from the spec).

### 10.3 · Cosign release cadence vs script maintenance

The pinned cosign version (§ 7.3) is a deliberate friction trade. cosign
releases roughly quarterly; a stale pin (e.g. 18 months old) starts
falling behind known-CVE fixes. We accept that friction because the
alternative — auto-bumping the trust root — is worse (every operator's
install trust depends on whoever can commit to the script's repo).

Mitigation: a quarterly maintenance task to bump cosign. Process is
documented in § 7.3. If the project adopts a release-tracking tool
(dependabot, renovate) for non-trust-root deps in future, cosign stays
out of that automation explicitly.

### 10.4 · Install-log rotation

`/var/log/sandbox-install.log` is written by install.sh + uninstall.sh on
each run. Idempotent re-runs add `action=skip` lines but no privileged
mutation. A worst-case re-run loop (a script in CI that calls install.sh
in a tight loop) could grow the file unboundedly.

Mitigation: install.sh's logs ~30 lines per run. 30 KB after 1000
re-runs; not a real risk. The spec does not configure logrotate
explicitly; operators wanting integration with their log shipper
(rsyslog, Vector, Promtail) handle that themselves. § 12 lists "ship a
`/etc/logrotate.d/sandbox-install` snippet" as an optional future
addition.

### 10.5 · `--purge` is destructive

`--yes --purge` removes `/var/lib/sandbox/` without confirmation. An
operator who pipes uninstall.sh into bash with `--yes` for a no-purge
uninstall is safe; one who adds `--purge` and `--yes` together is
intentionally destructive.

Mitigation: the help text (§ 5.1) flags `--yes` as "required for
non-interactive but skips the destructive-confirmation prompt." The
typo-protected confirmation token (`PURGE` literal, § 5.2.11) is the
interactive backstop. We accept the foot-gun by documenting it.

### 10.6 · Air-gapped install path needs offline test coverage

§ 6.3's `test_install_air_gapped` test simulates the offline path by
blocking outbound network mid-install. This is a partial test (the
script's cosign-bundle reading code path is exercised; the script's
download-cosign-binary code path is not). The fuller air-gapped story
(operator pre-stages cosign on a fully-offline build host before
ever connecting it to the internet) requires a multi-stage test or
manual verification. Spec 4 accepts the partial coverage as a v1 and
flags fuller coverage as a follow-up if a real air-gapped customer
materializes.

### 10.7 · `/etc/profile.d/sandbox.sh` for `SANDBOX_SOCKET`

Spec 3 § 5.3 anticipates that operators in `sandbox` group will need
the CLI to resolve the system-service socket
(`/run/sandbox/sandboxd.sock`) rather than the dev-mode XDG path. The
clean way to set this for everyone is
`/etc/profile.d/sandbox.sh` exporting `SANDBOX_SOCKET`. Spec 4 v1 does
**not** install this file — partly because it touches every operator's
environment beyond the daemon (a class of "side effect on other tools"
worth avoiding without explicit demand), and partly because the CLI's
`XDG_RUNTIME_DIR` fallback resolves to a clear "socket missing" error
on system installs, so operators can self-diagnose. § 12 lists shipping
the file as an optional follow-up; if early-adopter feedback indicates
discoverability suffers, the file becomes a §11 add-back.

### 10.8 · No CHANGELOG / release notes process today

The project has no `CHANGELOG.md` at the repo root and no documented
release-notes process. GitHub's auto-generated release notes (from PR
titles between two tags) would be a default. Spec 4 does **not** design
a release-notes pipeline — the handoff explicitly lists release notes
as out of scope. The release workflow simply omits a release-notes
step; the resulting GitHub Release page shows GH's auto-generated diff.
Operators authoring proper release notes is a documentation concern,
not a Spec 4 concern.

If a CHANGELOG.md does exist at release time (operators wrote one
between releases), the workflow could optionally read it. The workflow
shipped here does not.

## 11 · Out of scope

The following are **not** in Spec 4:

- **`sandbox update` CLI** — Spec 5. The boundary: install.sh produces
  installs from scratch; update mutates existing installs.
- **Config migration framework** (the registry that applies V001+ to
  `/etc/sandboxd/users.conf` during an update) — Spec 5. install.sh
  ships a fresh `users.conf` already at `_schema_version: 1` (Spec 1 § 4.2),
  so V001 has no work on a fresh install.
- **Backup mechanics** (the `.bak` files in `/var/lib/sandbox/backups/`
  produced during update; the backups dir created by Spec 3 § 5.1) —
  Spec 5. uninstall.sh writes a one-off backup under `$HOME/...` for the
  modified-`users.conf` case (§ 5.2.8); this is not the structured
  backup mechanism Spec 5 designs.
- **Lock-file mutex** for concurrent update prevention — Spec 5.
- **Automatic periodic rebuild of the lite image** — deferred,
  GH issue [Koriit/sandboxd#7](https://github.com/Koriit/sandboxd/issues/7).
- **Daemon-side changes** — all settled in Specs 1, 2, 3.
- **`sandbox doctor` subcommand design** — Spec 3 § 6.
- **Release notes / CHANGELOG content or process** — handoff explicitly
  out-of-scope (§ 10.8).
- **Multi-arch (x86_64 + aarch64) gateway image via Docker buildx +
  manifest lists** — v1 ships two separate per-arch images via
  `docker save`/`docker load`. A manifest-list-based "one image, many
  archs" delivery is more complex and not required.
- **Windows / macOS installs.** Linux only.
- **A `/etc/profile.d/sandbox.sh` for `SANDBOX_SOCKET`.** § 10.7
  documents the trade-off; v1 omits.
- **logrotate integration** for `/var/log/sandbox-install.log`. § 10.4
  documents the trade-off.

## 12 · Implementation notes (light)

Short, indicative bullets — not a plan, just a sanity check that the
spec's scope maps to a tractable change-set.

- `scripts/install.sh` (new, ~500–600 lines POSIX shell). Sources
  `scripts/lib.sh` if helpers are factored; otherwise inline.
- `scripts/uninstall.sh` (new, ~300–400 lines POSIX shell). Same lib
  if factored.
- `scripts/lib.sh` (optional new). Shared helpers: `log_*`, color
  helpers, `die`, `sudo_k`. Inline if single-file portability matters
  more than DRY; the spec's stance is "factor if it shrinks each script
  by >50 lines; else inline." Authors' discretion.
- `site/public/install.sh` (new) and `site/public/uninstall.sh` (new):
  symlinks or build-time copies of the canonical scripts (§ 4.1).
- `.github/workflows/release.yml` (new) — § 3.
- `.github/workflows/install-e2e.yml` (new) — § 6.4.
- `.github/workflows/ci.yml` (edit) — add the shellcheck step from § 8.2.
- `tests/install-e2e/` (new directory):
  - `tests/install-e2e/conftest.py` — shared fixtures (Lima helpers, the
    local-tarball builder, distro-template helpers).
  - `tests/install-e2e/build-local-tarball.sh` — script to produce the
    local-build tarball matching what the release workflow would.
  - `tests/install-e2e/test_install_*.py` — one file per test category
    (fresh install, idempotency, uninstall, air-gapped).
  - `tests/install-e2e/requirements.txt` — pytest + dependencies.
- `docs/start/installation.md` (edit) — replace the dev-mode-only
  instructions (currently the file walks the operator through `make
  setup-dev-env`) with two paths: "Operator install (curl|bash)" and
  "Developer install (make setup-dev-env)". The operator-install
  section is mostly a pointer at `https://Koriit.github.io/sandboxd/install.sh`
  plus the trust-chain note (§ 7).
- `Makefile` (edit) — no functional changes; optionally add an
  `install-scripts-sync` target that copies `scripts/*.sh` into
  `site/public/` for local development of the docs site (§ 4.1).

The cosign version pinned in the script: **cosign v2.4.1** (the latest
stable at write time). The two SHA256s for `cosign-linux-amd64` and
`cosign-linux-arm64` are fetched from cosign's release page and
embedded as constants. The script's first non-trivial PR should land
these.

## 13 · Affected files — summary

| Path                                                          | Touch type | Notes                                                                                              |
|---------------------------------------------------------------|------------|----------------------------------------------------------------------------------------------------|
| `scripts/install.sh`                                          | New        | POSIX shell, ~500 lines; § 4                                                                       |
| `scripts/uninstall.sh`                                        | New        | POSIX shell, ~300 lines; § 5                                                                       |
| `scripts/lib.sh`                                              | New (opt)  | Shared helpers; § 12 leaves inline-vs-factored to authors                                          |
| `site/public/install.sh`                                      | New        | Symlink or build-time copy of `scripts/install.sh`; § 4.1                                          |
| `site/public/uninstall.sh`                                    | New        | Symlink or build-time copy of `scripts/uninstall.sh`                                               |
| `.github/workflows/release.yml`                               | New        | Tag-triggered release pipeline; § 3                                                                |
| `.github/workflows/install-e2e.yml`                           | New        | Lima-based install/uninstall E2E; § 6.4                                                            |
| `.github/workflows/ci.yml`                                    | Edit       | Add shellcheck step (§ 8.2)                                                                        |
| `.github/workflows/docs.yml`                                  | Edit (opt) | Ensure `site/public/*.sh` ship to Pages; depends on Astro-config defaults                          |
| `tests/install-e2e/conftest.py`                               | New        | Lima fixtures, local-tarball builder                                                               |
| `tests/install-e2e/build-local-tarball.sh`                    | New        | Mirrors release-workflow's assemble step                                                           |
| `tests/install-e2e/test_install_fresh.py`                     | New        | Happy-path test per § 6.3                                                                          |
| `tests/install-e2e/test_install_idempotency.py`               | New        | Double-run, partial-failure-recovery                                                               |
| `tests/install-e2e/test_install_air_gapped.py`                | New        | `--from` + `--cosign-bundle` path                                                                  |
| `tests/install-e2e/test_uninstall.py`                         | New        | Clean uninstall, `--purge`, double-run idempotency                                                 |
| `tests/install-e2e/requirements.txt`                          | New        | pytest, Lima helpers                                                                               |
| `docs/start/installation.md`                                  | Edit       | Add operator-install path alongside dev-install                                                    |
| `Makefile`                                                    | Edit (opt) | `install-scripts-sync` target (§ 12), purely a developer convenience                               |

**Files explicitly *not* touched** (called out to forestall confusion):

| Path                                       | Reason untouched                                                                              |
|--------------------------------------------|-----------------------------------------------------------------------------------------------|
| `sandboxd/sandboxd/src/main.rs`            | No daemon-side changes in Spec 4. The install state file is forensic only (Spec 3 § 5.1).      |
| `sandboxd/sandbox-cli/src/main.rs`         | No CLI changes in Spec 4. `sandbox update` is Spec 5.                                          |
| `sandboxd/contrib/systemd/sandboxd.service`| Lands in Spec 3 § 15 (its canonical workspace location). Spec 4 reads it for the tarball.      |
| `sandboxd/sandbox-core/src/users_conf.rs`  | Schema convention is Spec 1. install.sh writes the conformant file from scratch.               |
| `Makefile` `setup-dev-env` sub-targets     | Dev-mode is preserved verbatim. § 9 documents coexistence.                                    |
| `contrib/users.conf.example`               | Used as the template content for `/etc/sandboxd/users.conf` in install.sh § 4.4.19; no edit.   |
| `networking/gateway/Dockerfile`            | Spec 3 § 8.3 already pinned the gateway image tag at build time; release workflow consumes it. |
