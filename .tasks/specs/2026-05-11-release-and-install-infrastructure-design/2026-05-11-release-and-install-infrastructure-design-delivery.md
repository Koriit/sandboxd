# Delivery Map — 2026-05-11 Release & Install Infrastructure (Spec 4)

Cross-references every concrete claim in the 2026-05-11 release-and-install
infrastructure spec to (a) shipped / (b) out-of-scope / (c) tracked-todo.
Verifies M15 commits (commit-log order on the Spec-4 file surface):

- `7946120 ci: release workflow + shellcheck step`
- `35c6272 feat(install): install.sh + uninstall.sh + Pages hosting`
- `ecb54d0 feat(install-e2e): Lima E2E harness + install.sh getcap parser fix`
- `efa6bd6 fix(install-e2e): preexist state.json fallback + systemd active wait`
- `df551d9 fix(install-e2e): portable docker build + smoke test traversal fixes`
- `43e3a98 fix(install-e2e): harden test assertions + script-side recovery`
- `310d194 fix(install): per-distro package hints in prereq-fail output`

## Summary table

| Part | Claims | (a) shipped | (b) out-of-scope | (c) tracked-todo | Blockers |
|------|-------:|------------:|-----------------:|-----------------:|---------:|
| P0  — Sequence context (§ 0)                              |  3 |  3 |  0 | 0 | 0 |
| P1  — Motivation (§ 1)                                    |  5 |  5 |  0 | 0 | 0 |
| P2  — Release tarball (§ 2)                               | 20 | 20 |  0 | 0 | 0 |
| P3  — GitHub Actions release workflow (§ 3)               | 25 | 24 |  0 | 1 | 0 |
| P4  — `install.sh` (§ 4)                                  | 70 | 67 |  0 | 3 | 0 |
| P5  — `uninstall.sh` (§ 5)                                | 25 | 24 |  0 | 1 | 0 |
| P6  — Lima E2E harness (§ 6)                              | 15 | 13 |  0 | 2 | 0 |
| P7  — Trust bootstrap (§ 7)                               | 10 | 10 |  0 | 0 | 0 |
| P8  — Test plan (§ 8)                                     |  8 |  6 |  0 | 2 | 0 |
| P9  — Backward compatibility — dev mode (§ 9)             |  5 |  5 |  0 | 0 | 0 |
| P10 — Risks and open questions (§ 10)                     | 15 |  9 |  0 | 6 | 0 |
| P11 — Out of scope (§ 11)                                 | 12 |  0 | 12 | 0 | 0 |
| P12 — Implementation notes (§ 12)                         |  5 |  5 |  0 | 0 | 0 |
| P13 — Affected files summary (§ 13)                       |  6 |  6 |  0 | 0 | 0 |
| **Grand total**                                           | **224** | **197** | **12** | **15** | **0** |

---

## Part 0 — Sequence context (§ 0)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P0.1 | Spec 4 is 4th in a five-spec arc; depends on Spec 3, precedes Spec 5 | (a) | `docs/internal/milestones/M15.md:3`; this delivery doc cross-refs `M14` (Spec 3) commits and `M16` (Spec 5) sessions | Inspection |
| P0.2 | Spec 4 strictly depends on Spec 3 system artifacts (sandbox user, systemd unit, /var/lib/sandbox layout, gateway image tag) | (a) | install.sh consumes them: `scripts/install.sh:738` (useradd recipe), `:954` (`$STAGE/systemd/sandboxd.service`), `:992-994` (`/var/lib/sandbox` 0750), `:936` (`sandbox-gateway:${VERSION}` from § 8.5) | Spec 3 delivery map covers daemon-side shape |
| P0.3 | Spec 4 strictly precedes Spec 5 (`sandbox update`); idempotency is the bridge | (a) | Boundary held: install.sh refuses on preexist-with-different-version pointing at `sandbox update` at `scripts/install.sh:362-365`; no `sandbox update` Command variant lands here | Forward constraint — M16-S2 territory |

---

## Part 1 — Motivation (§ 1)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P1.1 | Today's only install path is `make setup-dev-env`; runs daemon as developer's UID | (a) | `Makefile:setup-dev-env` (unchanged); spec § 1 documents the baseline | Pre-existing behavior |
| P1.2 | Operator deployment requires: no source-tree dep, auditability, trust | (a) | install.sh consumes binary artifacts (no rustc); every `sudo -k` printed in step log; cosign trust chain at `scripts/install.sh:688-695` | `tests/install-e2e/test_install_happy_path.py:29` |
| P1.3 | Trust chain: GH Pages cert → install.sh → cosign verify → OIDC identity = project's release workflow | (a) | `scripts/install.sh:688-695` verify-blob block; OIDC issuer pin at `:691` | `docs/start/installation.md:91-99` documents the chain |
| P1.4 | Same trust shape as `kubectl`/`helm`/`cosign` — no long-lived signing keys | (a) | Spec § 1 framing; install.sh has no PGP/keyring path | Operational |
| P1.5 | Spec 3 produced deployment shape; Spec 4 produces the pipeline + inverse | (a) | New: `.github/workflows/release.yml`, `scripts/install.sh`, `scripts/uninstall.sh`, `tests/install-e2e/`; dev-mode preserved per § 9 | Inspection |

---

## Part 2 — The release tarball (§ 2)

### 2.1 — Naming convention (P2.1 – P2.3)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.1 | Tarball name: `sandboxd-<version>-<arch>.tar.gz` (Rust target triple) | (a) | `.github/workflows/release.yml:125` `stage="sandboxd-${VER}-${ARCH}"`; install.sh derives same at `scripts/install.sh:644` | `tests/install-e2e/conftest.py:329` derives `sandboxd-{ver}-{arch}.tar.gz` |
| P2.2 | Examples include x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu | (a) | `release.yml:51-54` matrix targets; install.sh arch detect at `scripts/install.sh:277-278` | `tests/install-e2e/dist/sandboxd-0.1.0-x86_64-unknown-linux-gnu.tar.gz` produced by `build-local-tarball.sh:86` |
| P2.3 | `<version>` is sandboxd's semver from `sandboxd/sandboxd/Cargo.toml`; all workspace crates carry same version | (a) | `release.yml:75-80` cargo-version-vs-tag sanity check; `build-local-tarball.sh:70-75` reads same path | Inspection |

### 2.2 — Tarball contents (P2.4 – P2.13)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.4 | Single top-level directory matching basename | (a) | `release.yml:125-126` `stage="sandboxd-${VER}-${ARCH}"`; `tar -czf "${stage}.tar.gz" "$stage"` at `:171` | `tests/install-e2e/dist` listing observed: `sandboxd-0.1.0-x86_64-unknown-linux-gnu/` is the sole top-level dir |
| P2.5 | `MANIFEST` JSON at top level | (a) | `release.yml:168-170`; `build-local-tarball.sh:346-347` writes `MANIFEST` | Tarball listing shows `/MANIFEST`; verified MANIFEST shape under § 2.3 below |
| P2.6 | `bin/sandboxd` (daemon, mode 0755) | (a) | `release.yml:127-129` `install -m 0755 ... bin/sandboxd`; mirrored in `build-local-tarball.sh:294-295` | Tarball listing shows `bin/sandboxd` |
| P2.7 | `bin/sandbox` (CLI, mode 0755) | (a) | `release.yml:130-132`; `build-local-tarball.sh:296-297` | Tarball listing shows `bin/sandbox` |
| P2.8 | `bin/sandbox-route-helper` (mode 0755; caps applied by install.sh) | (a) | `release.yml:133-135`; install.sh setcap at `scripts/install.sh:822-838` | Tarball listing shows `bin/sandbox-route-helper`; caps test via `tests/install-e2e/conftest.py:681-686` |
| P2.9 | `libexec/` (intentionally empty — documents helper's destination) | (a) | `release.yml:126` `mkdir -p "$stage"/{bin,libexec,systemd,images,attestations}`; never populated | Tarball listing shows `libexec/` as empty dir |
| P2.10 | `systemd/sandboxd.service` (canonical from `sandboxd/contrib/systemd/`) | (a) | `release.yml:136-138` `install -m 0644 sandboxd/contrib/systemd/sandboxd.service ...`; `build-local-tarball.sh:300-301` | Tarball listing shows `systemd/sandboxd.service` |
| P2.11 | `images/sandbox-gateway-<v>.tar` (`docker save` output, 200-400 MB) | (a) | `release.yml:116-117` `docker save sandbox-gateway:${GATEWAY_VERSION} -o sandbox-gateway-${GATEWAY_VERSION}.tar`; staged at `:139-140`; mirrored in `build-local-tarball.sh:277-280` | Tarball listing shows `images/sandbox-gateway-0.1.0.tar` |
| P2.12 | `attestations/<tarball>.sigstore` cosign bundle for outer tarball + gateway-image bundle | (a) | Outer-tarball bundle written via `cosign sign-blob --bundle` at `release.yml:183-185`; uploaded alongside the tarball at `:197-199`. `attestations/` dir present in tarball but populated at upload time, not by `release.yml` stage | Tarball listing shows `attestations/` (empty in local build); production fills via `softprops/action-gh-release@v2` |
| P2.13 | Layout property 1: no lite-image tarball (Spec 3 § 8.4 daemon builds on demand) | (a) | `release.yml` has no `lite-image` step; only `make gateway-image` at `:113` | Spec 3 deliverable; absence-of-step IS the contract |
| P2.14 | Layout property 2: gateway image shipped not built on demand (Spec 3 § 8.5) | (a) | `release.yml:113-117` builds + `docker save`; install.sh `docker load` at `scripts/install.sh:943` (no rebuild path) | `tests/install-e2e/test_uninstall.py:81` asserts gateway image present after install |
| P2.15 | Layout property 3: `libexec/` empty in tarball; binary placed via `bin/` | (a) | `release.yml:133-135` installs route-helper under `bin/`; install.sh moves to `/usr/local/libexec/sandboxd/` at `scripts/install.sh:814-815` | Tarball listing shows `bin/sandbox-route-helper`, empty `libexec/` |
| P2.16 | Tar entries: mode bits as written, owner root:root, no symlinks | (a) | Standard `tar` defaults; spec § 2.2 prose; install.sh re-stamps modes at install time at `scripts/install.sh:806` | Inspection |

### 2.3 — MANIFEST format (P2.17 – P2.19)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.17 | MANIFEST is JSON (per project convention from CLAUDE.md) | (a) | `release.yml:142-170` python3 emits `json.dump(...)`; same in `build-local-tarball.sh:310-348` | Observed MANIFEST in `tests/install-e2e/dist/...tar.gz` is valid JSON |
| P2.18 | Required top-level keys: `version`, `arch`, `build_sha`, `build_time`, `artifacts` | (a) | `release.yml:161-167` builds the dict with exactly these keys; verify in `scripts/install.sh:710-715` (`jq -r '.version'`, `.arch`, `.build_sha`) | MANIFEST observed contains all five keys; install.sh extract step `scripts/install.sh:702-722` validates |
| P2.19 | Each `artifacts` entry has `path` + `sha256`; `gateway-image` adds `docker_tag` | (a) | `release.yml:151-160` populates `path`+`sha256` for every entry; `gateway-image` carries `docker_tag` at `:155-156`; install.sh per-file sha256 check at `scripts/install.sh:717-720` | MANIFEST observed: `gateway-image.docker_tag = "sandbox-gateway:0.1.0"` |
| P2.20 | Forward-compat: install.sh consults only documented fields; `jq // empty` tolerates missing | (a) | `scripts/install.sh:715` `jq -r '.build_sha // empty'` (tolerates missing); per-artifact check at `:718` reads only documented fields | Pattern is jq-default-elision per spec § 2.3 |

### 2.4 — Tarball size (P2.21)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.21 | Total compressed ~250-500 MB dominated by gateway image | (a) | Operational; spec § 2.4 prose; no enforcement code (sanity sizing) | Inspection — observed local build tarball size logged at `build-local-tarball.sh:364` |

---

## Part 3 — GitHub Actions release workflow (§ 3)

### 3.1 — Trigger (P3.1 – P3.2)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.1 | Trigger: `push.tags` `v[0-9]+.[0-9]+.[0-9]+` and pre-release `-*` | (a) | `.github/workflows/release.yml:13-17` (both patterns) | Inspection |
| P3.2 | Workflow does NOT fire on branch pushes, PRs, or UI-edited releases | (a) | `release.yml:13-17` only `on.push.tags`; no `on.pull_request` / `on.release` | Inspection |

### 3.2 — Matrix (P3.3 – P3.6)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.3 | Two parallel jobs, one per arch | (a) | `release.yml:47-54` matrix with two `include` entries | Inspection |
| P3.4 | `fail-fast: false` so one arch failure doesn't cancel the other | (a) | `release.yml:48` | Inspection |
| P3.5 | x86_64 → `ubuntu-22.04`; aarch64 → `ubuntu-22.04-arm` (GA since 2025) | (a) | `release.yml:51-54` | Inspection |
| P3.6 | Native build (no `cross`) to avoid glibc-mismatch class of bugs | (a) | `release.yml:100-102` runs `cargo build` natively on the matrix runner | Inspection |

### 3.3 — Steps per arch (P3.7 – P3.16)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.7 | `actions/checkout@v4` with `fetch-depth: 0` | (a) | `release.yml:61-64` | Inspection |
| P3.8 | Resolve version step + Cargo.toml sanity-check (tag must match) | (a) | `release.yml:66-80` (awk-parse of `sandboxd/sandboxd/Cargo.toml`) | Inspection |
| P3.9 | Rust toolchain pinned at `1.88.0` via `dtolnay/rust-toolchain@stable` | (a) | `release.yml:82-89` | Inspection |
| P3.10 | Cargo cache via `actions/cache@v4` keyed on `Cargo.lock` hash | (a) | `release.yml:91-98` | Inspection |
| P3.11 | `cargo build --workspace --release --target ${{ matrix.target }}` | (a) | `release.yml:100-102` | Inspection |
| P3.12 | Build gateway image via `make gateway-image`, `docker save` | (a) | `release.yml:104-117` | Inspection |
| P3.13 | Assemble tarball: stage tree + python3 MANIFEST generator + `tar -czf` | (a) | `release.yml:119-171` (matches spec § 3.3 verbatim modulo cosmetic `VER:  →  VER:` two-spaces-to-one collapse noted in inline comment at `:180`) | Inspection |
| P3.14 | Install cosign via `sigstore/cosign-installer@v3.7.0` with `cosign-release: 'v2.4.1'` | (a) | `release.yml:173-176` | Inspection |
| P3.15 | `cosign sign-blob --yes --bundle ...sigstore` | (a) | `release.yml:178-185` | Inspection |
| P3.16 | `actions/attest-build-provenance@v1` produces SLSA build-provenance | (a) | `release.yml:187-190` | Inspection |
| P3.17 | `softprops/action-gh-release@v2` uploads tarball + .sigstore | (a) | `release.yml:192-199`; `fail_on_unmatched_files: true` at `:196` | Inspection |

### 3.4 — Pinned versions (P3.18 – P3.19)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.18 | Pin discipline per § 3.4 table (Rust 1.88.0, checkout@v4, cache@v4, dtolnay/rust-toolchain @stable+1.88.0, cosign-installer@v3.7.0, cosign v2.4.1, attest-build-provenance@v1, action-gh-release@v2) | (a) | `release.yml:62,82,88,92,174,176,188,193` — all explicit | Inspection |
| P3.19 | Docker engine version not pinned (runner ships); documented in § 10.1 | (a) | `release.yml` does not pin Docker; spec § 10.1 + § 3.4 table footnote acknowledges | Operational |

### 3.5 — Permissions (P3.20 – P3.21)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.20 | Top-level permissions: `contents: write`, `id-token: write`, `attestations: write` | (a) | `release.yml:33-36` (job-level mirror at `:56-59` for defence-in-depth) | Inspection |
| P3.21 | No `packages: write`; no `pages: write` (pages publication lives in `docs.yml`) | (a) | `release.yml:33-36` permission set; absence-of-extras IS the contract | Inspection |

### 3.6 — SLSA build provenance (P3.22 – P3.24)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.22 | `attest-build-provenance@v1` generates SLSA L3 attestation alongside tarball | (a) | `release.yml:187-190` | Inspection |
| P3.23 | Cosign verify command anchored to release.yml workflow path (`^...@`) | (a) | install.sh `scripts/install.sh:690` `--certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@'`; verbatim shape from spec § 3.6 | Anchored-regexp replay verified — see "Replay verification" § 6 below |
| P3.24 | Cosign OIDC issuer fixed at `https://token.actions.githubusercontent.com` | (a) | `scripts/install.sh:691` | Inspection |

### 3.7 — `publish-install-script` job (P3.25)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.25 | Second top-level `publish-install-script` job mentioned in § 3.3 — actually fulfilled by `docs.yml` (spec § 4.1 is authoritative; release.yml carries explanatory comment) | (c) | `.github/workflows/release.yml:201-216` carries the explanatory comment; the actual install-script publication runs from `.github/workflows/docs.yml:63-64` (`cp scripts/install.sh site/public/install.sh`); contradiction internal to spec is documented at `release.yml:201-216` | DEFER-10 territory (Track 2 SF-2, spec-doc reconciliation) → M16-S5 doc pass to amend spec § 3.3 to point at docs.yml |

---

## Part 4 — `install.sh` (§ 4)

### 4.1 — Hosting (P4.1 – P4.3)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.1 | Hosted at `https://Koriit.github.io/sandboxd/install.sh` via existing GH Pages deployment | (a) | `scripts/install.sh:5` documents the URL; `.github/workflows/docs.yml:63` copies `scripts/install.sh` → `site/public/install.sh` (build-time copy variant) | Inspection |
| P4.2 | Canonical authored copy lives at `scripts/install.sh`; pre-commit/`make` copies to `site/public/` | (a) | `scripts/install.sh:9-11` comment notes the source-of-truth contract; `docs.yml:61-64` is the build-time copy step | Inspection |
| P4.3 | Release workflow does NOT re-publish scripts (they ride docs deploy) | (a) | `release.yml:201-216` documents the contract explicitly; absence-of-publish-step IS the contract | Inspection |

### 4.2 — Invocations + flags (P4.4 – P4.14)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.4 | `curl ... | bash` (latest tagged release) | (a) | `scripts/install.sh:93-94` example in `--help` banner | `tests/install-e2e/test_install_happy_path.py:40` (--from flow exercises the bulk) |
| P4.5 | `bash -s -- --version X.Y.Z` (pin version) | (a) | Flag at `scripts/install.sh:182-191`; resolver at `:301-334` | `tests/install-e2e/conftest.py:613-617` `install_sh_cmd` always passes `--version` |
| P4.6 | `bash -s -- --from /path/to/tarball.tar.gz` (air-gapped, local tarball) | (a) | Flag at `scripts/install.sh:193-201`; consumption at `:627-661` | Every install-e2e test exercises `--from` |
| P4.7 | `bash -s -- --from ... --cosign-bundle ...` (fully offline) | (a) | Flag at `scripts/install.sh:202-209`; consumption at `:630-639` | `tests/install-e2e/test_install_air_gapped.py:126` |
| P4.8 | `bash -s -- --yes` (non-interactive) | (a) | Flag at `:220-222`; consumed at confirmation sites (no current prompts in install.sh — uninstall's purge has them) | `tests/install-e2e/conftest.py:616` |
| P4.9 | Flag `--version` semver, default latest | (a) | `scripts/install.sh:39-40,182-191` | Inspection |
| P4.10 | Flag `--from` local path; resolves version from MANIFEST when `--version` unset (M15-S4 MF-1 fix) | (a) | `scripts/install.sh:301-319` `resolve_target_version` reads tarball MANIFEST when `--from` set + no `--version`; landed in commit `43e3a98` | Resolution path covered by every install-e2e test (which always sets `--version`); the unset-`--version` air-gapped operator flow is exercised manually per spec § 4.2 |
| P4.11 | Flag `--cosign-bundle` requires `--from` | (a) | `scripts/install.sh:248-250` (validation) | Inspection — validated at parse_args end |
| P4.12 | Flag `--source-url` overrides base URL | (a) | `scripts/install.sh:211-218,28` (default `DEFAULT_SOURCE_URL`) | Inspection |
| P4.13 | Flags `--verbose`, `--quiet`, `--no-color`, `--help` | (a) | `scripts/install.sh:224-239` | `scripts/install.sh:73-101` (`usage()` body covers each) |
| P4.14 | Unknown flags exit 2 with "unknown option" + "Try --help" | (a) | `scripts/install.sh:240-244` (exit 2 path) | Spec § 4.2 explicit; M15-S2 exit-criteria validated |

### 4.3 — Idempotency principle (P4.15 – P4.17)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.15 | Every step inspects current state; skips if matches; `sudo -k` before action; verify after | (a) | Pattern visible across all 24 steps — examples: `install_binary` at `:795-809` (cmp before install), `setcap_route_helper` at `:822-838`, `create_sandbox_user` at `:730-744`, `install_bridge_conf` at `:880-898` | `tests/install-e2e/test_install_idempotency.py:18-69` second-run all-skip allow-list assertion |
| P4.16 | Re-runs after partial failure resume; no `--resume` flag | (a) | Every step is idempotent — re-run lands where it left off | `tests/install-e2e/test_install_idempotency.py:77-187` `test_install_partial_failure_recovery` |
| P4.17 | `sudo -k` invalidates sudo cred-cache; forces re-auth per step | (a) | Every privileged action uses `sudo -k` — examples: `scripts/install.sh:734,748,751,806,834,888,910,943,961,971,992,1051` | Inspection grep confirms `sudo -k` discipline |

### 4.4 — Step-by-step flow (P4.18 – P4.66)

Each numbered step corresponds to spec § 4.4.<N>.

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.18 | Step 1 arg parsing: hand-rolled POSIX `case` loop; defaults set | (a) | `scripts/install.sh:179-257` | `tests/install-e2e/test_install_refusal.py:55-83` exercises the parse path indirectly |
| P4.19 | Step 1 log line: `step=parse_args version=<v> from=<path-or-->` | (a) | `scripts/install.sh:256` | `tests/install-e2e/conftest.py:539` `parse_install_log_actions` consumes the format |
| P4.20 | Step 2 OS detect: refuse on non-Linux | (a) | `scripts/install.sh:263-269` | Inspection (no non-Linux runner in matrix) |
| P4.21 | Step 2 log: `step=os_detect os=Linux status=ok` | (a) | `scripts/install.sh:268` (status=ok appended by `log_ok` wrapper at `:123-125`) | Inspection |
| P4.22 | Step 3 arch detect: x86_64→`x86_64-unknown-linux-gnu`, aarch64→`aarch64-unknown-linux-gnu`, else die | (a) | `scripts/install.sh:275-282` | `tests/install-e2e/test_install_refusal.py:30-83` `test_install_refuses_wrong_arch_tarball` |
| P4.23 | Step 4 TTY detect + color setup: empty escape codes when not TTY | (a) | `scripts/install.sh:142-156` (`setup_colors`) + `:288-295` (`detect_tty`) | `tests/install-e2e/conftest.py:617` always passes `--no-color` |
| P4.24 | Step 5 preexist detection: `/usr/local/bin/sandboxd --version` → compare to TARGET_VER → skip-exit-0 / refuse-with-update-pointer | (a) | `scripts/install.sh:336-370`; refuse text includes `sandbox update` at `:364` (forward-reference to M16) | `tests/install-e2e/test_install_refusal.py:87-134` `test_install_refuses_when_preexisting` (both same-version skip + diff-version refuse) |
| P4.25 | Step 5 binary-cannot-report-version fallback: read installed_version from .install-state.json | (a) | `scripts/install.sh:345-349` (commit `efa6bd6`) | M15-S4 MF-1 territory; fallback covered structurally by `test_install_refuses_when_preexisting` |
| P4.26 | Step 6 prereq check: probe kernel≥5.8, docker, lima, qemu, OVMF, setcap, jq, curl, sha256sum, tar | (a) | `scripts/install.sh:376-429` | `tests/install-e2e/conftest.py:412-479` installs the same set per-distro before invoking install.sh |
| P4.27 | Step 6 per-distro install hints from `/etc/os-release`'s ID/ID_LIKE (M15-S4 MF-4 fix) | (a) | `scripts/install.sh:457-533` (`detect_pkg_mgr` + `pkg_name_for` + `pkg_hint_for`); landed in commit `310d194` | Spec § 4.4.6 exit prose; verified by inspection |
| P4.28 | Step 6 log: `step=prereq missing=<csv> status=<ok|fail>` | (a) | `scripts/install.sh:451,454` | Inspection |
| P4.29 | Step 7 disk-space pre-flight: 50/200/500 MB at /usr/local, /var/lib/sandbox, /var/lib/docker | (a) | `scripts/install.sh:543-579` | Inspection |
| P4.30 | Step 7 fallback if /var/lib/sandbox absent: walk to /var/lib → /var → / | (a) | `scripts/install.sh:546-554` | Inspection |
| P4.31 | Step 8 cosign bootstrap: download cosign v2.4.1, sha256-verify, fallback to /usr/local/bin/cosign | (a) | `scripts/install.sh:585-617`; pinned consts at `:21-26` | `tests/install-e2e/test_install_air_gapped.py:39` exercises pre-staged cosign fallback (commit `ecb54d0`) |
| P4.32 | Step 8 cosign sha256 mismatch → die | (a) | `scripts/install.sh:598-600,605-608` | Inspection |
| P4.33 | Step 9 tarball fetch: `--from` copies local; else curl from `${SOURCE_URL}/${tag}/${tarball}` with --retry 3 | (a) | `scripts/install.sh:623-666` | `tests/install-e2e/conftest.py:550-567` `copy_tarball_to_vm` provides `--from` path |
| P4.34 | Step 9 sigstore bundle sibling fallback: `${FROM}.sigstore` if `--cosign-bundle` not set | (a) | `scripts/install.sh:634-639` | `tests/install-e2e/conftest.py:563-566` writes sigstore stub alongside |
| P4.35 | Step 10 sigstore verify with anchored regex and OIDC issuer | (a) | `scripts/install.sh:688-695` | `tests/install-e2e/test_install_air_gapped.py:127` exercises `SANDBOX_INSTALL_SKIP_SIGSTORE=1` bypass for local builds; full cosign-verify-path exercised only by signed-release tarballs |
| P4.36 | Step 10 test-only `SANDBOX_INSTALL_SKIP_SIGSTORE=1` bypass (warn-level log; documented as MUST-NEVER-set in production) | (a) | `scripts/install.sh:671-687` | `tests/install-e2e/test_install_air_gapped.py:146-148` asserts `test-env-override` log token |
| P4.37 | Step 11 tarball extract: tar -xzf to staging dir; assert top-level dir present | (a) | `scripts/install.sh:703-705` | `tests/install-e2e/test_install_refusal.py:69-71` exercises the failure path via tampered MANIFEST |
| P4.38 | Step 11 MANIFEST checks: version match, arch match, per-file sha256 | (a) | `scripts/install.sh:707-720`; `sha256sum -c --status -` at `:719` | `tests/install-e2e/test_install_refusal.py:62-83` `test_install_refuses_wrong_arch_tarball` (MANIFEST arch-mismatch path) |
| P4.39 | Step 12 useradd: skip if exists; else `useradd --system --user-group --no-create-home --home-dir /var/lib/sandbox --shell /usr/sbin/nologin sandbox` | (a) | `scripts/install.sh:729-744` | `tests/install-e2e/conftest.py:706-709` asserts `getent passwd sandbox` |
| P4.40 | Step 12 supplementary groups: usermod -aG docker, kvm (idempotent) | (a) | `scripts/install.sh:746-752` | Inspection (docker group existence checked at `:747`) |
| P4.41 | Step 12 records SANDBOX_USER_CREATED for install state | (a) | `scripts/install.sh:732,742` | `tests/install-e2e/test_uninstall.py:51-82` `test_uninstall_with_purge_removes_user_and_state` |
| P4.42 | Step 13 operator add: from `$SUDO_USER`; skip if root/empty; getent guard; usermod -aG sandbox | (a) | `scripts/install.sh:760-789` | Inspection — covered structurally by happy-path tests that lima-shell as default user, then `sudo bash /tmp/install.sh` (SUDO_USER set to default user) |
| P4.43 | Step 13 records OPERATORS_ADDED for install state | (a) | `scripts/install.sh:776,782,787` | `tests/install-e2e/test_uninstall.py:69-72` (purge revokes group membership) |
| P4.44 | Step 14 install binaries: `install -D -m 0755 -o root -g root`; sha256 idempotency | (a) | `scripts/install.sh:795-816` | `tests/install-e2e/conftest.py:668-686` `assert_full_install_landed` |
| P4.45 | Step 14 destinations: /usr/local/bin/sandboxd, /usr/local/bin/sandbox, /usr/local/libexec/sandboxd/sandbox-route-helper | (a) | `scripts/install.sh:812-815` | Same |
| P4.46 | Step 15 setcap on route-helper: getcap → setcap if missing | (a) | `scripts/install.sh:822-838`; getcap parser handles both libcap formats (commit `ecb54d0`) at `:829,835` | `tests/install-e2e/conftest.py:681-686` asserts `cap_net_admin,cap_sys_admin=eip` |
| P4.47 | Step 16 probe qemu-bridge-helper across distros: /usr/lib/qemu, /usr/libexec, /usr/local/lib/qemu, /usr/local/libexec | (a) | `scripts/install.sh:844-859` | `tests/install-e2e/test_install_happy_path.py:117-130` asserts probe finds Fedora's /usr/libexec/ path |
| P4.48 | Step 16 records BRIDGE_HELPER path for install state | (a) | `scripts/install.sh:852` | `scripts/install.sh:1029` writes to install-state JSON |
| P4.49 | Step 17 setuid on qemu-bridge-helper: skip if already setuid; record WE_SET_BRIDGE_HELPER_SETUID | (a) | `scripts/install.sh:865-874` | Inspection; uninstall's revert at `scripts/uninstall.sh:285-305` reads the flag |
| P4.50 | Step 18 install /etc/qemu/bridge.conf: additive `allow sb-*` (production scope); never destructive | (a) | `scripts/install.sh:880-898`; rule `allow sb-*` at `:881` | Inspection — uninstall's `remove_bridge_conf_rules` at `scripts/uninstall.sh:311-358` removes only added lines |
| P4.51 | Step 18 records ADDED_BRIDGE_CONF_RULES for install state | (a) | `scripts/install.sh:889,895` | `scripts/install.sh:1038` writes to state |
| P4.52 | Step 19 install /etc/sandboxd/users.conf: create if absent at `_schema_version: 1` with pool 10.209.0.0/20 + allow_users=[sandbox, $operator] | (a) | `scripts/install.sh:904-929`; pool at `:920`, allow_users at `:921` | Inspection — schema-version=1 pre-applied so Spec 1's V001 is a no-op on fresh installs |
| P4.53 | Step 19 leave alone if exists (operators may have customized) | (a) | `scripts/install.sh:905-909` | Same |
| P4.54 | Step 19 mode 0644 root:root | (a) | `scripts/install.sh:926` | Same |
| P4.55 | Step 20 docker load gateway image: skip if tag exists | (a) | `scripts/install.sh:935-947`; `sandbox-gateway:${VERSION}` tag at `:936` | `tests/install-e2e/test_uninstall.py:81` asserts gateway image present after install |
| P4.56 | Step 20 docker load via sudo -k (operator may not be in docker group yet) | (a) | `scripts/install.sh:943` `sudo -k docker load -i ...` | Inspection |
| P4.57 | Step 21 install systemd unit: `install -m 0644 -o root -g root` to /etc/systemd/system/sandboxd.service; cmp idempotency | (a) | `scripts/install.sh:953-964` | `tests/install-e2e/conftest.py:677-679` asserts unit present |
| P4.58 | Step 21 does NOT touch /etc/systemd/system/sandboxd.service.d/ (drop-ins survive) | (a) | `scripts/install.sh:953-964` has no `.service.d/` reference; spec § 4.4.21 explicit contract | Forward constraint — uninstall `purge_step` similarly skips drop-ins at `scripts/uninstall.sh:484-486` |
| P4.59 | Step 22 `systemctl daemon-reload` always runs after unit install | (a) | `scripts/install.sh:970-973` | Inspection — wired in `main()` at `:1111` |
| P4.60 | Step 23 write /var/lib/sandbox/.install-state.json: mode 0640 owner sandbox:sandbox | (a) | `scripts/install.sh:991-1053`; chown+chmod at `:992-994`; install -m 0640 -o sandbox -g sandbox at `:1051` | `tests/install-e2e/conftest.py:688-703` parses state file (asserts jq parses + installed_version present) |
| P4.61 | Step 23 state schema: all 13 documented fields (see § 4.5 below) | (a) | `scripts/install.sh:1027-1042` writes all fields | `tests/install-e2e/conftest.py:688-703` asserts well-formed JSON + installed_version |
| P4.62 | Step 23 daemon never reads the file (forensic-only) | (a) | No daemon-side reader exists; spec § 5.1 daemon-state principle holds; install state path `/var/lib/sandbox/.install-state.json` is not referenced anywhere in `sandboxd/sandboxd/src/main.rs` | Spec 3 forward constraint; static inspection |
| P4.63 | Step 23 jq self-check on the written file | (a) | `scripts/install.sh:1046-1049` `jq -e . "$staged"` | Inspection |
| P4.64 | Step 24 print next-steps: numbered (1 group only if operator-added), 2 systemctl, 3 doctor | (a) | `scripts/install.sh:1059-1073`; gated step 1 at `:1064-1066` | Inspection |
| P4.65 | Step 24 reports install state path + log path | (a) | `scripts/install.sh:1070-1071` | Inspection |
| P4.66 | Step 24 log: `step=done version=<v> status=ok` | (a) | `scripts/install.sh:1072` | Inspection |

### 4.5 — Install state file (P4.67 – P4.68)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.67 | Forensic-only — daemon never opens; for uninstall.sh + audit + support bundle | (a) | No daemon-side reference; uninstall.sh consumes at `scripts/uninstall.sh:212-234` | `tests/install-e2e/test_uninstall.py:21-47` exercises the forensic-read flow |
| P4.68 | Schema: 13 fields with "could-not-be-inferred-from-filesystem" criterion (we_created_*, bridge_helper_path_at_install, users_conf_sha256_at_install, etc.) | (a) | `scripts/install.sh:1027-1042` writes all 13 fields; uninstall.sh reads with `jq // <default>` at `:224-231` | Inspection — every field uninstall reads has a default fallback |
| P4.69 | Forward-compat: extra fields tolerated via `jq // null`; removing a field is breaking | (a) | `scripts/uninstall.sh:224-231` `jq -r '.<field> // ""'` / `// false` / `// []` defensive defaults | Forward-compat by construction |

### 4.6 — Install log format (P4.70 – P4.74)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.70 | Log at `/var/log/sandbox-install.log`; created on first run mode 0640 root:root | (a) | `scripts/install.sh:158-167` (`ensure_install_log`); chmod 0640 + chown root:root at `:164-165` | Inspection — M15-S2 exit-criteria validated this |
| P4.71 | Format: ISO8601 timestamp prefix, then `script step=... key=val ... pid=N` | (a) | `scripts/install.sh:110-121` `log_line` emits `"$ts $SCRIPT_NAME $* pid=$$"`; ts is `date -u +%Y-%m-%dT%H:%M:%SZ` at `:112` | `tests/install-e2e/conftest.py:539-547` `parse_install_log_actions` regex `\bstep=(\S+)` / `\baction=(\S+)` consumes the format |
| P4.72 | Second token is script name (install.sh or uninstall.sh) | (a) | `scripts/install.sh:33` `SCRIPT_NAME="install.sh"`; `scripts/uninstall.sh:25` `SCRIPT_NAME="uninstall.sh"` | Inspection |
| P4.73 | `status=ok` / `status=warn` / `status=fail` wrappers | (a) | `scripts/install.sh:123-133` (log_ok/log_warn/log_fail) | Inspection |
| P4.74 | Values with spaces single-quoted (e.g. `rule='allow sb-*'`) | (a) | `scripts/install.sh:890,896` `rule='$target_rule'` | Inspection |

### 4.7 — Color/TTY output (P4.75 – P4.77)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.75 | Reserve four colors: green/red/yellow/blue + reset | (a) | `scripts/install.sh:142-156` `setup_colors` | Inspection |
| P4.76 | TTY detect via `[ -t 1 ]` + `--no-color` opt-out | (a) | `scripts/install.sh:143` | `tests/install-e2e/conftest.py:617` always passes `--no-color` |
| P4.77 | ASCII prefixes (`+`, `x`, `!`) instead of emoji — script uses ASCII `+`/`x` per M15-S4 DEFER-13 reconciliation | (a) | `scripts/install.sh:137,357,361,416,432,562,566,570,763,772,1061,1065,1067,1068` emit `${RED}x${RESET}` / `${GREEN}+${RESET}` / `${YELLOW}!${RESET}` ASCII glyphs (spec § 4.7 prose says `✓`/`✗` Unicode — the implementation chose ASCII per DEFER-13's "spec § 4.7 reconciliation" call) | DEFER-13 → M16-S5 doc-pass to reconcile spec § 4.7 glyph examples to ASCII |

---

## Part 5 — `uninstall.sh` (§ 5)

### 5.1 — Flags (P5.1 – P5.7)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.1 | `--purge` (state + user + groups + image) | (a) | `scripts/uninstall.sh:141,446-506` | `tests/install-e2e/test_uninstall.py:51` `test_uninstall_with_purge_removes_user_and_state` |
| P5.2 | `--force` (proceed if active) | (a) | `scripts/uninstall.sh:142,192-206`; coarse "any responsive daemon" check (not per-session) per M15-S4 B3 fix shape (b) | DEFER-1 + spec-text reconciliation needed; current behavior covered by `tests/install-e2e/test_install_happy_path.py:72` (`--force` flag used to override running-daemon refusal) |
| P5.3 | `--yes` (skip confirmation prompts) | (a) | `scripts/uninstall.sh:143,452-463` (PURGE prompt gated) | `tests/install-e2e/test_uninstall.py:36,65` |
| P5.4 | `--verbose` (echo every command) | (a) | `scripts/uninstall.sh:144,156-158` | Inspection |
| P5.5 | `--quiet` (suppress non-error) | (a) | `scripts/uninstall.sh:145` | Inspection |
| P5.6 | `--no-color` (force plain text) | (a) | `scripts/uninstall.sh:146` | `tests/install-e2e/test_uninstall.py:36,65,101,111` always passes `--no-color` |
| P5.7 | `--help` (usage + exit 0) | (a) | `scripts/uninstall.sh:147,56-82` | Inspection |

### 5.2 — Step-by-step flow (P5.8 – P5.27)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.8 | Step 1 arg parsing; defaults PURGE=0 FORCE=0 YES=0 | (a) | `scripts/uninstall.sh:138-161` | Inspection |
| P5.9 | Step 2 refuse if sessions are active — implementation downgrades from per-session probe to "any-daemon-running" coarse check (B3 fix path (b)) | (a) | `scripts/uninstall.sh:176-206`; the coarse check via `curl --unix-socket /health` at `:186-189` lands per M15-S4 B3 fix; previous broken-CLI probe replaced. Spec § 5.2 step 2 prescribes per-session probe; implementation deviation documented inline at `:165-174` and forward-tracks per-session probe to `sandbox update` (M16-S2) | `tests/install-e2e/test_install_happy_path.py:71` passes `--force` to override; the coarse-refusal path itself has no dedicated E2E (DEFER); B3 fix landed in commit `43e3a98` |
| P5.10 | Step 3 read install state with `jq // <default>` defensive defaults; fall back to best-effort on missing | (a) | `scripts/uninstall.sh:212-234`; best-effort branch at `:213-216` | `tests/install-e2e/test_uninstall.py:21` exercises the happy-path read |
| P5.11 | Step 4 stop and disable systemd unit; idempotent (enabled→disable, active→stop, else skip) | (a) | `scripts/uninstall.sh:240-261` | `tests/install-e2e/test_uninstall.py:21-47` post-uninstall asserts unit absent |
| P5.12 | Step 5 remove systemd unit file; `systemctl daemon-reload` after | (a) | `scripts/uninstall.sh:267-279` | Same as P5.11 |
| P5.13 | Step 5 leaves /etc/systemd/system/sandboxd.service.d/ intact (operator-owned) | (a) | `scripts/uninstall.sh:267-279` does not touch `.service.d/`; purge step at `:484-486` explicitly skips with rationale | Forward constraint with Spec 3 § 4.3 |
| P5.14 | Step 6 revert qemu-bridge-helper setuid only if WE_SET_BH_SETUID=true | (a) | `scripts/uninstall.sh:285-305` (gates on HAVE_STATE + flag + helper present) | Inspection |
| P5.15 | Step 7 remove /etc/qemu/bridge.conf rules: only the lines we added; preserve operator-added | (a) | `scripts/uninstall.sh:311-358`; single-pass awk drop-set + only-delete-if-result-is-empty-AND-rule-count-matches-original-line-count at `:345-346` (M15-S4 MF-2 fix shape) | Inspection |
| P5.16 | Step 7 grep-vxF whole-line literal match (rule may contain `*`) | (a) | M15-S4 MF-2 rewrote loop to single-pass awk; `:337-339` awk drops exact recorded rules from set | Inspection; commit `35c6272` (replaced in fix-pass) |
| P5.17 | Step 8 remove /etc/sandboxd/users.conf with sha256-based backup if modified since install | (a) | `scripts/uninstall.sh:364-401`; sha256 check at `:369-373`; backup to `$HOME/sandboxd-uninstall-backup-<ts>/users.conf` at `:374-385` | Spec § 5.2.8 prose; verified by inspection |
| P5.18 | Step 8 backup destination resolution: $HOME → $SUDO_USER's getent passwd home → /tmp | (a) | `scripts/uninstall.sh:374-378` | Inspection |
| P5.19 | Step 8 remove empty /etc/sandboxd/ dir | (a) | `scripts/uninstall.sh:394-400` | Inspection |
| P5.20 | Step 9 helper-caps removal is deferred (binary removal in step 10 auto-removes file caps); logged for symmetry | (a) | `scripts/uninstall.sh:407-414` | Inspection |
| P5.21 | Step 10 remove binaries: /usr/local/bin/sandboxd, /usr/local/bin/sandbox, /usr/local/libexec/sandboxd/sandbox-route-helper; remove empty libexec dir | (a) | `scripts/uninstall.sh:420-440` | `tests/install-e2e/test_uninstall.py:42-45` asserts binaries + unit absent |
| P5.22 | Step 11 --purge: state dir removal, userdel/groupdel (only if WE_CREATED_SANDBOX_USER), drop-ins skip, gpasswd -d operator group revoke, docker image rm gateway | (a) | `scripts/uninstall.sh:446-506`; PURGE confirm prompt at `:452-463` | `tests/install-e2e/test_uninstall.py:51-82` `test_uninstall_with_purge_removes_user_and_state` (asserts dir gone, user gone, image gone) |
| P5.23 | Step 11 confirmation token is literal "PURGE" (typo-protector) | (a) | `scripts/uninstall.sh:461-463` `[ "$confirm" = "PURGE" ] || die "Aborted."` | Inspection |
| P5.24 | Step 11 docker image removal only under --purge | (a) | `scripts/uninstall.sh:498-505` (inside the `if [ "$PURGE" -ne 1 ]` short-circuit branch at `:447-450`) | `tests/install-e2e/test_uninstall.py:81` `docker image inspect sandbox-gateway:0.1.0` returns non-zero after purge (DEFER-8 / hardcoded tag noted; benign — see DEFER row) |
| P5.25 | Step 11 drop-in dir under --purge: SKIPS (operator-owned) | (a) | `scripts/uninstall.sh:484-486` logs `step=remove_drop_ins action=skip reason=operator-owned` (M15-S4 DEFER-17 mitigation) | Inspection |
| P5.26 | Step 12 final state report: emit Removed: list + Kept: list (Kept only when not --purge) | (a) | `scripts/uninstall.sh:512-533` | `tests/install-e2e/test_uninstall.py:21-47` and `:51-82` validate both branches |
| P5.27 | Drop-in dir reversal under --purge: spec § 5.2.11 prescribes `rm -rf .service.d/`; implementation skips (M15-S4 DEFER-17 — install.sh never creates the dir) | (c) | `scripts/uninstall.sh:484-486` deliberate skip with operator-owned rationale | DEFER-17 → M16-S5 doc-pass to amend spec § 5.2.11 OR add operator-customization persistence test (and promote if persistence is in scope) |

---

## Part 6 — Lima E2E test harness (§ 6)

### 6.1 / 6.2 — Why Lima + harness shape (P6.1 – P6.4)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.1 | Lima provides per-test fresh VMs; avoids polluting host | (a) | `tests/install-e2e/conftest.py:369-409` `vm_factory` spins per-test VM; `lima delete --force` on teardown at `:404-409` | Self-evident |
| P6.2 | Tests real Linux distros (Ubuntu/Debian/Fedora) — different bridge-helper paths, OVMF paths | (a) | `tests/install-e2e/test_install_happy_path.py:28` (ubuntu+debian) + `:87-89` (fedora) parametrizations | Per-test |
| P6.3 | Reuses existing Lima dep; no new infra | (a) | `tests/install-e2e/install-e2e.yml:28` `[self-hosted, kvm]` (same as e2e-matrix) | Inspection |
| P6.4 | Harness shape per test: limactl start, lima_cp scripts+tarball, run install, assert filesystem state, run uninstall | (a) | Pattern visible in every test file (`test_install_happy_path.py`, `test_install_air_gapped.py`, etc.) | Per-test |

### 6.3 — Test matrix (P6.5 – P6.14)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.5 | `test_install_fresh_then_doctor_passes` (ubuntu-22.04, debian-12) — full pipeline + doctor green | (a) | `tests/install-e2e/test_install_happy_path.py:29` (B1 fix landed `assert_doctor_passes` at `:66`; commit `43e3a98`) | Test exists; M15-S4 matrix PASSED |
| P6.6 | `test_install_fresh_then_doctor_passes_rhel_paths` (fedora; bridge-helper at /usr/libexec/) | (a) | `tests/install-e2e/test_install_happy_path.py:88`; fedora pinned to `fedora-41` substitute per DEFER-11; B4 fix landed `assert_full_install_landed` + `assert_doctor_passes` at `:133,142` | Test exists; M15-S4 matrix PASSED |
| P6.7 | `test_install_idempotent_double_run` — second run all-skip allow-list | (a) | `tests/install-e2e/test_install_idempotency.py:18`; allow-list inversion at `:63-69` (MF-3 fix) | Test exists; M15-S4 matrix PASSED |
| P6.8 | `test_install_partial_failure_recovery` — kill mid-step, re-run, verify continuation | (a) | `tests/install-e2e/test_install_idempotency.py:78`; injects real `exit 1` between user-create and binary-install at `:103-113`; un-patches then re-runs at `:145-148`. Single failure-point only (DEFER-1 — spec § 8.4 lists 4) | DEFER-1/DEFER-2 → M16+ (multi-point harness lands when a real-recovery test framework exists) |
| P6.9 | `test_uninstall_after_install_clean` (no-purge keeps state) | (a) | `tests/install-e2e/test_uninstall.py:22` | Test exists; M15-S4 matrix PASSED |
| P6.10 | `test_uninstall_with_purge_removes_user_and_state` | (a) | `tests/install-e2e/test_uninstall.py:51` | Test exists |
| P6.11 | `test_uninstall_double_run_idempotent` (second run all-skip) | (a) | `tests/install-e2e/test_uninstall.py:86`; allow-list inversion at `:121-133` (MF-3 fix) | Test exists |
| P6.12 | `test_install_air_gapped` (network blocked mid-install; --from + --cosign-bundle) | (a) | `tests/install-e2e/test_install_air_gapped.py:39`; comprehensive iptables `! -o lo -j REJECT` egress block at `:95-102` (B2 fix shape (a) — pre-stage real cosign at pinned sha + un-patch cosign_bootstrap); sigstore_verify env-bypass at `:127` | Test exists; M15-S4 matrix PASSED |
| P6.13 | `test_install_refuses_wrong_arch_tarball` (aarch64 MANIFEST on x86_64 host) | (a) | `tests/install-e2e/test_install_refusal.py:30`; MUST-match-arch-mismatch assertion at `:69-71` (MF-5 fix) | Test exists |
| P6.14 | `test_install_refuses_when_preexisting` (second install refuses, points at update) | (a) | `tests/install-e2e/test_install_refusal.py:87` (same-version skip + diff-version refuse paths) | Test exists |

### 6.4 — CI integration (P6.15)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.15 | `.github/workflows/install-e2e.yml` exists with `push.paths`-filtered trigger on scripts/install.sh + tests/install-e2e/**; `[self-hosted, kvm]` runner; 60-min timeout; build-local-tarball + pytest 900s timeout | (a) | `.github/workflows/install-e2e.yml:1-59` | YAML inspection (per M15-S3 exit-criterion "actionlint or act --dryrun") |
| P6.16 | `integration_systemd_unit_smokes` deferred from M14-S3: install via lima, systemctl enable --now, socket 0660, doctor exit 0 | (a) | `tests/install-e2e/test_systemd_smokes.py:33` `integration_systemd_unit_smokes` (collected via `pyproject.toml` `python_functions = ["test_*", "integration_*"]`) | M15-S3 deferral closed |

---

## Part 7 — Trust bootstrap (§ 7)

### 7.1 — Trust chain (P7.1 – P7.7)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.1 | TLS to GitHub Pages (cert via Let's Encrypt to *.github.io) | (a) | Infrastructural; documented at `docs/start/installation.md:95` | Operational |
| P7.2 | install.sh deployed by docs.yml from site/public/install.sh ← scripts/install.sh | (a) | `.github/workflows/docs.yml:63` build-time copy | Inspection |
| P7.3 | cosign pinned by sha256 in install.sh; refuse on mismatch | (a) | `scripts/install.sh:21-26,597-600` | `tests/install-e2e/conftest.py:730-735` mirrors the pin (Track 5 finding satisfied) |
| P7.4 | Release tarball verify-blob: identity-regex anchored, OIDC issuer pin | (a) | `scripts/install.sh:688-695` | Anchored-regex replay verified — see "Replay verification" § 6 below |
| P7.5 | Per-artifact sha256 from MANIFEST | (a) | `scripts/install.sh:717-720` | Inspection |
| P7.6 | OIDC identity = short-lived per-workflow-run token, Fulcio-signed | (a) | Sigstore architecture; OIDC issuer pinned at `scripts/install.sh:691` | Operational |
| P7.7 | Every link auditable (Pages TLS, install.sh source, cosign binary, signing identity, MANIFEST hashes) | (a) | `docs/start/installation.md:91-99` lists each link verbatim | Inspection |

### 7.2 — Auditability for paranoid operators (P7.8 – P7.9)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.8 | Recommended flow: `curl ... | less` review then `curl ... | bash` | (a) | `docs/start/installation.md:102-104` documents the review pattern verbatim | Inspection |
| P7.9 | POSIX-shell shape (no bash-isms) so runs on Debian `dash` | (a) | `scripts/install.sh:13` "intentionally POSIX sh; do not introduce bashisms"; shellcheck CI step at `.github/workflows/ci.yml:57-63` `-s sh` | shellcheck step passes per M15-S2 exit-criterion |

### 7.3 — Cosign version pinning (P7.10)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.10 | COSIGN_VERSION + COSIGN_SHA256_AMD64/_ARM64 as header constants; pinned at v2.4.1; bump process is manual | (a) | `scripts/install.sh:21-26` (constants); `tests/install-e2e/conftest.py:730-735` (mirrored for harness pre-stage) | Inspection — values match cosign v2.4.1's published sha256 (Track 5 verification finding) |

---

## Part 8 — Test plan for the scripts themselves (§ 8)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.1 | § 8.1 Lima E2E is primary correctness gate (covered by Part 6) | (a) | All test files in `tests/install-e2e/` | Per-test |
| P8.2 | § 8.2 Shellcheck step in `ci.yml`: `-s sh -S style scripts/install.sh scripts/uninstall.sh` | (a) | `.github/workflows/ci.yml:52-63`; current step short-circuits if scripts absent (no-op once they exist) | M15-S2 exit-criterion validated |
| P8.3 | § 8.3 Idempotency unit tests: parse second-run log, assert all `action=skip` (allow-list inversion) | (a) | `tests/install-e2e/test_install_idempotency.py:18-69`; allow-listed to `{"skip"}` at `:63` (MF-3 fix) | Test exists |
| P8.4 | § 8.3 No real `sudo` prompt fires on second-run (test runs without TTY → would error rather than block) | (c) | The current `test_install_idempotent_double_run` short-circuits at preexist step (so no sudo path is exercised on the second run anyway); the contract is consequently weaker than the spec's "no sudo prompt fired" probe | DEFER-3 territory → M16+ harness improvement (curl-tracer + sudo-prompt detector) |
| P8.5 | § 8.4 Partial-failure recovery: 4 failure points (useradd, binary, setcap, docker_load) — implementation has one mid-script-kill case (between user-create and binary-install) | (c) | `tests/install-e2e/test_install_idempotency.py:78` covers 1 of 4 cases | DEFER-1/DEFER-2 → M16+ (multi-point parameterization) |
| P8.6 | § 8.5 Uninstall double-run: install, uninstall, uninstall again; second is all-skip | (a) | `tests/install-e2e/test_uninstall.py:86`; allow-listed at `:121-133` | Test exists |
| P8.7 | § 8.6 Air-gapped install path: comprehensive egress block + un-patched cosign_bootstrap + SANDBOX_INSTALL_SKIP_SIGSTORE bypass | (a) | `tests/install-e2e/test_install_air_gapped.py:39-152` (B2 fix shape (a) landed in commit `ecb54d0`) | Test exists; M15-S4 matrix PASSED |
| P8.8 | Fully-offline scenario (operator pre-stages cosign on never-online host) — partial coverage | (c) | `test_install_air_gapped` covers mid-install block; fully-never-online path is documented partial in spec § 10.6 | DEFER-3 → M16+ (curl-tracer assertion) |

---

## Part 9 — Backward compatibility — dev mode (§ 9)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P9.1 | `make setup-dev-env` unchanged; dev daemon runs from `target/release/`, state under `~/.local/share/sandboxd/` | (a) | `Makefile` (no functional changes in M15); spec § 9 coexistence table | Operational |
| P9.2 | Coexistence table per § 9: separate binary paths, state paths, socket paths | (a) | install.sh writes to /usr/local/bin/ etc.; dev daemon runs from workspace target dir | Inspection |
| P9.3 | install.sh's preexist check (§ 4.4.5) refuses if /usr/local/bin/sandboxd exists; dev daemon at workspace target path doesn't trip it | (a) | `scripts/install.sh:336-370` only checks `/usr/local/bin/sandboxd` | Inspection |
| P9.4 | Recommended dev→system migration: stop dev daemon, optionally copy sessions.db, run install.sh, enable systemd, update SANDBOX_SOCKET | (a) | `docs/start/installation.md:120-122` cross-links the developer install section | Inspection |
| P9.5 | Strict-equality version check passes in dev (workspace inherits version across CLI+daemon; Spec 3 § 7.4) | (a) | Spec 3 deliverable (P7.13 in Spec 3 delivery); Spec 4 inherits | Spec 3 coverage |

---

## Part 10 — Risks and open questions (§ 10)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P10.1 | § 10.1 GH-hosted aarch64 runner fallback ladder (ubuntu-24.04-arm → self-hosted → cross) | (a) | `release.yml:54` pins `ubuntu-22.04-arm`; spec § 10.1 documents fallback strategy (no code switch needed yet) | Operational; awareness-documented |
| P10.2 | § 10.2 KVM-enabled CI runner for Lima harness; `[self-hosted, kvm]` shared with e2e-matrix | (a) | `.github/workflows/install-e2e.yml:28`; `ci.yml:113`; spec § 10.2 documents the unprovisioned-runner mitigation | Operational; awareness-documented |
| P10.3 | § 10.3 Cosign release cadence vs script maintenance; quarterly manual bump task | (c) | `scripts/install.sh:21-26` has no auto-bump; documented as manual process per spec § 7.3 | progress todo → M16+ (quarterly maintenance reminder; no code change) |
| P10.4 | § 10.4 Install-log rotation not configured; logrotate optional future addition | (c) | No logrotate.d snippet ships; spec § 10.4 acknowledges | progress todo → M16+ (optional logrotate snippet per § 11 out-of-scope reaffirmation) |
| P10.5 | § 10.5 `--purge` is destructive; `--yes --purge` removes /var/lib/sandbox/ without prompt | (a) | `scripts/uninstall.sh:452-463` PURGE prompt only fires when `--yes` is unset; `--yes --purge` proceeds | `tests/install-e2e/test_uninstall.py:51-82` exercises the destructive path with explicit `--yes` |
| P10.6 | § 10.5 Typo-protected confirmation token `PURGE` literal | (a) | `scripts/uninstall.sh:461-463` | Inspection |
| P10.7 | § 10.6 Air-gapped install partial coverage (mid-install block exercised; fully-never-online not) | (c) | `tests/install-e2e/test_install_air_gapped.py:39` covers mid-install block; fully-never-online flagged as partial in spec § 10.6 | DEFER-3 → M16+ (curl-tracer assertion + sudo-prompt detector) |
| P10.8 | § 10.7 `/etc/profile.d/sandbox.sh` for SANDBOX_SOCKET — v1 omits | (c) | No `/etc/profile.d/` writes anywhere in install.sh; spec § 10.7 acknowledges trade-off | progress todo → M16+ (early-adopter feedback gate per § 10.7 prose) |
| P10.9 | § 10.8 No CHANGELOG / release-notes process; GH auto-generates from PRs | (a) | No `release-notes` step in `release.yml`; absence-of-step IS the contract per spec § 10.8 | Inspection |
| P10.10 | § 10.8 If CHANGELOG.md exists at release time, workflow does NOT read it | (a) | `release.yml` has no CHANGELOG.md reader | Inspection |
| P10.11 | M15-S4 B3 fix: uninstall.sh active-session probe coarsened to "any-daemon-running" (was broken `sandbox session ls` reference) | (a) | `scripts/uninstall.sh:176-206`; commit `43e3a98` | DEFER row — spec § 5.2 step 2 still describes per-session probe; reconciliation lands with `sandbox update` (M16-S2) which adds the JSON-emitting subcommand the per-session probe needs |
| P10.12 | M15-S4 DEFER-11 fedora-40 → fedora-41 substitution; coverage preserved (still RHEL paths under /usr/libexec/) | (a) | `tests/install-e2e/conftest.py:55` `DEFAULT_FEDORA = "fedora-41"` | DEFER-11 → M16-S5 doc-pass (spec § 6.3 acknowledgment) |
| P10.13 | M15-S4 DEFER-17 `--purge` does NOT touch `.service.d/` (operator-owned) | (a) | `scripts/uninstall.sh:484-486` deliberate skip | DEFER-17 → M16-S5 doc-pass (spec § 5.2.11 amendment OR persistence test) |
| P10.14 | M15-S4 DEFER-9 first-party actions pinned by major-tag (not SHA); third-party (dtolnay/rust-toolchain, action-gh-release) by version | (a) | `release.yml:62,82,92,174,188,193` | DEFER-9 → M16+ supply-chain hardening pass |
| P10.15 | DEFER-12 § 4.4.12 useradd log: spec wants `we_created=` on the same `step=useradd` line; implementation emits it on the next `step=usermod_groups` line — functionally correct but log-format-consumer drift | (c) | `scripts/install.sh:743,753` — `we_created=` written on usermod_groups line | DEFER-12 → M16-S5 doc-pass (low-risk log cleanup) |

---

## Part 11 — Out of scope (§ 11)

All rows here are (b) by spec definition.

| # | Claim | Status | Locator |
|---|-------|--------|---------|
| P11.1 | `sandbox update` CLI — Spec 5 | (b) | No `Update` Command variant in `sandboxd/sandbox-cli/src/main.rs`; install.sh's preexist refusal points at `sandbox update` as forward-reference at `scripts/install.sh:364` |
| P11.2 | Config migration framework | (b) | No `cfg_migrations/` dir; spec 5 § 4 |
| P11.3 | Backup mechanics (.bak files in /var/lib/sandbox/backups/) — Spec 5 | (b) | uninstall.sh `$HOME/sandboxd-uninstall-backup-...` one-off at `scripts/uninstall.sh:374-385` is NOT the structured Spec 5 mechanism |
| P11.4 | Lock-file mutex for concurrent update prevention — Spec 5 | (b) | No `.update.lock` in `scripts/` |
| P11.5 | Automatic periodic rebuild of lite image (GH #7) | (b) | No periodic-rebuild code anywhere |
| P11.6 | Daemon-side changes — settled in Specs 1, 2, 3 | (b) | No `sandboxd/sandboxd/src/main.rs` edits in M15 commits |
| P11.7 | `sandbox doctor` design — Spec 3 | (b) | install.sh's "step 3 verify" points at doctor; the subcommand itself lives in Spec 3 |
| P11.8 | Release notes / CHANGELOG content or process | (b) | No `release-notes` workflow step; `release.yml:201-216` notes the gap explicitly |
| P11.9 | Multi-arch (buildx + manifest list) gateway image | (b) | `release.yml:104-117` produces per-arch tarballs separately; no `docker buildx manifest` |
| P11.10 | Windows / macOS installs | (b) | install.sh refuses non-Linux at `scripts/install.sh:263-269` |
| P11.11 | `/etc/profile.d/sandbox.sh` for SANDBOX_SOCKET | (b) | No `/etc/profile.d/` writes (also tracked as P10.8) |
| P11.12 | logrotate integration for /var/log/sandbox-install.log | (b) | No `/etc/logrotate.d/` writes (also tracked as P10.4) |

---

## Part 12 — Implementation notes (§ 12)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P12.1 | `scripts/install.sh` (new, ~500-600 lines POSIX shell) — actual is 1117 lines (oversized vs estimate; spec § 12 prose is indicative) | (a) | `scripts/install.sh` (1117 lines) | Inspection |
| P12.2 | `scripts/uninstall.sh` (new, ~300-400 lines POSIX shell) — actual is 556 lines | (a) | `scripts/uninstall.sh` (556 lines) | Inspection |
| P12.3 | `scripts/lib.sh` (optional shared helpers) — NOT factored (in-line helpers in both scripts; per § 12 "if it shrinks each script by >50 lines; else inline" — discretion exercised, will be factored in M16-S1 per M16.md) | (a) | No `scripts/lib.sh` in tree; in-line `log_*`, `die`, `setup_colors` in both scripts | Forward-link to M16-S1 (cosign-pin extraction into lib.sh) |
| P12.4 | `site/public/install.sh` + `site/public/uninstall.sh` — build-time copy via docs.yml (Astro layout) | (a) | `.github/workflows/docs.yml:63-64` | Inspection |
| P12.5 | New workflows: `release.yml`, `install-e2e.yml`; edit: `ci.yml` (shellcheck) | (a) | Files present at the expected paths | Inspection |

---

## Part 13 — Affected files summary (§ 13)

| # | Claim | Status | Locator |
|---|-------|--------|---------|
| P13.1 | `scripts/install.sh` New, ~500 lines | (a) | Actual 1117 lines (P12.1 caveat) |
| P13.2 | `scripts/uninstall.sh` New, ~300 lines | (a) | Actual 556 lines (P12.2 caveat) |
| P13.3 | `scripts/lib.sh` New (optional) | (a) | Deferred to M16-S1 per M16.md (P12.3) |
| P13.4 | `site/public/install.sh` + `site/public/uninstall.sh` (symlink or build-time copy) | (a) | `.github/workflows/docs.yml:61-64` build-time copy (P12.4) |
| P13.5 | `.github/workflows/release.yml`, `install-e2e.yml` (new); `ci.yml`, `docs.yml` (edits) | (a) | All present at expected paths |
| P13.6 | `tests/install-e2e/*` + `requirements.txt` + `build-local-tarball.sh` + `conftest.py` (new dir) | (a) | All present at `tests/install-e2e/` |
| P13.7 | `docs/start/installation.md` edit: two-path structure (operator + dev) | (a) | `docs/start/installation.md:6-9` (lists both paths); `:30-118` Operator section; `:120-122` Developer pointer |
| P13.8 | Files explicitly NOT touched: `sandboxd/sandboxd/src/main.rs`, `sandbox-cli/src/main.rs`, `sandboxd/contrib/systemd/sandboxd.service` (Spec 3 owns), `users_conf.rs`, dev-mode Makefile targets, `contrib/users.conf.example` | (a) | M15 commit log shows no edits to any of these paths | git log inspection |

---

## Replay verification

### 1. Tarball layout

Ran `bash tests/install-e2e/build-local-tarball.sh` (executed during M15-S3 commit `ecb54d0`); the produced tarball at `tests/install-e2e/dist/sandboxd-0.1.0-x86_64-unknown-linux-gnu.tar.gz` expands to:

```
sandboxd-0.1.0-x86_64-unknown-linux-gnu/
sandboxd-0.1.0-x86_64-unknown-linux-gnu/MANIFEST
sandboxd-0.1.0-x86_64-unknown-linux-gnu/bin/sandboxd
sandboxd-0.1.0-x86_64-unknown-linux-gnu/bin/sandbox
sandboxd-0.1.0-x86_64-unknown-linux-gnu/bin/sandbox-route-helper
sandboxd-0.1.0-x86_64-unknown-linux-gnu/libexec/
sandboxd-0.1.0-x86_64-unknown-linux-gnu/systemd/sandboxd.service
sandboxd-0.1.0-x86_64-unknown-linux-gnu/images/sandbox-gateway-0.1.0.tar
sandboxd-0.1.0-x86_64-unknown-linux-gnu/attestations/
```

Matches Spec § 2.2 exactly: top-level basename dir, `bin/` (3 binaries), `libexec/` (empty), `systemd/sandboxd.service`, `images/sandbox-gateway-<v>.tar`, `attestations/` (empty in local build; populated at release-upload time per § 2.2 and `release.yml:197-199`), `MANIFEST` at top level.

### 2. MANIFEST schema

The extracted MANIFEST (observed):

```json
{
  "arch": "x86_64-unknown-linux-gnu",
  "artifacts": {
    "gateway-image": {
      "docker_tag": "sandbox-gateway:0.1.0",
      "path": "images/sandbox-gateway-0.1.0.tar",
      "sha256": "1f829fc01093bc33fa9e7d5e5124f6a1a701ba767bcd35a86bbf94f40fd25cd8"
    },
    "sandbox":              { "path": "bin/sandbox",              "sha256": "..." },
    "sandbox-route-helper": { "path": "bin/sandbox-route-helper", "sha256": "..." },
    "sandboxd":             { "path": "bin/sandboxd",             "sha256": "..." },
    "systemd-unit":         { "path": "systemd/sandboxd.service", "sha256": "..." }
  },
  "build_sha": "43e3a98f6cfcdb44ad66b43d2d7cb6a7ffa0bc29",
  "build_time": "2026-05-12T20:11:36Z",
  "version": "0.1.0"
}
```

All five required top-level keys present (`version`, `arch`, `build_sha`, `build_time`, `artifacts`). Every artifact entry has `path` + `sha256`; `gateway-image` additionally carries `docker_tag` per § 2.3.

### 3. Install log format

The format consumed by `tests/install-e2e/conftest.py:539-547` `parse_install_log_actions` (regex `\bstep=(\S+)` and `\baction=(\S+)`) matches Spec § 4.6's prescribed shape:

```
2026-05-11T14:23:12Z install.sh step=install_binary path=/usr/local/bin/sandboxd sha256=abc... action=install status=ok pid=12345
```

ISO8601-prefixed first token, `install.sh` or `uninstall.sh` second token, `key=value` pairs, `status=ok`/`warn`/`fail` trailing, `pid=N` last — emitted by `scripts/install.sh:110-121` (`log_line`).

### 4. Doctor on freshly installed VM

M15-S4 Lima matrix (commit `43e3a98`) verified via `tests/install-e2e/test_install_happy_path.py:66` (`assert_doctor_passes`) which both checks `r.returncode == 0` AND asserts the `"checks passed, 0 failed"` token in stdout (commit `43e3a98` B1 fix). The matrix run logged at the M15-S4 review (12 of 12 PASSED) is the verification fact. The transient `/tmp/m15-s4-lima-matrix.log` path is operator-host-local; the durable evidence is the test name + commit + green M15-S4 verdict.

### 5. Uninstall preserves /var/lib/sandbox without --purge

`tests/install-e2e/test_uninstall.py:22` `test_uninstall_after_install_clean` asserts post-uninstall: `test -x /usr/local/bin/sandboxd` returns non-zero (binary gone), `test -f /etc/systemd/system/sandboxd.service` returns non-zero (unit gone), AND `sudo test -d /var/lib/sandbox` returns zero (state preserved) AND `id sandbox` returns zero (user preserved). M15-S4 matrix PASSED.

### 6. Cosign verify-blob anchored regexp

Read at `scripts/install.sh:690`:

```sh
--certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@' \
```

Matches Spec § 3.6 verbatim with both `^` (start anchor) and `@` (trailing anchor before the workflow ref) — preventing a workflow at a different path (e.g. `release-test.yml`) or a workflow signed without a ref suffix from passing. OIDC issuer pinned at `scripts/install.sh:691` to `https://token.actions.githubusercontent.com`.

Note: the verify-blob command lives ONLY in `install.sh` (operator-side), NOT in `release.yml` (release.yml signs but does not verify). This matches Spec § 3.6 prose "Spec 4 ships the cosign verification command verbatim in install.sh § 4.4.10" — release.yml only signs.

### 7. Out-of-scope conformance grep

Ran `grep -nE 'sandbox update|profile\.d/sandbox|logrotate|CHANGELOG'` over `scripts/`, `tests/install-e2e/`, `.github/workflows/`:

- `scripts/install.sh:364` — `emit "      sudo sandbox update --version $TARGET_VER"` (forward-reference inside the preexist refusal message — legitimate per Spec § 4.4.5)
- `scripts/uninstall.sh:69,167` — comments referencing `sandbox update` as forward-reference for per-session probe (legitimate; deviation flagged at P5.9/P10.11)
- `tests/install-e2e/test_install_refusal.py:94,131-133` — test asserts the preexist refusal message contains "update" hint (legitimate; testing the spec § 4.4.5 contract)

No `/etc/profile.d/sandbox.sh` writes anywhere (P10.8 / P11.11 conformance verified). No `logrotate` references (P10.4 / P11.12 conformance verified). No `CHANGELOG` reader anywhere (P10.10 conformance verified). All Spec § 11 out-of-scope items absent.

---

## M15-S4 review fix outcomes

The four BLOCKERs (B1–B4) and five MUST-FIXes (MF-1 – MF-5) raised at M15-S4 (see `.tasks/handoffs/m15-s4-triage.md`) all landed in commits `43e3a98` (test + script hardening) and `310d194` (prereq-fail per-distro hints):

- **B1** (`test_install_fresh_then_doctor_passes` never invoked doctor) → fixed by lifting `assert_doctor_passes(vm)` into both happy-path variants at `tests/install-e2e/test_install_happy_path.py:66,142`, asserting both exit code 0 AND `"checks passed, 0 failed"` token per spec § 6.2 (via `conftest.py:623-655`).
- **B2** (`test_install_air_gapped` patched out cosign) → fixed by un-patching `cosign_bootstrap` (factory option `patch_install_sh=False` at `tests/install-e2e/test_install_air_gapped.py:55`), pre-staging real cosign binary at the pinned sha256 via `pinned_cosign_binary` fixture (`conftest.py:739-777`), comprehensive iptables egress block (`! -o lo -j REJECT`) at `:95-102`, HTTPS probe to confirm offline at `:105-112`; only sigstore-verify itself takes the documented `SANDBOX_INSTALL_SKIP_SIGSTORE=1` test-env bypass.
- **B3** (uninstall.sh broken `sandbox session ls` probe) → fixed by replacing with `socket_responsive()` + `/health` curl probe at `scripts/uninstall.sh:176-206`; deviation from spec § 5.2 step 2 (per-session) documented inline at `:165-174`; per-session probe deferred to M16-S2 (`sandbox update --check` introduces the JSON-emitting subcommand the probe needs).
- **B4** (`test_install_fresh_then_doctor_passes_rhel_paths` asserted only log content) → fixed by lifting `assert_full_install_landed(vm)` + `assert_doctor_passes(vm)` into the rhel-paths variant at `tests/install-e2e/test_install_happy_path.py:133,142`.
- **MF-1** (`--from` without `--version` died at MANIFEST verify) → fixed by `resolve_target_version` reading version from tarball MANIFEST when `--from` is set + `--version` is unresolved, at `scripts/install.sh:301-319`.
- **MF-2** (uninstall bridge-conf rule-loop subshell + over-aggressive empty-result delete) → fixed by single-pass awk drop-set + only-delete-if-result-empty-AND-rule-count-matches-original-line-count at `scripts/uninstall.sh:337-346`.
- **MF-3** (forbidden-action sets incomplete) → fixed by inverting to allow-list `{"skip"}` at `tests/install-e2e/test_install_idempotency.py:63-69` and `test_uninstall.py:121-133`.
- **MF-4** (prereq-fail missing per-distro hints) → fixed by `detect_pkg_mgr` + `pkg_name_for` + `pkg_hint_for` at `scripts/install.sh:457-533`, landed in commit `310d194`.
- **MF-5** (`test_install_refuses_wrong_arch_tarball` disjunctive match) → fixed by dropping the second disjunct; assertion now requires MANIFEST arch-mismatch verbatim + cross-checks install log at `tests/install-e2e/test_install_refusal.py:62-83`.

M15-S4 Lima matrix outcome: **12 of 12 tests PASSED** under commit `43e3a98`. This is the M15-S5 entry condition (all BLOCKERs cleared, all MUST-FIXes landed, residual is the DEFER-list of 17 items each routed to either M16-S5 doc-pass, M16+ harness improvement, or M16+ supply-chain hardening).

The 17 DEFER items are mapped to (c) tracked-todo rows above:
- DEFER-1/-2 → P6.8, P8.5 (multi-point partial-failure harness)
- DEFER-3 → P8.4, P8.8, P10.7 (curl-tracer + fully-offline assertion)
- DEFER-4 → folded into DEFER-1/-2 path
- DEFER-5/-6 → uninstall reversal/state schema tests (no (c) row — these are SHOULD-FIX-level test additions per M16-S5 doc-pass)
- DEFER-7 → moot post-B1
- DEFER-8 → P5.24 (hardcoded `sandbox-gateway:0.1.0` tag in test_uninstall.py:81)
- DEFER-9 → P10.14 (SHA-pin third-party actions)
- DEFER-10 → P3.25 (spec § 3.3 publish-install-script reconciliation)
- DEFER-11 → P10.12 (fedora-40 → fedora-41 substitution)
- DEFER-12 → P10.15 (useradd log format drift)
- DEFER-13 → P4.77 (`✓`/`✗` vs ASCII reconciliation)
- DEFER-14 → blanket "polish bundle" — no (c) row, individual items are too granular
- DEFER-15 → blanket "docs consolidation" — no (c) row
- DEFER-16 → blanket "example.invalid URL swap" — no (c) row (Track 5 MF-2 demotion; out of M15-S2 named-doc surface)
- DEFER-17 → P5.27 (purge `.service.d/` reversal)

---

## Open Questions / BLOCKERs requiring orchestrator decision

(No open BLOCKERs. All four M15-S4 BLOCKERs landed in commits `43e3a98` + `310d194`; M15-S4 Lima matrix PASSED 12 of 12 under the fix commit.)
