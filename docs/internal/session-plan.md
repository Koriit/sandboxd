# Session plan

Sandbox daemon providing isolated Linux VMs (Lima/QEMU) for coding agents. Per-milestone session detail lives in [milestones/](milestones/); each milestone file links the design-doc specs it implements.

---

## M0 — Project Scaffolding
**Goal.** Cargo workspace, directory structure, pytest setup.
**Status.** completed · **Sessions.** 1 · **Details.** [milestones/M0.md](milestones/M0.md)

## M1 — sandboxd Skeleton + Lima VM Lifecycle
**Goal.** CLI, session store, Lima integration, session lifecycle.
**Status.** completed · **Sessions.** 4 · **Details.** [milestones/M1.md](milestones/M1.md)

## M2 — vsock Control Channel
**Goal.** Host connector, VM-side listener, SSH over vsock.
**Status.** completed · **Sessions.** 3 · **Details.** [milestones/M2.md](milestones/M2.md)

## M3 — Gateway Container + Per-Session Networking
**Goal.** Gateway image, Docker bridge, nftables, CA lifecycle, orchestration.
**Status.** completed · **Sessions.** 6 · **Details.** [milestones/M3.md](milestones/M3.md)

## M4 — Policy Engine
**Goal.** Policy schema, compilation, CoreDNS plugin, mitmproxy addon, DNS propagation.
**Status.** completed · **Sessions.** 6 · **Details.** [milestones/M4.md](milestones/M4.md)

## M5 — Workspace Provisioning
**Goal.** Clone mode, cp, git-over-vsock.
**Status.** completed · **Sessions.** 3 · **Details.** [milestones/M5.md](milestones/M5.md)

## M6 — Hardening
**Goal.** QEMU sandboxing, device model lockdown.
**Status.** completed · **Sessions.** 3 · **Details.** [milestones/M6.md](milestones/M6.md)

## M7 — Documentation
**Goal.** Polish and consolidate user, operator, and contributor docs.
**Status.** completed · **Sessions.** 1 · **Details.** [milestones/M7.md](milestones/M7.md)

## M8 — Polish and Deferred TODOs
**Goal.** Resolve accumulated TODOs, deferred findings, technical debt.
**Status.** completed · **Sessions.** 3 · **Details.** [milestones/M8.md](milestones/M8.md)

## M8.5 — E2E Fix-up
**Goal.** Fix all runtime issues preventing E2E tests from passing.
**Status.** completed · **Sessions.** 4 · **Details.** [milestones/M8.5.md](milestones/M8.5.md)

## M9 — User Polish and Refactors
**Goal.** XDG paths, docs, timeouts, test runners, pre-baked images.
**Status.** completed · **Sessions.** 19 · **Details.** [milestones/M9.md](milestones/M9.md)

## M10 — Port-explicit policies, presets, and observability
**Goal.** v2 policy schema with explicit ports, CLI-local preset system, unified event surface across all policy layers.
**Status.** completed · **Sessions.** 10 · **Details.** [milestones/M10.md](milestones/M10.md)

## M11 — Lite mode: container backend
**Goal.** Second `sandboxd` session backend (Docker container via `--lite`) behind a new backend abstraction; full UX parity with VM sessions, container-level isolation traded for fast session creation. M11-S7 added post-verification for residual quality items; M11-S8 added to enforce the rootless-Docker out-of-scope contract in code rather than relying on test-side skipifs that silently masked it; M11-S9 added to harden the route helper's authorization config against env-var override, simplify the daemon-side resolver, and bundle the dev-environment make-target setup that the prior sessions implicitly assumed; M11-S10 added to promote the orphan reaper's CIDR-anchor (currently doc-only) to enforced filtering, closing the cross-daemon mass-delete gap.
**Status.** completed · **Sessions.** 10 · **Details.** [milestones/M11.md](milestones/M11.md)

## M12 — Loose ends & UDP hardening
**Goal.** Drain the deferred-todo backlog, harden UDP support to a known-working transport, and reconcile design/spec/code drift before further feature work. M12-S1 fixes the UDP pre-DNAT deny-event attribution (#29) so downstream UDP work has correct deny tuples; M12-S2 corrects the UDP datapath itself (allow-path skips Envoy, deny-path becomes `nft drop` + NFLOG, new conntrack-driven allow-flow logger, deny-logger splits into two `nft-`-prefixed binaries on a shared `sandbox-event-emitter` lib) and reconciles every UDP-overclaiming doc — full design at `.tasks/specs/2026-05-01-udp-nft-loggers/2026-05-01-udp-nft-loggers-design.md`; M12-S3 reverts the CoreDNS plugin's blanket-deny on SVCB/HTTPS to the original strip-only design (the spec was right, the implementation drifted) and folds in the small `version`-field doc clarification; M12-S4 closes M11 verifier follow-ups (`--no-cache` daemon enforcement, orphan TODO, fractional cpus, cross-session L4 isolation test, delivery-doc wording) and lands the first new preset since M11 (`ubuntu` default-allow); M12-S5 does the reviewer-nit + cleanup-rename round-up; M12-S6 strips milestone references from code/tests; M12-S7 refactors `sandbox cp` to native `limactl cp` / `docker cp`; M12-S8 adds rsync-like directory sync on top; M12-S9 is a backlog buffer that prevents M12 itself from reseeding the deferred pile; M12-S10 is the terminal claim-to-code verification gate — M12.md acts as the spec, every concrete claim across S1–S9 must map to a code+test locator, an explicit out-of-scope bullet, or a tracked follow-on before M12 can close. M12-S11 executes three follow-on items selected after the post-S10 review: run the deferred sync E2E pair on both backends (#130, ~80 min wall-clock), strip the milestone-tag exemption from `CLAUDE.md` and rename all milestone-tagged file/symbol names workspace-wide (#131), and refresh `CLAUDE.md` end-to-end against current `Cargo.toml`/`Makefile`/conventions (#133); M12-S12 fixes two Lima daemon bugs surfaced during the S11 sync E2E run — #136 partial-clone instance cleanup on `clone_vm` error paths, #137 base-image provisioning validation (probe `socat`/`git`/`rsync`/`docker` between base-VM boot and golden-image stamping) — and re-runs the sync E2E pair to confirm green; M12-S13 closes the test/prod isolation gap that made the e2e suite blast-radius across production daemon resources, by landing two harness-side isolations together so the conftest preflight sweep can finally be deleted: (A) singleton isolation — replace `const BASE_VM_NAME` with a `LimaManager.base_vm_name` field driven by a validated `SANDBOX_BASE_VM_NAME` env knob, so the test daemon manages a distinct base VM (`sandbox-test-base`) from production; (B) CIDR pool isolation — add a `comment: Option<String>` field to `SubnetEntry` (with `#[serde(default)]` so existing files keep parsing), update `contrib/users.conf.example` to ship two pools (prod `10.209.0.0/20`, test `10.220.0.0/20`) with explanatory comments, teach `make setup-users-conf` to idempotently append the test pool to existing canonical files, and have conftest write a tempfile users.conf with only the test pool and set `SANDBOX_USERS_CONF=<tempfile>` for the spawned test daemon (the daemon honors the override unconditionally per M11-S9; the production route helper continues reading the canonical `/etc/sandboxd/users.conf` — which now lists both pools — so authorization succeeds without weakening the privilege boundary); (C) drop the destructive `_preflight_checks` sweep at `tests/e2e/conftest.py:287-350` entirely, leaving cleanup to the M11-S10 CIDR-scoped reaper which now has genuinely disjoint pools to filter on; (D) replace the existing "Lima-only tests skip on container" e2e convention with a marker-based one — `@pytest.mark.lima` / `@pytest.mark.container` for single-backend tests (no `backend` fixture, hardcoded backend in `make_create_args`), Linux/KVM check dropped from session-scoped preflight (Lima's native probing handles it cleanly across Linux+KVM and the upcoming macOS VZ backend), Lima-installed check moved behind a `lima`-marker-gated fixture, and Makefile selectors switched to `-m "not lima" -k "not [lima]"` for `test-e2e-container` so both `make test-e2e-container` and `make test-e2e-matrix` produce zero convention-driven skips.
**Status.** in_progress · **Sessions.** 13 · **Details.** [milestones/M12.md](milestones/M12.md)

## M13 — Security foundations: helper identity + API session isolation
**Goal.** Implement Specs 1 and 2 of the five-spec arc: route-helper pair-membership identity check + daemon SO_PEERCRED plumbing (Spec 1) and per-caller API session ownership + guest version compatibility infrastructure (Spec 2). Together they make a dedicated `sandbox` system user safe at both the helper-authorization and API layers. Terminal milestone for Spec 1 and Spec 2; ends with a multi-track review (S6) and dual claim-to-code verification (S7). Specs 3–5 follow in M14–M16.
**Status.** not_started · **Sessions.** 7 · **Details.** [milestones/M13.md](milestones/M13.md)

## M14 — Daemon productionization
**Goal.** Implement Spec 3 of the five-spec arc: hardened daemon startup (state-dir mode enforcement, `sessions.db` chmod), version-pinned gateway image references, QEMU wrapper cleaned of its rootless-Docker branch, the `/version` endpoint, strict CLI ↔ daemon version equality on every connect, the `sandbox doctor` diagnostic subcommand, and `GET /diagnostics`. Ships `sandboxd/contrib/systemd/sandboxd.service` as a source artifact for Spec 4 to install. Terminal milestone for Spec 3.
**Status.** not_started · **Sessions.** 5 · **Details.** [milestones/M14.md](milestones/M14.md)

## M15 — Release & install infrastructure
**Goal.** Implement Spec 4 of the five-spec arc: GitHub Actions release pipeline (tagged builds, cosign/sigstore attestations, multi-arch tarballs, MANIFEST), `install.sh` + `uninstall.sh` curl|bash scripts hosted on GitHub Pages, and the Lima-based E2E harness that exercises them on real Linux distros. Closes the `integration_systemd_unit_smokes` coverage gap from M14. Terminal milestone for Spec 4.
**Status.** not_started · **Sessions.** 5 · **Details.** [milestones/M15.md](milestones/M15.md)

## M16 — Update infrastructure
**Goal.** Implement Spec 5 — the terminal spec of the five-spec arc: `sandbox update` CLI subcommand (30-step pre-flight + stateful orchestration), config migration framework (`ConfigMigration` trait, V001 adapter, apply loop, atomic write), lock file with sticky `was_running`, backup mechanics with 2-set retention, daemon-side `_schema_version` mismatch refusal, and the Lima E2E harness extension that proves the full update cycle. Terminal milestone for Spec 5 and the entire five-spec arc; M16-S5 verifies Spec 5 plus every arc-level forward constraint from Specs 1–4.
**Status.** not_started · **Sessions.** 5 · **Details.** [milestones/M16.md](milestones/M16.md)

---

## Future milestones

Separate tracks, not on the critical path. Tracked here for planning continuity; execution is deferred.

### F1 — macOS Support
**Goal.** socket_vmnet, Colima, macvlan.
**Status.** not_started · **Sessions.** 2 · **Details.** [milestones/F1.md](milestones/F1.md)

### F2 — Policy Persistence Hardening
**Goal.** Schema migration playbook, encryption at rest.
**Status.** not_started · **Sessions.** 2 · **Details.** [milestones/F2.md](milestones/F2.md)

