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
**Status.** completed · **Sessions.** 13 · **Details.** [milestones/M12.md](milestones/M12.md)

## M13 — Security foundations: helper identity + API session isolation
**Goal.** Implement Specs 1 and 2 of the five-spec arc: route-helper pair-membership identity check + daemon SO_PEERCRED plumbing (Spec 1) and per-caller API session ownership + guest version compatibility infrastructure (Spec 2). Together they make a dedicated `sandbox` system user safe at both the helper-authorization and API layers. Terminal milestone for Spec 1 and Spec 2; ends with a multi-track review (S6) and dual claim-to-code verification (S7). Specs 3–5 follow in M14–M16.
**Status.** completed · **Sessions.** 7 · **Details.** [milestones/M13.md](milestones/M13.md)

## M14 — Daemon productionization
**Goal.** Implement Spec 3 of the five-spec arc: hardened daemon startup (state-dir mode enforcement, `sessions.db` chmod), version-pinned gateway image references, QEMU wrapper cleaned of its rootless-Docker branch, the `/version` endpoint, strict CLI ↔ daemon version equality on every connect, the `sandbox doctor` diagnostic subcommand, and `GET /diagnostics`. Ships `sandboxd/contrib/systemd/sandboxd.service` as a source artifact for Spec 4 to install. Terminal milestone for Spec 3.
**Status.** completed · **Sessions.** 5 · **Details.** [milestones/M14.md](milestones/M14.md)

## M15 — Release & install infrastructure
**Goal.** Implement Spec 4 of the five-spec arc: GitHub Actions release pipeline (tagged builds, cosign/sigstore attestations, multi-arch tarballs, MANIFEST), `install.sh` + `uninstall.sh` curl|bash scripts hosted on GitHub Pages, and the Lima-based E2E harness that exercises them on real Linux distros. Closes the `integration_systemd_unit_smokes` coverage gap from M14. Terminal milestone for Spec 4.
**Status.** completed · **Sessions.** 5 · **Details.** [milestones/M15.md](milestones/M15.md)

## M16 — Update infrastructure
**Goal.** Implement Spec 5 — the terminal spec of the five-spec arc: `sandbox update` CLI subcommand (30-step pre-flight + stateful orchestration), config migration framework (`ConfigMigration` trait, V001 adapter, apply loop, atomic write), lock file with sticky `was_running`, backup mechanics with 2-set retention, daemon-side `_schema_version` mismatch refusal, and the Lima E2E harness extension that proves the full update cycle. Terminal milestone for Spec 5 and the entire five-spec arc; M16-S5 verifies Spec 5 plus every arc-level forward constraint from Specs 1–4. M16-S6 added post-S5 to close the Spec 2 § 3.8.1 production gap (`docker cp` on `--read-only` lite containers) by switching container-side guest delivery to a host-staged bind-mount. M16-S7/S8/S9 split the remaining post-arc fix-up backlog by theme — code, tests, docs — each absorbing the matching subset of the M16-S4 MAY-FIX triage plan. M16-S10 stood up the Lima multi-uid harness for the peercred + isolation tests (and unblocked an M16-S6 sandbox-guest install-path regression in the process). M16-S11 and M16-S12 split the local Sigstore stack work — S11 hand-rolled the docker-compose stack with OIDC impersonation (after `sigstore/scaffolding` turned out to be Kubernetes-only), S12 wired it into install-e2e so install.sh and `sandbox update` exercise the real `cosign verify-blob` path against the local trust chain. M16-S13..S17 clear the remaining deferred-todo backlog by theme: S13 bundles three real correctness/security fixes (rollback WAL/SHM, drop daemon-staging vestige, feature-gate test env vars); S14 fixes the cross-operator peercred bug that surfaced during S10; S15 hardens test infrastructure (test-group filters, persistent Rekor signer, Python prefix sweep); S16 closes coverage gaps and triage bookkeeping; S17 is the final thorough documentation review. M16-S18 is the final flush of the post-arc deferred-todo backlog (nine kept items after 1-by-1 triage: `cargo fmt` sweep to unblock `make build`, install-e2e fixture cache-staleness consolidation under always-rebuild plus its dependent Sigstore-stack tear-out, `install.sh` test-env-var leak strip, snake_case wire-format unit-test pin, post-S14 keep-alive regression test, conftest text-mode hazard option, stale `Command::Doctor` rustdoc, and a broken lite-mode docs URL); after S18 zero deferred todos remain. M16-S19 is the full e2e matrix run (`make test-e2e-matrix`) — verification-only session that exercises the full session-lifecycle and cross-backend surface that the narrower per-session harnesses miss. M16-S20 is the milestone-closing full install-e2e suite run across every parametrised distro, with a cold-start `docker compose down -v` cycle to confirm S18's always-rebuild reshape behaves correctly under a fresh Sigstore stack; together S19 + S20 form the M16 close-out verification. M16-S21 is a post-arc cleanup wave folded into M16 at the user's request — five small surgical fixes to deferred todos that surfaced during S18..S20 close-out (two stale published URLs unblocked by the now-known `https://Koriit.github.io/sandboxd/` origin, plus three e2e harness durability fixes: gateway-image preflight tag mismatch, `--durations=20` Makefile flag, and a durable users.conf schema-version bridge).
**Status.** in_progress (S20 done, S21 final cleanup wave) · **Sessions.** 21 · **Details.** [milestones/M16.md](milestones/M16.md)

## M17 — Workspace ergonomics
**Goal.** Four workspace changes under one umbrella, all delivered against the 2026-05-20 spec (which supersedes the narrower 2026-05-14 9p-securityModel spec): (1) make the 9p `securityModel` of `shared:` selectable per session — default `mapped-xattr`, opt-in `none` for real-symlink interop both directions; `passthrough` / `mapped-file` deliberately not exposed; (2) make the `shared:` guest path configurable with a breaking default of *preserving the host path* inside the guest (so build artefacts referring to the working directory survive a host↔guest round-trip) — pre-0.1.0 breaking-default change accepted; (3) add a new `local:` workspace mode — rsync-based host-snapshot at session create plus operator-driven `sandbox workspace push` / `pull` (`-f`/`-n` safety gate, `--safe-links`, `--no-gitignore`), no 9p or bind-mount surface, no live host writes; (4) add a workspace-lock subsystem — daemon in-memory per-session lock that serialises push/pull and atomically state-gates workspace ops at acquire time, refuses `sandbox stop` / `sandbox delete` against a session with an active workspace op, and surfaces a `sandbox workspace unlock --force` recovery path for orphan locks left by a crashed CLI. The expansion also restructures `SessionConfigDto` with a `workspace_mode_detail` field (DTO separation per the project convention) and renames `WorkspaceSecurityModel::None` to `NoneMapping` to remove the `Option::None` collision. CLI grammar grows to `shared:<host>[:<guest>][:<model>]`, `local:<host>[:<guest>]`, and a new `sandbox workspace unlock <session> [--force]` subcommand. M17-S1 ships the `shared:` parser + guest-path + securityModel + breaking default + DTO scaffold; M17-S2 ships `local:` mode core (variant, parser, daemon-side rsync orchestration at create, describe rendering, capability advertisement) on both backends with integration + create-side E2E; M17-S3 ships the push/pull CLI together with the workspace-lock subsystem they consume (acquire/release/force endpoints, lifecycle interaction with stop/delete, `unlock --force` CLI, orphan-lock recovery, lock unit + integration + E2E); M17-S4 is the six-track review across S1+S2+S3; M17-S5 is the spec-delivery verification. Terminal milestone for the 2026-05-20 spec.
**Status.** not_started · **Sessions.** 5 · **Details.** [milestones/M17.md](milestones/M17.md)

## M18 — Cross-user CLI access
**Goal.** Implement the 2026-05-24 cross-user CLI access spec: fix the six CLI commands (`sandbox ssh`, `cp`, `sync`, `workspace push`, `workspace pull`, and transitively `git-remote-sandbox`) that break when the daemon runs as the `sandbox` system user but the CLI is invoked by an unprivileged operator. The fix adopts the daemon-mediated approach used by Docker/libvirt/LXD/Kubernetes/systemd-machined: every cross-session operation tunnels through a new `GET /sessions/{id}/proxy` WebSocket endpoint via `ProxyCommand`, and the daemon distributes a per-session SSH config block via a new `GET /sessions/{id}/ssh-config` endpoint that the CLI persists under `~/.ssh/sandbox/` with an `Include` line inserted at the very top of `~/.ssh/config` between marker comments. Both backends unify on sshd by baking openssh-server into the lite-image (and renaming the in-container guest user from `agent` to `sandbox` so the SSH-config template's `User sandbox` line works without per-backend branching). M18-S1 reshapes the e2e harness to launch sandboxd via its existing systemd unit (or `sudo -u sandbox sandboxd` where systemd is unavailable) and lands the three Phase-1 acceptance tests (Lima ssh, Lima `git-remote-sandbox`, container ssh) so the bug is reproducible in CI before any production code change; M18-S2 bakes sshd into the lite-image and lands the guest-user rename; M18-S3 ships the `V007__add_ssh_keypair.sql` forward-only migration, per-session ed25519 keypair generation on container create, tmpfs `/run/sandbox/authorized_keys` injection, and the `GET /sessions/{id}/ssh-config` endpoint returning `SshConfigDto { config, private_key }` with `404 SSH_NOT_AVAILABLE` for pre-migration container sessions; M18-S4 ships the `GET /sessions/{id}/proxy` WebSocket byte mover with `tokio::io::copy_bidirectional` between the WebSocket and `tokio::net::TcpStream` (Lima) / `docker exec … socat` async-pipe child (container), with the deliberate `tokio::process::Command` carve-out from the project's `spawn_blocking` convention documented in inline code comments; M18-S5 ships the CLI `sandbox proxy <id>` hidden shim plus the persistent `~/.ssh/sandbox/` management module (flock + tempfile+rename atomic writes, marker-delimited `Include` block at the top of `~/.ssh/config`); M18-S6 rewrites the six broken CLI commands to use the `sandbox-<id>` alias and wires the single-retry drift-recovery path matched only at outermost CLI dispatch (never inside `sandbox proxy`, so `git-remote-sandbox`'s nested invocations cannot stack retries); M18-S7 wires the lifecycle hooks — `sandbox rm` cleanup of the per-session key + config block, `sandbox ls` opportunistic reconcile against the daemon's session list (full-list query only, silently skipped on unreachable daemon, `--no-reconcile` opt-out), and `sandbox proxy <id>` lazy-404 cleanup; M18-S8 is the six-track review across S1..S7 — six parallel subagents covering implementation-vs-spec, code quality, unit-test quality (with non-tautological-assertion focus and code-coverage-tooling setup), e2e-test quality (with non-tautological + coverage-gap focus), docs quality, and workarounds + deprecated patterns — followed by aggregation and fix-up; M18-S9 is the spec-delivery verification gate — full e2e matrix under the new harness, manual `git-remote-sandbox` and VS Code Remote-SSH sanity checks, claim-to-code map at `.tasks/specs/2026-05-24-cross-user-cli-access-design/2026-05-24-cross-user-cli-access-design-delivery.md` with a single conjunctive hard gate. Terminal milestone for the 2026-05-24 spec.
**Status.** not_started · **Sessions.** 9 · **Details.** [milestones/M18.md](milestones/M18.md)

---

## Future milestones

Separate tracks, not on the critical path. Tracked here for planning continuity; execution is deferred.

### F1 — macOS Support
**Goal.** socket_vmnet, Colima, macvlan.
**Status.** not_started · **Sessions.** 2 · **Details.** [milestones/F1.md](milestones/F1.md)

### F2 — Policy Persistence Hardening
**Goal.** Schema migration playbook, encryption at rest.
**Status.** not_started · **Sessions.** 2 · **Details.** [milestones/F2.md](milestones/F2.md)

