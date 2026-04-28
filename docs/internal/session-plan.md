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
**Goal.** Second `sandboxd` session backend (Docker container via `--lite`) behind a new backend abstraction; full UX parity with VM sessions, container-level isolation traded for fast session creation. M11-S7 added post-verification to clear residual quality items before merge to main.
**Status.** in_progress (S7 in flight: polish) · **Sessions.** 7 · **Details.** [milestones/M11.md](milestones/M11.md)

---

## Future milestones

Separate tracks, not on the critical path. Tracked here for planning continuity; execution is deferred.

### F1 — macOS Support
**Goal.** socket_vmnet, Colima, macvlan.
**Status.** not_started · **Sessions.** 2 · **Details.** [milestones/F1.md](milestones/F1.md)

### F2 — Policy Persistence Hardening
**Goal.** Schema migration playbook, encryption at rest.
**Status.** not_started · **Sessions.** 2 · **Details.** [milestones/F2.md](milestones/F2.md)

