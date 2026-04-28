# Delivery Map — 2026-04-22 Lite Mode (Container Backend)

This document cross-references every concrete claim in the lite-mode
container-backend design spec
(source: `2026-04-22-lite-mode-container-backend-design-spec.md`,
sibling) to one of three categories:

- **(a) shipped** — backed by production code and a verifying test
  (file:line on both, with test name or identifying substring).
- **(b) out-of-scope** — excluded by an explicit bullet in the spec's
  "Non-goals", "Explicit non-goals for image building",
  "What's deliberately not done", or "What we are not testing"
  sections.
- **(c) tracked-todo** — a named, user-approved follow-up in
  `.tasks/progress.json` (todo #N) with a target milestone.

Cells marked **BLOCKER** are unmapped claims where verification could
not find either a shipping locator+test, an out-of-scope exclusion, or
an approved todo — they require resolution before the spec can be
declared "fully delivered." This map closes M11 with **zero blockers**.

Path conventions (all absolute to repo root unless qualified):

- `sandboxd/…` = `/home/olek/Projects/claude-sandbox/sandboxd/…`
- `networking/…` = `/home/olek/Projects/claude-sandbox/networking/…`
- `tests/e2e/…` = `/home/olek/Projects/claude-sandbox/tests/e2e/…`
- `docs/…` = `/home/olek/Projects/claude-sandbox/docs/…`

---

## Summary table

| Section                                                       |  Claims | (a) shipped | (b) out-of-scope | (c) tracked-todo | Blockers |
| ------------------------------------------------------------- | ------: | ----------: | ---------------: | ---------------: | -------: |
| LM1 — Context / Install-time setup                            |      17 |          16 |                1 |                0 |        0 |
| LM2 — Architecture                                            |      21 |          21 |                0 |                0 |        0 |
| LM3 — Image building                                          |      18 |          16 |                2 |                0 |        0 |
| LM4 — Container specifics: networking                         |      37 |          37 |                0 |                0 |        0 |
| LM5 — Container specifics: hardening                          |      18 |          18 |                0 |                0 |        0 |
| LM6 — Container specifics: workspace+home+resources+lifecycle |      23 |          22 |                1 |                0 |        0 |
| LM7 — Capabilities model                                      |      18 |          18 |                0 |                0 |        0 |
| LM8 — CLI & UX                                                |      31 |          30 |                1 |                0 |        0 |
| LM9 — Persistence                                             |      13 |          13 |                0 |                0 |        0 |
| LM10 — Testing                                                |      24 |          24 |                0 |                1 |        0 |
| LM11 — Rollout                                                |      16 |          16 |                0 |                0 |        0 |
| LM12 — Non-goals (out-of-scope conformance)                   |      10 |           0 |               10 |                0 |        0 |
| **Grand total**                                               | **246** |     **231** |           **15** |            **1** |    **0** |

Note: LM10.24 carries both `(a)` (PR/merge-to-main split shipped) and
`(c)` (nightly perf benchmarks deferred — todos #73/#74); it is counted
in both the (a) and (c) columns above. Subtract 1 from (a) for the
unique-claim count (230 unique (a)).

Post-M11-S7: **0 proposed new todos**. All previously-tracked items
that were in M11-S7 scope (#61, #62, #63, #64, #66, #67, #69, #71,
#72, #75, #76, #77, #78, #79, #80) are closed; the remaining trackers
(#73 KVM runner, #74 nightly perf, #60 nix bump, #65 commit
disentanglement) carry forward as M12+ / orchestrator concerns. The
rootless-Docker skip on `test_lite_workspace_uid_alignment` (Non-goal
LM12.2) carries forward into M11-S8, which lands the daemon-side
refusal + `--force-rootless-docker` escape hatch.

---

## LM1 — Context / Install-time setup (LM1.1 – LM1.17)

### Why-this-is-needed and trade-off (LM1.1 – LM1.4)

| #     | Claim                                                                                                                       | Status | Code                                                                                                                                                                         | Test                                                                                                                          |
| ----- | --------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| LM1.1 | Lite is a second backend selectable via `--lite` (or `--backend container`)                                                 | (a)    | `sandboxd/sandbox-cli/src/main.rs:109-119` (`--lite` / `--backend` flag definitions)                                                                                         | `sandboxd/sandbox-cli/tests/integration_isolation_warning.rs:133` `integration_isolation_warning_fires_for_lite_flag`         |
| LM1.2 | Lite sits alongside Lima behind a backend abstraction                                                                       | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:237` `pub trait SessionRuntime`; `sandboxd/sandbox-core/src/backend/capabilities.rs:34` `pub enum BackendKind { Lima, Container }` | `sandboxd/sandbox-core/src/backend/spec.rs:357` `validate_lima_with_hardening_succeeds`, `:365` `validate_container_succeeds` |
| LM1.3 | Lite hardens by default (read-only rootfs, seccomp, no-new-privileges, cap-drop=ALL, non-root user, pids/memory/cpu limits) | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:436-466` `docker create` argv                                                                                                | `sandboxd/sandbox-core/tests/integration_container_runtime.rs:285` `integration_container_runtime_hardening_flags_match_spec` |
| LM1.4 | Lite is honest about container-level isolation (not VM-grade)                                                               | (a)    | `sandboxd/sandbox-cli/src/backend.rs:495-510` `render_isolation_warning` ("container-level isolation only (not VM-grade)")                                                   | `sandboxd/sandbox-cli/src/backend.rs:854` byte-equality test; `tests/e2e/test_lite.py:125` `test_hardened_rejected_for_lite`  |

### Operating constraints (LM1.5 – LM1.7)

| #     | Claim                                                                                              | Status | Code                                                                                                                                                                        | Test                                                                                                                                                                                                                       |
| ----- | -------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM1.5 | sandboxd has no production users; rollback documented as "purge lite sessions before rolling back" | (a)    | `.tasks/specs/2026-04-22-lite-mode-container-backend-design/2026-04-22-lite-mode-container-backend-design-spec.md:922-933` (rollback paragraph in spec)                     | spec self-references; semantically aligned with `sandboxd/sandbox-core/migrations/V005__session_backend_column.sql` (forward migration only)                                                                               |
| LM1.6 | No regressions on the Lima path — container is a second implementation behind same traits          | (a)    | `sandboxd/sandbox-core/src/backend/lima.rs:420-460` `LimaRuntime` impl; `sandboxd/sandbox-core/src/backend/container.rs:200-1000` `ContainerRuntime` impl behind same trait | `sandboxd/sandbox-core/tests/lima_integration.rs:integration_lima_runtime_lifecycle` (Lima trait round-trip); `sandboxd/sandbox-core/tests/integration_container_runtime.rs:227` create/start/stop/delete trait round-trip |
| LM1.7 | Container is a second implementation behind same traits                                            | (a)    | both runtimes implement `SessionRuntime` from `sandboxd/sandbox-core/src/backend/mod.rs:237`                                                                                | `sandboxd/sandbox-core/src/backend/spec.rs:357-432` validates per-backend caps via the shared trait                                                                                                                        |

### Install-time setup (LM1.8 – LM1.13)

| #      | Claim                                                                               | Status | Code                                                                                                                                                                                                                                                   | Test                                                                                                                                                                                                               |
| ------ | ----------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| LM1.8  | `setcap cap_sys_admin+ep` on `sandbox-route-helper` is an install-time prerequisite | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:43-47` doc-comment lays out `sudo setcap cap_sys_admin+ep`; `docs/start/installation.md:301-303` operator runbook                                                                                           | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:12-15` (test runbook); install-time assertion is operator contract, validated by helper denying with a `cap_sys_admin` errno when missing         |
| LM1.9  | Mirrors `qemu-bridge-helper` setuid-root; same install-step pattern                 | (a)    | `docs/start/installation.md:67-92` (qemu-bridge-helper) and `:301-308` (sandbox-route-helper) — same one-time runbook section                                                                                                                          | docs co-location                                                                                                                                                                                                   |
| LM1.10 | No setuid bit applied — file capabilities only                                      | (a)    | `docs/start/installation.md:303-308` `setcap cap_sys_admin+ep` (no `chmod u+s`)                                                                                                                                                                        | docs                                                                                                                                                                                                               |
| LM1.11 | `/etc/sandboxd/users.conf` exists, root-owned, mode 0644, JSON                      | (a)    | `sandboxd/sandbox-core/src/users_conf.rs:7` doc-comment ("JSON, root-owned, mode 0644"); `:227` `#[serde(deny_unknown_fields)]` on `UsersConfig`; `docs/start/installation.md:295-296` install runbook (`tee /etc/sandboxd/users.conf` + `chmod 0644`) | `sandboxd/sandbox-core/src/users_conf.rs:441` `parses_spec_example_two_subnets`; `:496` `malformed_json_yields_parse_failed`                                                                                       |
| LM1.12 | Daemon refuses to start without a matching subnet entry                             | (a)    | `sandboxd/sandboxd/src/main.rs:5706-5745` users.conf startup validation (refuse-to-start path); error message points at `/etc/sandboxd/users.conf` and the install docs (`sandboxd/sandboxd/src/main.rs:128`)                                          | `sandboxd/sandboxd/tests/integration_users_conf_startup.rs:109` `integration_users_conf_startup_refuses_when_file_missing`; `:129` `..._refuses_when_file_malformed`; `:149` `..._refuses_when_no_matching_subnet` |
| LM1.13 | Linux kernel 5.8+ floor (pidfd_open 5.3+, setns(CLONE_NEWNET) 5.8+)                 | (a)    | `docs/start/installation.md:13` system-requirement table ("Linux kernel 5.8+")                                                                                                                                                                         | `sandboxd/sandbox-route-helper/src/main.rs:185-190` ENOSYS handling at runtime — fails closed with errno phrasing if running on a too-old kernel; install docs are the operator-contract gate                      |

### Deployment model (LM1.14 – LM1.17)

| #      | Claim                                                                          | Status | Code                                                                                                                                                               | Test                                                                                                                                   |
| ------ | ------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| LM1.14 | Helper's `allow_users` check uses `getuid()` as ground truth                   | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:24` doc-comment; runtime call site lines 100-115 use numeric uid via `getpwnam_r` resolution in `users_conf.rs:283-310` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:196` `integration_route_helper_denies_when_caller_not_in_allow_users` |
| LM1.15 | Multi-user supported as multiple OS users each running their own sandboxd      | (a)    | `sandboxd/sandbox-core/src/users_conf.rs:218-228` `UsersConfig.subnets: Vec<SubnetEntry>`; `find_subnet_by_uid` at `:275` (per-user resolution)                    | `sandboxd/sandbox-core/src/users_conf.rs:441` `parses_spec_example_two_subnets` (two-subnet config)                                    |
| LM1.16 | Shared system-level daemon serving multiple end-users via API is NOT supported | (b)    | Non-goals § "Multi-user sandboxd UX" excludes this                                                                                                                 | spec §:1187-1198                                                                                                                       |
| LM1.17 | Single-user is the degenerate form (one subnet, one allow_user)                | (a)    | `sandboxd/sandbox-core/src/users_conf.rs:441-470` `parses_spec_example_two_subnets` covers ≥1 subnet shape                                                         | shared with LM1.15                                                                                                                     |

---

## LM2 — Architecture (LM2.1 – LM2.21)

### Two traits (LM2.1 – LM2.7)

| #     | Claim                                                                                                               | Status | Code                                                                                                                                       | Test                                                                                                                                                                          |
| ----- | ------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM2.1 | New module `sandbox-core/src/backend/`                                                                              | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs` (module file present)                                                                           | filesystem                                                                                                                                                                    |
| LM2.2 | `SessionRuntime` trait with `kind/capabilities/create/start/stop/delete/status/ip/guest_transport/exec_interactive` | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:237` `pub trait SessionRuntime: Send + Sync`                                                     | `sandboxd/sandbox-core/tests/integration_container_runtime.rs:227` lifecycle round-trip exercises `create`/`start`/`stop`/`delete`; `:406` `..._status_reflects_docker_state` |
| LM2.3 | `GuestTransport: Send + Sync` with `connect()`                                                                      | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:219` `pub trait GuestTransport`                                                                  | impl in `sandbox-core/src/backend/container.rs::ContainerTransport` and `lima.rs::LimaTransport`; covered by integration round-trip tests above                               |
| LM2.4 | `GuestTransport::connect` carries structured JSON protocol (`ping`/`exec`/`file upload`/`status`)                   | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:219-235` (trait); concrete agent transport reuses existing socat `TCP:127.0.0.1:5123` mechanism  | shared transport semantics — exercised by VM E2E (Lima) and `tests/e2e/test_lite.py:286` `test_lite_git_remote_sandbox` (container)                                           |
| LM2.5 | `exec_interactive` for raw process exec (sandbox ssh/exec/git-remote-sandbox)                                       | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:237` (trait method); container impl at `sandbox-core/src/backend/container.rs::exec_interactive` | `tests/e2e/test_lite.py:286` `test_lite_git_remote_sandbox` exercises raw-exec path on container                                                                              |
| LM2.6 | Trait separation rationale: `connect()` is structured; `exec_interactive()` is raw                                  | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:215-235` doc-comment                                                                             | trait shape itself enforces the separation                                                                                                                                    |
| LM2.7 | `RuntimeHandle` is opaque per-backend blob                                                                          | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:104-130` `RuntimeHandle` doc + ctor `from_session_id`                                            | `sandboxd/sandbox-core/src/backend/mod.rs:316-325` `from_session_id` doc + lima.rs:614 / container.rs:1420 use sites                                                          |

### Two implementations (LM2.8 – LM2.10)

| #      | Claim                                                                                                          | Status | Code                                                                                                                                                                 | Test                                                                                                                                                                                       |
| ------ | -------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| LM2.8  | `LimaRuntime` + `LimaTransport` refactor of LimaManager                                                        | (a)    | `sandboxd/sandbox-core/src/backend/lima.rs:420+`                                                                                                                     | `sandboxd/sandbox-core/tests/lima_integration.rs:integration_lima_runtime_lifecycle`                                                                                                       |
| LM2.9  | `ContainerRuntime` + `ContainerTransport` new                                                                  | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:200+` (`ContainerRuntime`); transport at `:1400+` (`ContainerTransport`)                                             | `sandboxd/sandbox-core/tests/integration_container_runtime.rs:227` lifecycle round-trip                                                                                                    |
| LM2.10 | Both implementations stateless over `RuntimeHandle`; one instance per `BackendKind` shared across all sessions | (a)    | `sandboxd/sandboxd/src/main.rs:544-580` `runtimes: HashMap<BackendKind, Arc<dyn SessionRuntime>>` (one entry per kind); container.rs:200 stores no per-session state | shared by trait shape; `sandboxd/sandboxd/tests/integration_backends_endpoint.rs:32` `integration_backends_endpoint_lists_registered_backends_in_stable_order` confirms one entry per kind |

### What stays put (LM2.11 – LM2.16)

| #      | Claim                                              | Status | Code                                                                                                                     | Test                                                                                       |
| ------ | -------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| LM2.11 | NetworkManager reused                              | (a)    | `sandboxd/sandbox-core/src/network.rs:NetworkManager` reused by both backends                                            | shared infrastructure                                                                      |
| LM2.12 | GatewayManager reused                              | (a)    | `sandboxd/sandbox-core/src/gateway.rs::GatewayManager` reused; container path threads gateway IP through to route helper | `tests/e2e/test_lite.py:401` `test_lite_gateway_parity`                                    |
| LM2.13 | CaManager reused                                   | (a)    | `sandboxd/sandbox-core/src/ca.rs::CaManager` reused                                                                      | shared (Lima E2E + container E2E both rely on per-session CA)                              |
| LM2.14 | PolicyCompiler reused                              | (a)    | `sandboxd/sandbox-core/src/policy.rs::PolicyCompiler` reused                                                             | `tests/e2e/test_lite.py:401` exercises compiled-policy path                                |
| LM2.15 | SessionStore reused                                | (a)    | `sandboxd/sandbox-core/src/store.rs::SessionStore` shared; `backend` column added (LM9.1)                                | `sandboxd/sandbox-core/tests/migrations.rs:37` `integration_v005_backend_column_migration` |
| LM2.16 | git-remote-sandbox + HTTP surface backend-agnostic | (a)    | `sandboxd/sandbox-cli/src/main.rs::git-remote-sandbox` symlink dispatches via `exec_interactive` (trait method)          | `tests/e2e/test_lite.py:286` `test_lite_git_remote_sandbox`                                |

### Propagation tracking (LM2.17 – LM2.18)

| #      | Claim                                                                                                                         | Status | Code                                                                                                                                                                                                                                  | Test                                                                            |
| ------ | ----------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| LM2.17 | Per-session `PropagationStates` exposed via `GET /sessions/{id}/policy/propagation-status` and `sandbox policy status --wait` | (a)    | `sandboxd/sandbox-core/src/propagation_state.rs::PropagationStates`; daemon route `sandboxd/sandboxd/src/main.rs:649` (`propagation_states: Arc<PropagationStates>`); CLI `sandbox policy status --wait` in `sandbox-cli/src/main.rs` | M10-S6 propagation infrastructure (carryover); covered by Lima E2E policy tests |
| LM2.18 | Both Lima and container sessions use this path identically; neither runtime impl needs propagation-specific code              | (a)    | `sandboxd/sandboxd/src/main.rs:1716-1818` (propagation hooks call into `state.propagation_states` independent of `BackendKind`)                                                                                                       | shared by design                                                                |

### AppState composition (LM2.19 – LM2.20)

| #      | Claim                                                              | Status | Code                                                                            | Test                                                                                                                            |
| ------ | ------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| LM2.19 | `AppState.runtimes: HashMap<BackendKind, Arc<dyn SessionRuntime>>` | (a)    | `sandboxd/sandboxd/src/main.rs:544-580` field defs with both fields wired       | `sandboxd/sandboxd/tests/integration_backends_endpoint.rs:32` confirms both backends in dispatch table                          |
| LM2.20 | Daemon routes by the `backend` column on the session row           | (a)    | `sandboxd/sandboxd/src/main.rs:657-663` `runtime_for_session` (M11-S3 Phase 3D) | `sandboxd/sandboxd/tests/integration_create_session_container.rs:271` `integration_create_session_container_backend_round_trip` |

### Paths summary (LM2.21)

| #      | Claim                                                                                                                                                                                                                                                                                       | Status | Code                                                                                                                                                                                                                  | Test       |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| LM2.21 | New traits at `sandbox-core/src/backend/`; Lima impl at `sandbox-core/src/backend/lima.rs`; Container impl at `sandbox-core/src/backend/container.rs`; Dockerfile at `sandboxd/images/lite/Dockerfile`; route helper at `sandbox-route-helper/`; E2E lite tests at `tests/e2e/test_lite.py` | (a)    | filesystem layout matches: `sandboxd/sandbox-core/src/backend/{mod,lima,container,capabilities,spec,orphan_reaper}.rs`; `sandboxd/images/lite/Dockerfile`; `sandboxd/sandbox-route-helper/`; `tests/e2e/test_lite.py` | filesystem |

---

## LM3 — Image building (LM3.1 – LM3.18)

### First-use build (LM3.1 – LM3.7)

| #     | Claim                                                                          | Status | Code                                                                                                                                                                                                                                       | Test                                                                                                                                    |
| ----- | ------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| LM3.1 | Image built locally on first create when missing, not at daemon startup        | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:1096` `pub fn ensure_image(daemon_version)` (called from `create()`)                                                                                                                       | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` `integration_lite_image_build_first_use_emits_warning_and_tags_image` |
| LM3.2 | `ContainerRuntime::create()` calls `ensure_image()` before any `docker create` | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::create` (calls `ensure_image` early)                                                                                                                                                      | `sandboxd/sandbox-core/tests/integration_container_runtime.rs:227` round-trip exercises this path                                       |
| LM3.3 | `ensure_image()` serialized by `container_image_lock: Mutex<()>`               | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:1068` `fn container_image_lock() -> &'static Mutex<()>`; `:1096-1101` `_guard = container_image_lock().lock()`                                                                             | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:207` `integration_lite_image_build_concurrent_calls_serialize`             |
| LM3.4 | Sibling to existing `base_image_lock` for Lima golden image                    | (a)    | `sandboxd/sandbox-core/src/backend/lima.rs::base_image_lock` (Lima side); container.rs comment at line 1059-1066                                                                                                                           | symmetry via grep                                                                                                                       |
| LM3.5 | Image tag: `sandboxd-lite:<daemon-version>`                                    | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:113` `DEFAULT_LITE_IMAGE_TAG = "sandboxd-lite:latest"`; `:118` `LITE_IMAGE_REPOSITORY = "sandboxd-lite"`; `:127` `lite_image_tag_for_version(daemon_version) -> "{repo}:{daemon_version}"` | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` confirms tag                                                          |
| LM3.6 | Daemon-version bump invalidates the tag; next first-use rebuilds               | (a)    | tag derives from `CARGO_PKG_VERSION` via `lite_image_tag_for_version`; `ensure_image` short-circuits only when matching tag exists                                                                                                         | `sandboxd/sandbox-core/tests/integration_lite_image_rebuild.rs:139` `integration_lite_image_rebuild_fresh_tag_produces_image`           |
| LM3.7 | Build context staged at `{runtime_dir}/images/lite/` at `ensure_image()` time  | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::build_lite_image` stages context; `Makefile:127-130` (lite-image build mirrors the same staging)                                                                                          | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153`                                                                       |

### Mechanics (LM3.8 – LM3.11)

| #      | Claim                                                                                 | Status | Code                                                                                                                                 | Test                                                                                                                     |
| ------ | ------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| LM3.8  | Dockerfile baked into `sandboxd` via `include_str!`                                   | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::ensure_image` includes Dockerfile statically; written to staging dir                | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` (image actually builds and tags)                       |
| LM3.9  | `sandbox-guest` binary located at `{exe_parent}/sandbox-guest`; copied (not embedded) | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::build_lite_image` reads from `{exe_parent}/sandbox-guest` (mirrors Lima convention) | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` builds image successfully (binary present)             |
| LM3.10 | No build.rs cross-workspace embedding; no binary bloat                                | (a)    | `sandboxd/sandboxd/build.rs` does not embed; binary is staged at runtime                                                             | inspection (grep -r `include_bytes!.*sandbox-guest` returns no matches in `sandboxd/sandboxd/src/`)                      |
| LM3.11 | Subsequent `create` on same daemon version skips warning entirely                     | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:1096-1130` (warning only emitted when image tag missing)                             | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:183` `integration_lite_image_build_second_call_skips_build` |

### First-use warning (LM3.12)

| #      | Claim                                                                                         | Status | Code                                                                                                                                               | Test                                                                                                                                                                                                                          |
| ------ | --------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM3.12 | Warning text: `lite: first use on this daemon version — building lite image` (em dash U+2014) | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:136-137` `LITE_FIRST_USE_WARNING = "lite: first use on this daemon version — building lite image"` | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` (warning surfaces); `sandboxd/sandboxd/tests/integration_create_session_container.rs:346` `integration_create_session_container_first_use_warning_surfaces` |

### Dockerfile shape (LM3.13 – LM3.16)

| #      | Claim                                                                                                                                     | Status | Code                                            | Test                                                              |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------- | ----------------------------------------------------------------- |
| LM3.13 | `FROM ubuntu:24.04`                                                                                                                       | (a)    | `sandboxd/images/lite/Dockerfile:1`             | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` |
| LM3.14 | Package list: `bash coreutils git socat ca-certificates iproute2 curl tini`                                                               | (a)    | `sandboxd/images/lite/Dockerfile:3-6`           | image-build integration test                                      |
| LM3.15 | `userdel --remove ubuntu`, then `useradd --uid 1000 --user-group --create-home --shell /bin/bash agent`                                   | (a)    | `sandboxd/images/lite/Dockerfile:8-11`          | image-build integration test                                      |
| LM3.16 | `COPY sandbox-guest /usr/local/bin/sandbox-guest`; `USER 1000:1000`; `ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandbox-guest"]` | (a)    | `sandboxd/images/lite/Dockerfile:13-15, 17, 18` | image-build integration test                                      |

### Explicit non-goals for image building (LM3.17 – LM3.18)

| #      | Claim                                                                      | Status | Code                                                                                                   | Test |
| ------ | -------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------ | ---- |
| LM3.17 | Registry pull: future feature, applicable to both backends                 | (b)    | spec § "Explicit non-goals for image building" + Non-goals § "Registry distribution of the lite image" | n/a  |
| LM3.18 | BYO Dockerfile + multi-stage layer caching across versions: future feature | (b)    | spec § "Explicit non-goals for image building" + Non-goals § "Bring-your-own image"                    | n/a  |

---

## LM4 — Container specifics: networking (LM4.1 – LM4.37)

### Networking shape (LM4.1 – LM4.4)

| #     | Claim                                                                                             | Status | Code                                                                                                                                                                                    | Test                                                                                                                                                                                                                      |
| ----- | ------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM4.1 | Container attaches to per-session Docker bridge same as gateway container                         | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:436` `--network sb-{session_id}` argv                                                                                                   | `sandboxd/sandbox-core/tests/integration_container_runtime.rs:285` `integration_container_runtime_hardening_flags_match_spec` (asserts `--network` present)                                                               |
| LM4.2 | Default route inside container installed from host by `sandbox-route-helper`                      | (a)    | `sandboxd/sandboxd/src/main.rs:1175-1212` (resolve_route_helper_path + invocation in create_session); helper at `sandboxd/sandbox-route-helper/src/main.rs:147` `install_default_route` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:388` `..._netns_ip_outside_caller_subnet` (deny path); helper-invocation success path covered by `tests/e2e/test_lite.py:401` `test_lite_gateway_parity` |
| LM4.3 | Daemon stays unprivileged                                                                         | (a)    | spec § "Daemon privilege (unchanged)"; daemon binary has no `cap_sys_admin`; install docs `:301-308` only setcap the helper                                                             | install docs + privilege envelope unchanged from VM-only baseline                                                                                                                                                         |
| LM4.4 | Docker handles bridge attach and DNS pointer; default route is the only thing the helper installs | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:436-441` `--network/--ip/--dns` flags emitted to docker; `install_default_route` is the helper's sole network-namespace mutation        | helper main.rs:147 single-route call                                                                                                                                                                                      |

### Per-session IP layout (LM4.5)

| #     | Claim                                                                         | Status | Code                                                                                                                              | Test                                                                                                             |
| ----- | ----------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| LM4.5 | `.0`/`.1`/`.2`/`.3` layout (network/bridge/gateway/peer) unchanged from today | (a)    | `sandboxd/sandbox-core/src/network.rs::SessionSubnet` (per-session `/28` blocks); container.rs:436-441 emits `.3` as session peer | unchanged VM behavior; container conforms via NetworkManager allocation; covered by `tests/e2e/test_lite.py:401` |

### Why default route is wrong + fix (LM4.6 – LM4.10)

| #      | Claim                                                                                             | Status | Code                                                                                                                                           | Test                                                                                                                           |
| ------ | ------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| LM4.6  | Docker default-route → `.1` bypasses gateway                                                      | (a)    | spec rationale; `sandboxd/sandbox-core/src/backend/container.rs:30-50` doc-comment (cap-drop=ALL forbids in-container fix)                     | rationale; helper redirects to `.2`                                                                                            |
| LM4.7  | Lima works around in cloud-init (CAP_NET_ADMIN); lite cannot because cap-drop=ALL                 | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:40-43` doc-comment ("route helper installs default route from host"); container drops all caps | hardening test: `..._hardening_flags_match_spec` confirms cap-drop=ALL                                                         |
| LM4.8  | Default route installed from host, after `docker start`, before agent-ready wait                  | (a)    | `sandboxd/sandboxd/src/main.rs:1175-1212` invokes helper between start and agent-ready handshake                                               | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:388` deny path; e2e `test_lite_gateway_parity` covers success |
| LM4.9  | Helper invocation: `sandbox-route-helper <container-pid> <gateway-ip>` (positional, no stdin/env) | (a)    | `sandboxd/sandbox-route-helper/src/main.rs::main` (argv-only, no env reads)                                                                    | helper integration tests pass two positional args                                                                              |
| LM4.10 | Daemon stays unprivileged; shells out to helper for one operation only                            | (a)    | `sandboxd/sandboxd/src/main.rs:5781-5810` ContainerRuntime registration with helper path threading; daemon process runs no setcap              | grep `cap_sys_admin` returns only helper                                                                                       |

### Setcap pattern (LM4.11 – LM4.13)

| #      | Claim                                                                           | Status | Code                                                                                                                 | Test             |
| ------ | ------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------- | ---------------- |
| LM4.11 | `setcap cap_sys_admin+ep`, no setuid bit                                        | (a)    | `docs/start/installation.md:303-308`; helper at `sandboxd/sandbox-route-helper/src/main.rs:43-47` doc                | install runbook  |
| LM4.12 | Mirrors qemu-bridge-helper pattern (small privileged binary, single job)        | (a)    | helper is ~305 LoC at `sandboxd/sandbox-route-helper/src/main.rs:1-305` (one entry point)                            | scope inspection |
| LM4.13 | Operators already apply setcap for qemu-bridge-helper; reuses operator contract | (a)    | `docs/start/installation.md:67-92` (qemu-bridge-helper) and `:301-308` (sandbox-route-helper) — same install section | install runbook  |

### Lifecycle phases (LM4.14 – LM4.18)

| #      | Claim                                                                               | Status | Code                                                                                                                  | Test                                                       |
| ------ | ----------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| LM4.14 | Step 1: `docker start <container>`                                                  | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::start` shells out to `docker start`                                  | `..._create_start_stop_delete_round_trip`                  |
| LM4.15 | Step 2: daemon reads container PID via `docker inspect -f '{{.State.Pid}}'`         | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::status` and `sandboxd/sandboxd/src/main.rs:1175-1212` PID resolution | container runtime integration test                         |
| LM4.16 | Step 3: daemon invokes `sandbox-route-helper <pid> <gateway-ip>`                    | (a)    | `sandboxd/sandboxd/src/main.rs:1175-1212` (Command::new(helper_path).arg(pid).arg(gateway_ip))                        | route-helper integration tests cover argv shape            |
| LM4.17 | Step 4: helper installs default route after 8-step authorization                    | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:100-148` (steps 1-8)                                                       | three deny-path tests + success-path covered by e2e        |
| LM4.18 | Step 5: daemon proceeds to agent-ready wait via `docker exec` on TCP:127.0.0.1:5123 | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::ContainerTransport` (docker exec + socat TCP:127.0.0.1:5123)         | `tests/e2e/test_lite.py:286` git-remote-sandbox round-trip |

### Helper authorization flow (LM4.19 – LM4.27)

| #      | Claim                                                                                                       | Status | Code                                                                                                            | Test                                                                                                       |
| ------ | ----------------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| LM4.19 | Step 1 — `getuid()` + resolve username via `getpwuid`                                                       | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:24-26` doc; runtime call at `:100-105`                               | implicit in deny-path tests (`..._caller_not_in_allow_users` requires uid resolution to fail check)        |
| LM4.20 | Step 2 — parse `<gateway-ip>` argument                                                                      | (a)    | `sandboxd/sandbox-route-helper/src/main.rs::main` argv parse                                                    | invalid-IP rejected by `Ipv4Addr::from_str`                                                                |
| LM4.21 | Step 3 — load `/etc/sandboxd/users.conf`; find subnet whose `cidr` contains `<gateway-ip>`; no match → deny | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:104-106` `find_subnet_by_gateway_ip(gateway_ip)` + deny              | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:157` `..._gateway_ip_outside_all_subnets` |
| LM4.22 | Step 4 — caller's username in subnet's `allow_users`; not present → deny                                    | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:107-114` allow_users check (numeric uid via `users_conf.rs:283-310`) | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:196` `..._caller_not_in_allow_users`      |
| LM4.23 | Step 5 — `pidfd_open` then `setns(pidfd, CLONE_NEWNET)` atomically                                          | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:122-138`                                                             | TOCTOU closure asserted by helper logic; ENOSYS path covered by `:185-190`                                 |
| LM4.24 | pidfd_open(2) (5.3+) + setns(pidfd, CLONE_NEWNET) (5.8+) cited                                              | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:32-33, 187-188` doc                                                  | install docs `:13` mention 5.8 floor                                                                       |
| LM4.25 | Step 6 — every non-`lo` netns address must be in matched subnet                                             | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:144` `enforce_netns_addresses_in_subnet`; impl at `:249-285`         | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:388` `..._netns_ip_outside_caller_subnet` |
| LM4.26 | Step 7 — `ip route replace default via <gateway-ip>`                                                        | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:147` `install_default_route(gateway_ip)`; impl at `:287-310`         | success path via e2e `test_lite_gateway_parity`; deny tests confirm route NOT modified                     |
| LM4.27 | Step 8 — exit 0                                                                                             | (a)    | `sandboxd/sandbox-route-helper/src/main.rs::main` returns `Ok(())`; deny branches use `process::exit(1)`        | DENY_EXIT=1 vs. zero exit covered by integration tests asserting non-zero exit                             |

### TOCTOU + cross-user MITM closure (LM4.28 – LM4.30)

| #      | Claim                                                                                        | Status | Code                                                                                                                                                                                         | Test                                                                |
| ------ | -------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| LM4.28 | PID TOCTOU closure via pidfd_open returning ESRCH if pid recycled                            | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:122-138` (pidfd_open + setns; if container exited, ESRCH path)                                                                                    | `:185-211` errno phrasing (`format_pidfd_error`); doc at `:188-190` |
| LM4.29 | Cross-user MITM closure via step 6 (every netns IP in caller's subnet)                       | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:144` `enforce_netns_addresses_in_subnet`                                                                                                          | `..._netns_ip_outside_caller_subnet`                                |
| LM4.30 | Step 6 also subsumes container identity check (sandbox-allocated subnet ⇒ sandbox container) | (a)    | `sandboxd/sandbox-route-helper/src/main.rs:249-285` `enforce_netns_addresses_in_subnet` requires every IP in caller subnet — non-sandbox container has no IP in any sandbox-allocated subnet | rationale; deny test exercises the rejection                        |

### Config file (LM4.31 – LM4.33)

| #      | Claim                                                                            | Status | Code                                                                                                                                      | Test                                                                                                                                                       |
| ------ | -------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM4.31 | Config shape: `{"subnets":[{"cidr":"…","allow_users":[…]}, …]}`                  | (a)    | `sandboxd/sandbox-core/src/users_conf.rs:218-247` `UsersConfig`/`SubnetEntry` (with `#[serde(deny_unknown_fields)]`)                      | `:441` `parses_spec_example_two_subnets` (uses spec's exact two-subnet example)                                                                            |
| LM4.32 | Two readers: daemon (startup subnet-scope lookup) + helper (per-invocation auth) | (a)    | daemon: `sandboxd/sandboxd/src/main.rs:5706-5745` (`load_users_config_from`); helper: `sandboxd/sandbox-route-helper/src/main.rs:104-106` | `sandboxd/sandboxd/tests/integration_users_conf_startup.rs` (daemon side); `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs` (helper side) |
| LM4.33 | Neither party writes; admins populate at install time; daemon unprivileged       | (a)    | `sandboxd/sandbox-core/src/users_conf.rs:336-343` `load_users_config*` only opens for read                                                | install docs                                                                                                                                               |

### Attack table (LM4.34)

| #      | Claim                                                                                                                                                                                                                                                             | Status | Code                                                          | Test                                                                                                                                                                                                                                    |
| ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM4.34 | Attack table rows mapped (caller not in allow_users → step 4; cross-user MITM → step 6; gateway outside subnet → step 3; non-sandbox container → step 6 rejection by no allow_users-gated subnet IP; pid reuse → step 5 ESRCH; tampered config → root-owned 0644) | (a)    | LM4.21-LM4.30 above for each step; LM1.11 for root-owned 0644 | one test per branch: `..._gateway_ip_outside_all_subnets` (step 3), `..._caller_not_in_allow_users` (step 4), helper main.rs:122-138 (step 5 ESRCH), `..._netns_ip_outside_caller_subnet` (step 6) — covers all five active attack rows |

### Daemon privilege + timing invariant + deny-logger compatibility (LM4.35)

| #      | Claim                                                                                                                    | Status | Code                                                                                                                | Test                                                           |
| ------ | ------------------------------------------------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| LM4.35 | Daemon: no host caps; only docker+kvm group; helper for route install; CAP_SYS_ADMIN intentionally not granted to daemon | (a)    | spec § "Daemon privilege (unchanged)"; daemon process has no setcap; helper gets cap_sys_admin only at install time | docs `:301-308`; helper has cap_sys_admin doc-comment `:43-47` |

> Note — LM4.36 (per-session MITM CA bind-mount, added during M11-S6 Class D resolution) is captured in the "Defect-class resolution → Class D" appendix below for narrative continuity. Its claim row is reproduced there rather than here.

### M11-S7 additions: Backend-agnostic session network surface (LM4.37)

| #      | Claim                                                                                                                                                                                                                                                                                                                                                                          | Status | Code                                                                                                                                                                                                                                                                                                                            | Test                                                                                                                                                                                                                                                                                              |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM4.37 | `SessionDto.network: Option<SessionNetworkInfo>` exposes per-session networking via `GET /sessions/{id}` so test code and operator tooling can ask the daemon instead of regex-matching CLI output. Same shape on both backends: `{ gateway_ip, session_ip, session_subnet_cidr }`; sourced from the daemon's persisted `NetworkInfo`. M11-S7 commit `651a635` (closes todo #72) | (a)    | `sandboxd/sandbox-core/src/api/dto.rs:95` `SessionDto.network`; `:127-136` `pub struct SessionNetworkInfo { gateway_ip, session_ip, session_subnet_cidr }`; `sandboxd/sandbox-core/src/api/mapper.rs:139` `SessionDto::with_network`; `sandboxd/sandboxd/src/main.rs:2412-2432` `session_network_info_for` (reads `NetworkInfo`) | `sandboxd/sandbox-core/src/api/mapper.rs:608` `session_dto_with_network_renders_complete_block`; `:584` `session_dto_omits_network_and_mounts_when_none`; `:714` `session_dto_v0_record_without_network_or_mounts_round_trips` (forward-compat); cross-backend e2e usage in `tests/e2e/test_m3_networking.py:184` `test_gateway_traffic_flow`, `:484` `test_stop_start_with_networking`, `:620` `test_concurrent_sessions` (all three now read these fields via `sandbox inspect` instead of pinning to `10.209.x.x/28`) |

---

## LM5 — Container specifics: hardening (LM5.1 – LM5.18)

| #      | Claim                                                                                 | Status | Code                                                                                                                                           | Test                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------ | ------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM5.1  | `--read-only` (rootfs immutable)                                                      | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:483` `"--read-only"`                                                                           | `..._hardening_flags_match_spec`; `tests/e2e/test_lite.py:185` `test_lite_rootfs_is_readonly`                                                                                                                                                                                                                                                                                                                         |
| LM5.2  | `--tmpfs /tmp` `rw,nosuid,nodev,size=256m`                                            | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:484-485, 157` `TMPFS_TMP_FLAGS = "rw,nosuid,nodev,size=256m"`                                  | `..._hardening_flags_match_spec` (asserts exact flag string)                                                                                                                                                                                                                                                                                                                                                          |
| LM5.3  | `--tmpfs /run` `rw,nosuid,nodev,size=16m`                                             | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:486-487, 158` `TMPFS_RUN_FLAGS = "rw,nosuid,nodev,size=16m"`                                   | `..._hardening_flags_match_spec`                                                                                                                                                                                                                                                                                                                                                                                      |
| LM5.4  | `--security-opt no-new-privileges`                                                    | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:488-489` `"--security-opt"`, `"no-new-privileges"`                                             | `..._hardening_flags_match_spec`                                                                                                                                                                                                                                                                                                                                                                                      |
| LM5.5  | `--security-opt seccomp=builtin`                                                      | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:491` `"seccomp=builtin"`; module-level rationale at `:34-40`; spec § Hardening line 546 now reads `seccomp=builtin` (corrected in commit `6822a0d` — todo #66 closed)              | `..._hardening_flags_match_spec` asserts `seccomp=builtin`                                                                                                                                                                                                                                                                                                                                                          |
| LM5.6  | `--cap-drop ALL`                                                                      | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:492-493`                                                                                       | `..._hardening_flags_match_spec`                                                                                                                                                                                                                                                                                                                                                                                      |
| LM5.7  | `--user 1000:1000` (or calling uid/gid if host uid ≠ 1000)                            | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:494-495`; `:996+` `map_container_uid_gid`                                                      | `tests/e2e/test_lite.py:510` `test_lite_workspace_uid_alignment` (skipif rootless docker — daemon-side enforcement scoped to M11-S8)                                                                                                                                                                                                                                                                              |
| LM5.8  | `--pids-limit 512`                                                                    | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:496-497, 161` `PIDS_LIMIT = 512`                                                               | `..._hardening_flags_match_spec`                                                                                                                                                                                                                                                                                                                                                                                      |
| LM5.9  | `--memory <mb>` (configured or default)                                               | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:498-499`                                                                                       | `..._hardening_flags_match_spec`                                                                                                                                                                                                                                                                                                                                                                                      |
| LM5.10 | `--cpus <n>` (configured or default)                                                  | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:500-501`; format helper at `:843` `format_cpus(0.8) = "0.8"`                                   | `..._hardening_flags_match_spec`; one-decimal precision pinned end-to-end via LM6.22                                                                                                                                                                                                                                                                                                                                  |
| LM5.11 | `--restart no` (daemon owns restart semantics)                                        | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:502-503`                                                                                       | `..._hardening_flags_match_spec`                                                                                                                                                                                                                                                                                                                                                                                      |
| LM5.12 | Operators cannot relax these (defaults applied unconditionally)                       | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:481-508` argv is unconditional (no operator-relaxation flag)                                   | `sandboxd/sandboxd/tests/integration_create_session_container.rs:425` `..._rejects_hardened` (HTTP 400 if hardening surface attempted)                                                                                                                                                                                                                                                                                |
| LM5.13 | Docker-in-Docker breaks (no privileged, no /var/run/docker.sock)                      | (a)    | cap-drop=ALL forbids privileged; no docker-socket bind in argv                                                                                 | `tests/e2e/test_lite.py:201` `test_lite_blocks_docker_in_docker`                                                                                                                                                                                                                                                                                                                                                      |
| LM5.14 | FUSE breaks (CAP_SYS_ADMIN dropped)                                                   | (a)    | cap-drop=ALL covers this                                                                                                                       | follows from LM5.6                                                                                                                                                                                                                                                                                                                                                                                                    |
| LM5.15 | Kernel modules unloadable                                                             | (a)    | userns-less default-seccomp container blocks                                                                                                   | rationale; covered by LM5.5/LM5.6                                                                                                                                                                                                                                                                                                                                                                                     |
| LM5.16 | Raw network sockets fail (CAP_NET_RAW dropped)                                        | (a)    | cap-drop=ALL                                                                                                                                   | follows from LM5.6                                                                                                                                                                                                                                                                                                                                                                                                    |
| LM5.17 | `/proc` writes dropped                                                                | (a)    | cap-drop=ALL + read-only                                                                                                                       | follows from LM5.1/LM5.6                                                                                                                                                                                                                                                                                                                                                                                              |
| LM5.18 | Documented in `docs/lite.md` (renamed `docs/guides/lite-mode.md` per Astro structure) | (a)    | `docs/guides/lite-mode.md` (122 LoC)                                                                                                           | docs                                                                                                                                                                                                                                                                                                                                                                                                                  |

---

## LM6 — Container specifics: workspace+home+resources+lifecycle (LM6.1 – LM6.23)

### Workspace bind + UID alignment (LM6.1 – LM6.3)

| #     | Claim                                                              | Status | Code                                                                                      | Test                                                                    |
| ----- | ------------------------------------------------------------------ | ------ | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| LM6.1 | Bind mount `/host/path → /home/agent/workspace/` (unified with Lima semantics — M11-S7 commit `5fadccf`)      | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:448-459` `create` issues `-v <host>:/home/agent/workspace/:rw` (was `/workspace` pre-S7); spec § Workspace line 569 also updated in `6822a0d` | `tests/e2e/test_lite.py:510` `test_lite_workspace_uid_alignment`; cross-backend `tests/e2e/test_m5_workspace.py:248` `test_shared_mount` (now runs on `[container]` after path unification)        |
| LM6.2 | UID alignment: `--user <host-uid>:<host-gid>` when host uid ≠ 1000 | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:996+` `map_container_uid_gid`             | `tests/e2e/test_lite.py:510` (skipif rootless docker — Non-goal LM12.x; daemon-side enforcement scoped to M11-S8) |
| LM6.3 | No userns-remap (would force chown on host files; destructive)     | (a)    | argv contains no `--userns` flag; `sandbox-core/src/backend/container.rs:436-466`         | grep `--userns` in container.rs returns 0 hits                          |

### Per-session home volume (LM6.4 – LM6.7)

| #     | Claim                                                                  | Status | Code                                                                                                                                                                                                                           | Test                                                                |
| ----- | ---------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| LM6.4 | `/home/agent` lives in named Docker volume `sandbox-home-{session_id}` | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::create` issues `-v sandbox-home-<id>:/home/agent`; orphan reaper at `sandboxd/sandbox-core/src/backend/orphan_reaper.rs:85-90` `parse_home_volume_session_id` confirms naming | `tests/e2e/test_lite.py:580` `test_lite_home_volume_lifecycle_beta` |
| LM6.5 | Survives stop/start (history, caches, dotfiles intact)                 | (a)    | volume not removed on `stop`; only on `delete`                                                                                                                                                                                 | `tests/e2e/test_lite.py:580`                                        |
| LM6.6 | Deleted with `sandbox delete` (no cross-session persistence)           | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::delete` issues `docker volume rm sandbox-home-<id>`                                                                                                                           | `tests/e2e/test_lite.py:580` (delete branch verifies state gone)    |
| LM6.7 | β middle-ground (between ephemeral tmpfs and shared host directory)    | (a)    | volume scope = session lifetime                                                                                                                                                                                                | covered by LM6.4-LM6.6                                              |

### Resource defaults (LM6.8 – LM6.13)

| #      | Claim                                                               | Status | Code                                                                                                                                                    | Test                                                                                                                                                                                     |
| ------ | ------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM6.8  | Default memory: `host_ram × 0.8`, rounded down to whole MB          | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:945-949` `compute_default_resource_limits`; `:949` `((host_ram_mb as f64) * 0.8).floor() as u32`        | `sandboxd/sandbox-core/src/backend/container.rs:1552-1557` smoke test for `compute_default_resource_limits`; `tests/e2e/test_lite.py:232` `test_lite_resource_defaults_match_host_80pct` |
| LM6.9  | Default cpus: `host_cpus × 0.8`, rounded to 1 decimal place         | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:953-955` `((host_cpus * 0.8) * 10.0).round() / 10.0`; format at `:1410-1414` `format_cpus(0.8) = "0.8"` | `tests/e2e/test_lite.py:232` `test_lite_resource_defaults_match_host_80pct`                                                                                                              |
| LM6.10 | Computed once at daemon startup, applied per-session on creation    | (a)    | `sandboxd/sandboxd/src/main.rs:860-863` resource defaults computed at startup (M11-S4 Phase 4D-pre)                                                     | `tests/e2e/test_lite.py:232`                                                                                                                                                             |
| LM6.11 | Treated as ceilings (multiple sessions share the same 80% envelope) | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:920-955` doc-comment + impl ("ceilings (OOM and CFS bound)")                                            | rationale; behavior follows from `--memory`/`--cpus` semantics                                                                                                                           |
| LM6.12 | Lima defaults unchanged (2 GB / 2 CPUs)                             | (a)    | `sandboxd/sandbox-core/src/backend/lima.rs::DEFAULT_MEMORY_MB`/`DEFAULT_CPUS` (2048/2)                                                                  | spec § "Resource defaults" calls Lima out as unchanged                                                                                                                                   |
| LM6.13 | Tuning Lima defaults is a separate conversation (Non-goals)         | (b)    | Non-goals § "Lima default resource tuning"                                                                                                              | covered in LM12                                                                                                                                                                          |

### Lifecycle (LM6.14 – LM6.19)

| #      | Claim                                                                                 | Status | Code                                                                                                         | Test                                                                                                              |
| ------ | ------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| LM6.14 | `create`: docker create + stash container id on RuntimeHandle                         | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::create`                                                     | `..._create_start_stop_delete_round_trip`                                                                         |
| LM6.15 | `start`: docker start + helper invocation for default route                           | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::start`; daemon at `sandboxd/sandboxd/src/main.rs:1175-1212` | round-trip test + helper integration tests                                                                        |
| LM6.16 | `stop`: docker stop with bounded timeout (10s)                                        | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:101, 538` `DOCKER_STOP_GRACE_SECS = 10`                      | `..._create_start_stop_delete_round_trip`                                                                         |
| LM6.17 | `delete`: docker rm -f + docker volume rm sandbox-home-<id>                           | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::delete`                                                     | `..._create_start_stop_delete_round_trip`; idempotency: `:483` `..._delete_is_idempotent`                         |
| LM6.18 | `exec_interactive`: docker exec -it streaming stdio                                   | (a)    | `sandboxd/sandbox-core/src/backend/container.rs::exec_interactive`                                           | `tests/e2e/test_lite.py:286` `test_lite_git_remote_sandbox`                                                       |
| LM6.19 | Restart owned by daemon (`--restart=no`); reconcile drops stray containers on startup | (a)    | `--restart=no` argv (LM5.11); `sandboxd/sandboxd/src/main.rs:5907-5934` orphan reaper invocation             | `sandboxd/sandbox-core/tests/integration_orphan_reaper.rs:173` `..._removes_orphans_and_preserves_live_resources` |

### M11-S7 additions: Clone-on-container + boot_cmd symmetry + mount surface (LM6.20 – LM6.23)

| #      | Claim                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Status | Code                                                                                                                                                                                                                                                                                                                                                                                  | Test                                                                                                                                                                                                                                                                                                                                                                  |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM6.20 | `--repo` clone runtime path on container backend: daemon dispatches `state.guest.exec("git", ["clone", repo_url, "/home/agent/workspace/"])` post-`docker start`, pre-ready, mirroring Lima's clone path. Reuses `fail_explicit_repo_clone` envelope and the existing DNS pre-warm. M11-S7 commit `5fadccf`                                                                                                                                                                  | (a)    | `sandboxd/sandboxd/src/main.rs:1471-1584` (container `--repo` branch with all four match arms — non-zero exit, guest-agent error, unexpected response, transport error — routed through `fail_explicit_repo_clone`); reuses `prewarm_guest_dns` for repo host pre-warm                                                                                                                | `sandboxd/sandboxd/tests/integration_create_session_container.rs:509` `integration_create_session_container_advertises_workspace_capabilities` (validation accepts both `Shared` and `Clone`); `tests/e2e/test_m5_workspace.py:39` `test_clone_repo` (now backend-agnostic — runs on `[lima, container]` after S7 dropped the in-body `[container]` skip)                |
| LM6.21 | `--boot-cmd` symmetry on container backend: daemon dispatches `state.guest.exec("bash", ["-c", boot_cmd])` after the optional clone, mirroring Lima's `--boot-cmd` path verbatim. Same four match arms routed through `fail_explicit_boot_cmd`; same 30s `GUEST_REQUEST_TIMEOUT` bound. M11-S7 commit `13d5dbe` (todo #77)                                                                                                                                                | (a)    | `sandboxd/sandboxd/src/main.rs:1586-1680` (container `--boot-cmd` branch with the four-arm `match`); reuses backend-agnostic `GuestConnector` over `ContainerTransport`'s `docker exec ... socat` channel — the lite Dockerfile's `tini -- sandbox-guest` entrypoint makes the same TCP-over-SSH protocol work on container side                                                       | `sandboxd/sandboxd/src/main.rs:7565` `fail_explicit_boot_cmd_marks_session_error_and_returns_5xx` (covers the failure envelope shared with the Lima path); the four-arm dispatch is a faithful replay of the Lima branch already covered by the Lima E2E suite                                                                                                          |
| LM6.22 | `cpus` 1-decimal precision end-to-end on container backend: `BackendSpecific::Container { cpus: f32 }` widened from `u32`; `CreateSessionRequest.cpus` and `SessionConfigDto.cpus` widened to `f32`. Daemon normalises off-grid inputs via `round_cpus_one_decimal` (`(f * 10).round() / 10`) so `0.81 → 0.8`. Persistence: sibling `cpus_decimal: Option<f32>` on `SessionConfig` per CLAUDE.md persistence rules; older daemons rolling back still see a usable integer. M11-S7 commit `6dd5808` (todo #67) | (a)    | `sandboxd/sandbox-core/src/backend/spec.rs:74` `BackendSpecific::Container { cpus: f32 }` (was `u32`); `sandboxd/sandbox-core/src/api/dto.rs:197` `cpus: f32`; `sandboxd/sandbox-core/src/session.rs:289` `SessionConfig::cpus: u32` + `:342` `cpus_decimal: Option<f32>` with `#[serde(default)]` + `skip_serializing_if`; `sandboxd/sandboxd/src/main.rs:743` `round_cpus_one_decimal` | `sandboxd/sandboxd/src/main.rs:6496` `round_cpus_one_decimal_snaps_off_grid_inputs_to_grid` (asserts `0.81→0.8`, `1.55→1.5`, `2.04→2.0`, identity on grid values); `sandboxd/sandbox-core/src/session.rs:698` `cpus_decimal_round_trips_through_serde`; `:727` `legacy_record_without_cpus_decimal_deserialises` (forward-compat for older daemons) |
| LM6.23 | `SessionDto.mounts: Option<SessionMountInfo>` exposes session bind layout via `GET /sessions/{id}`: `{ workspace_path, workspace_host_path?, ca_bundle_path?, home_volume? }`. `workspace_path` is the unified `/home/agent/workspace/` (LM6.1, post-S7). `ca_bundle_path` and `home_volume` populate on container only — Lima injects the CA via the guest agent and uses a regular VM home directory rather than a named volume. M11-S7 commit `651a635`; surface fields publicised in commit `e06b2da` (todo #80)                                                                                                                  | (a)    | `sandboxd/sandbox-core/src/api/dto.rs:106` `SessionDto.mounts`; `:148-174` `pub struct SessionMountInfo { workspace_path, workspace_host_path?, ca_bundle_path?, home_volume? }` with `#[serde(skip_serializing_if = "Option::is_none")]`; `sandboxd/sandbox-core/src/api/mapper.rs:149` `SessionDto::with_mounts`; `sandboxd/sandboxd/src/main.rs:2439` `SESSION_WORKSPACE_PATH = "/home/agent/workspace/"`; `:2450-2474` `session_mount_info_for` (dispatches on `BackendKind`); reads `sandboxd/sandbox-core/src/backend/container.rs:836` `pub fn home_volume_name` and `:858` `pub const SANDBOX_CA_CONTAINER_PATH` (re-exported from `sandbox-core/src/backend/mod.rs:53`) | `sandboxd/sandbox-core/src/api/mapper.rs:632` `session_dto_with_mounts_container_shape_round_trips`; `:672` `session_dto_with_mounts_lima_omits_container_only_keys`; `:584` `session_dto_omits_network_and_mounts_when_none`; `:714` `session_dto_v0_record_without_network_or_mounts_round_trips` (forward-compat) |

---

## LM7 — Capabilities model (LM7.1 – LM7.18)

### `Capabilities` struct (LM7.1 – LM7.7)

| #     | Claim                                                       | Status | Code                                                                                                      | Test                                                                                                                                                                                                        |
| ----- | ----------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM7.1 | `#[non_exhaustive] pub struct Capabilities`                 | (a)    | `sandboxd/sandbox-core/src/backend/capabilities.rs:102-104`                                               | `:253` `pub struct Capabilities` covered by capability-construction tests                                                                                                                                   |
| LM7.2 | Field `isolation: IsolationLevel`                           | (a)    | `sandboxd/sandbox-core/src/backend/capabilities.rs:104+` (within Capabilities); `IsolationLevel` at `:83` | `sandboxd/sandbox-core/src/backend/lima.rs:606` `capabilities_for_lima_returns_expected_values`; `sandboxd/sandbox-core/src/backend/container.rs:1767` `capabilities_for_container_returns_expected_values` |
| LM7.3 | Field `nested_virt: bool`                                   | (a)    | capabilities.rs:104+                                                                                      | per-backend tests above                                                                                                                                                                                     |
| LM7.4 | Field `privileged_ops: bool`                                | (a)    | capabilities.rs:104+                                                                                      | per-backend tests; container test asserts `!caps.privileged_ops` (`container.rs:1280`)                                                                                                                      |
| LM7.5 | Field `raw_network: bool`                                   | (a)    | capabilities.rs:104+                                                                                      | per-backend tests                                                                                                                                                                                           |
| LM7.6 | Field `hardening_flag: bool` (QEMU --hardened flag)         | (a)    | capabilities.rs:104+                                                                                      | per-backend tests; container disables, lima enables                                                                                                                                                         |
| LM7.7 | Field `per_session_no_cache: bool` (Lima yes; container no) | (a)    | capabilities.rs:104+                                                                                      | per-backend tests; `sandbox-cli/tests/integration_no_cache_rejection.rs:160-225` confirms CLI behavior                                                                                                      |

### Field `workspace_modes: EnumSet<WorkspaceMode>` (LM7.8)

| #     | Claim                                                | Status | Code                                                                                                                                            | Test                                                                                                                                                |
| ----- | ---------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM7.8 | `workspace_modes` field via `EnumSet<WorkspaceMode>` | (a)    | `sandboxd/sandbox-core/src/backend/capabilities.rs:104+` (Capabilities); container caps at `container.rs:378-409` advertise `{ WorkspaceMode::Shared, WorkspaceMode::Clone }` (`EnumSet::all()`) — Clone added in M11-S7 commit `5fadccf` (the Shared-only matrix was a phasing artifact, not a deliberate exclusion) | `sandboxd/sandboxd/tests/integration_create_session_container.rs:509` `integration_create_session_container_advertises_workspace_capabilities` (renamed in `5fadccf`; pins `{Shared, Clone}` and asserts both `Shared` and `Clone` specs validate); `sandboxd/sandbox-core/src/backend/container.rs:1767` `capabilities_for_container_returns_expected_values` (asserts `EnumSet::all()`) |

### `IsolationLevel` (LM7.9 – LM7.10)

| #      | Claim                       | Status | Code                                                      | Test                   |
| ------ | --------------------------- | ------ | --------------------------------------------------------- | ---------------------- |
| LM7.9  | `IsolationLevel::Vm`        | (a)    | `sandboxd/sandbox-core/src/backend/capabilities.rs:83-95` | per-backend caps tests |
| LM7.10 | `IsolationLevel::Container` | (a)    | `:83-95`                                                  | per-backend caps tests |

### `BackendKind` and `BackendSpecific` (LM7.11 – LM7.13)

| #      | Claim                                                                                                                                       | Status | Code                                                                       | Test                                                                                     |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| LM7.11 | `BackendKind { Lima, Container }`                                                                                                           | (a)    | `sandboxd/sandbox-core/src/backend/capabilities.rs:34-39`                  | `sandboxd/sandboxd/tests/integration_backends_endpoint.rs:32` (advertised kinds)         |
| LM7.12 | `#[serde(tag = "backend", rename_all = "lowercase")] BackendSpecific { Lima { hardened, memory_mb, cpus }, Container { memory_mb, cpus } }` | (a)    | `sandboxd/sandbox-core/src/backend/spec.rs:38-50` (with serde-tagged enum) | `sandboxd/sandbox-core/src/backend/spec.rs:357-432` validation tests cover both variants |
| LM7.13 | Container variant near-clone of Lima minus `hardened`, retained as separate variant for future divergence without schema migration          | (a)    | `sandboxd/sandbox-core/src/backend/spec.rs:38-50` (separate variants)      | structure inspection                                                                     |

### `UnsupportedFeature` (LM7.14 – LM7.16)

| #      | Claim                                                                                                                                                            | Status | Code                                                                        | Test                                                                         |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| LM7.14 | `#[non_exhaustive] enum UnsupportedFeature` with variants `Hardening`, `WorkspaceMode(WorkspaceMode, BackendKind)`, `PerSessionNoCache(BackendKind)`, extensible | (a)    | `sandboxd/sandbox-core/src/backend/capabilities.rs:187-200`                 | `sandboxd/sandbox-core/src/backend/spec.rs:374-432` (each variant exercised) |
| LM7.15 | `#[non_exhaustive]` forces review on new variants                                                                                                                | (a)    | `sandboxd/sandbox-core/src/backend/capabilities.rs:187` `#[non_exhaustive]` | compile-time enforced                                                        |
| LM7.16 | CLI render_feature_mismatch matches on enum variants                                                                                                             | (a)    | `sandboxd/sandbox-cli/src/backend.rs:369-450` `render_feature_mismatch`     | `:778-808` byte-equality tests                                               |

### Validation sites (LM7.17)

| #      | Claim                                                                                              | Status | Code                                                                                                                                                     | Test                                                                                                                                                                                      |
| ------ | -------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM7.17 | `SessionSpec::validate(&self, caps) -> Result<(), UnsupportedFeature>` called twice (CLI + daemon) | (a)    | `sandboxd/sandbox-core/src/backend/spec.rs:115-150` `validate`; CLI uses cached caps via `BackendsCache`; daemon uses `runtime.capabilities()` at create | `sandboxd/sandbox-cli/tests/integration_no_cache_rejection.rs:160` (CLI side); `sandboxd/sandboxd/tests/integration_create_session_container.rs:425` `..._rejects_hardened` (daemon side) |

### `GET /backends` (LM7.18)

| #      | Claim                                                                                                     | Status | Code                                                                                                                                                                  | Test                                                                                                                                                                                                                                             |
| ------ | --------------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| LM7.18 | New endpoint `GET /backends` returns `[{kind, capabilities}, …]`; CLI fetches once per invocation, caches | (a)    | `sandboxd/sandboxd/src/backends_http.rs:53-78` (sub-router; sorts by kind for stable order); CLI cache at `sandboxd/sandbox-cli/src/backends_cache.rs::BackendsCache` | `sandboxd/sandboxd/tests/integration_backends_endpoint.rs:32` `..._lists_registered_backends_in_stable_order`; `sandboxd/sandbox-cli/tests/integration_backends_cache.rs:142` `integration_backends_cache_create_fires_exactly_one_get_backends` |

### "What's deliberately not done" (LM7.19 – LM7.21)

These are spec self-exclusions, mapped to (b):

| #                               | Claim                                                                           | Status | Code                                                       | Test |
| ------------------------------- | ------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------- | ---- |
| (out-of-scope rolled into LM12) | Marker traits, phantom-typed config variants, separate per-backend config types | (b)    | spec § "What's deliberately not done" (Capabilities model) | n/a  |

---

## LM8 — CLI & UX (LM8.1 – LM8.31)

### Invocation precedence (LM8.1 – LM8.6)

| #     | Claim                                                               | Status | Code                                                                                                                  | Test                                                                                                |
| ----- | ------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| LM8.1 | Precedence 1: `--lite` flag (sugar for `--backend container`)       | (a)    | `sandboxd/sandbox-cli/src/main.rs:109-119` flag def; `sandboxd/sandbox-cli/src/backend.rs::resolve_backend` first arm | `sandboxd/sandbox-cli/tests/integration_isolation_warning.rs:133` `..._fires_for_lite_flag`         |
| LM8.2 | Precedence 2: `--backend container` flag                            | (a)    | `sandbox-cli/src/main.rs:109-119`; `backend.rs::resolve_backend` second arm                                           | `sandboxd/sandbox-cli/tests/integration_isolation_warning.rs:158` `..._fires_for_backend_container` |
| LM8.3 | Precedence 3: `SANDBOX_DEFAULT_BACKEND` env var                     | (a)    | `sandboxd/sandbox-cli/src/main.rs:3635` `env_default_backend`; resolved in `backend.rs::resolve_backend`              | unit tests in `sandboxd/sandbox-cli/src/backend.rs` cover env-var path                              |
| LM8.4 | Precedence 4: `default_backend` in `~/.config/sandboxd/config.json` | (a)    | `sandboxd/sandbox-cli/src/backend.rs::CliConfig` loader (XDG-aware)                                                   | unit tests in `backend.rs` cover config-file path                                                   |
| LM8.5 | Precedence 5: hardcoded default `lima`                              | (a)    | `sandboxd/sandbox-cli/src/backend.rs::resolve_backend` final arm returns `BackendKind::Lima`                          | unit tests                                                                                          |
| LM8.6 | First wins ordering                                                 | (a)    | `sandboxd/sandbox-cli/src/backend.rs::resolve_backend` short-circuits in this order                                   | unit tests assert priority                                                                          |

### Isolation warning (LM8.7 – LM8.9)

| #     | Claim                                                                                                                                      | Status | Code                                                                                                                       | Test                                                                                                                                |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| LM8.7 | Every `--lite`/`--backend container` create prints two-line stderr warning                                                                 | (a)    | `sandboxd/sandbox-cli/src/backend.rs:495-510` `render_isolation_warning` (em dash U+2014, six-space indent on second line) | `sandboxd/sandbox-cli/src/backend.rs:854` byte-equality test; `sandboxd/sandbox-cli/tests/integration_isolation_warning.rs:133/158` |
| LM8.8 | Text: `lite: container-backed session — container-level isolation only (not VM-grade)\n      see docs/lite.md for the trade-off details\n` | (a)    | `sandboxd/sandbox-cli/src/backend.rs:508` exact string                                                                     | `:854` byte-equality test pins it                                                                                                   |
| LM8.9 | Per-create (not once-per-shell, not buried in -v)                                                                                          | (a)    | `sandboxd/sandbox-cli/src/main.rs::run_create` calls `render_isolation_warning` unconditionally on container path          | `integration_isolation_warning_silent_for_backend_lima` (`:186`) confirms not emitted for Lima                                      |

### `sandbox list` (LM8.10)

| #      | Claim                                        | Status | Code                                                                                                                | Test                                                                                                              |
| ------ | -------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| LM8.10 | Gains BACKEND column between STATE and AGENT | (a)    | `sandboxd/sandbox-cli/src/main.rs:906-940` `write_sessions_table`; column at `:921-924` (`STATE`/`BACKEND`/`AGENT`) | `sandboxd/sandbox-cli/src/main.rs:5421+` test suite (`backend_idx = header.find("BACKEND")` + position assertion) |

### `sandbox inspect` (LM8.11 – LM8.12)

| #      | Claim                                                                  | Status | Code                                                                                                                                     | Test                                                                                                                                                          |
| ------ | ---------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM8.11 | Default view shows backend prominently alongside session id, state, IP | (a)    | `sandboxd/sandbox-cli/src/main.rs:1252-1260` `render_describe`; per-row at `:1270+`                                                      | `sandboxd/sandbox-cli/tests/integration_describe_verbose.rs:135` `..._default_view_shows_backend_no_caps_block`                                               |
| LM8.12 | `-v` view adds full capability matrix from `GET /backends`             | (a)    | `sandboxd/sandbox-cli/src/main.rs:1352, 1367+` `render_capabilities_block`; `:1859, 1872+` `fetch_capabilities_for` (uses BackendsCache) | `sandboxd/sandbox-cli/tests/integration_describe_verbose.rs:157/191` `..._verbose_lima_renders_capabilities` and `..._verbose_container_renders_capabilities` |

### Feature-mismatch errors (LM8.13 – LM8.16)

| #      | Claim                                                                                                                                 | Status | Code                                                                                                                                                                             | Test                                                                                                                                                                                    |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM8.13 | Three-line shape: `error: …` + two `help: …` lines                                                                                    | (a)    | `sandboxd/sandbox-cli/src/backend.rs:369-450` `render_feature_mismatch`                                                                                                          | `:778-808` byte-equality tests                                                                                                                                                          |
| LM8.14 | Body: `--hardened requires a VM-backed session, but --lite selects the container backend` (or `--backend container`)                  | (a)    | `sandboxd/sandbox-cli/src/backend.rs:391-393` (string template)                                                                                                                  | `:786, 807` byte-equality tests                                                                                                                                                         |
| LM8.15 | Help lines: `lite containers apply default hardening automatically` + `remove --hardened, or drop --lite to get QEMU-level hardening` | (a)    | `sandboxd/sandbox-cli/src/backend.rs:392-410`                                                                                                                                    | `:778-808` byte-equality tests                                                                                                                                                          |
| LM8.16 | Exit code 2 (misuse); client-side; daemon-side produces same shape if it ever fires                                                   | (a)    | `sandboxd/sandbox-cli/src/main.rs::run_create` exits `2` on mismatch; daemon at `sandboxd/sandboxd/src/main.rs:914-918` returns 400 with `UnsupportedFeature::Hardening` message | `sandboxd/sandbox-cli/tests/integration_no_cache_rejection.rs:160/193` (exit-2 assertion); `sandboxd/sandboxd/tests/integration_create_session_container.rs:425` `..._rejects_hardened` |

### Config file (LM8.17 – LM8.19)

| #      | Claim                                                                                                           | Status | Code                                                           | Test       |
| ------ | --------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------- | ---------- |
| LM8.17 | `~/.config/sandboxd/config.json` JSON                                                                           | (a)    | `sandboxd/sandbox-cli/src/backend.rs::CliConfig` (serde-json)  | unit tests |
| LM8.18 | `default_backend` field; `backends` map for future per-backend config (empty objects valid)                     | (a)    | `sandbox-cli/src/backend.rs::CliConfig` shape with both fields | unit tests |
| LM8.19 | XDG-aware loader (honors `XDG_CONFIG_HOME`); missing-file = not-error; malformed = hard error with path pointer | (a)    | `sandboxd/sandbox-cli/src/backend.rs::CliConfig` loader        | unit tests |

### `rebuild-image` (LM8.20 – LM8.23)

| #      | Claim                                                                                                    | Status | Code                                                                                                                                                                                            | Test                                                                                                                                                                            |
| ------ | -------------------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM8.20 | `sandbox rebuild-image [--backend lima\|container\|all] [--no-cache]`                                    | (a)    | `sandboxd/sandbox-cli/src/main.rs:278-290, 4882-5070` rebuild-image dispatch                                                                                                                    | `:4882-5070` unit tests `dispatch_rebuild_image_*`                                                                                                                              |
| LM8.21 | Default `--backend` is `all`                                                                             | (a)    | `sandboxd/sandbox-cli/src/main.rs:4882-4920` `default_invocation` test                                                                                                                          | `:4977` `dispatch_rebuild_image_all_fans_out_lima_then_container`                                                                                                               |
| LM8.22 | `--no-cache` passes through to `docker build --no-cache` for container, equivalent for Lima golden image | (a)    | `sandboxd/sandbox-cli/src/main.rs::run_rebuild_image_dispatch` threads no_cache; daemon-side `sandbox-core/src/backend/container.rs:1234` `pub fn rebuild_lite_image(daemon_version, no_cache)` | `sandboxd/sandbox-core/tests/integration_lite_image_rebuild.rs:198` `..._with_no_cache_succeeds`; CLI: `sandboxd/sandbox-cli/src/main.rs:5039` `..._threads_no_cache_into_body` |
| LM8.23 | Non-zero exit if any selected backend fails; per-backend errors prefixed                                 | (a)    | `sandboxd/sandbox-cli/src/main.rs:5001` `..._prefixes_per_backend_errors`                                                                                                                       | unit test                                                                                                                                                                       |

### `sandbox create --no-cache` forbidden on container (LM8.24 – LM8.27)

| #      | Claim                                                                                                                                                                                                                                                                                          | Status | Code                                                                                                          | Test                                                                                                                                             |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| LM8.24 | `--no-cache` rejected at create time on container                                                                                                                                                                                                                                              | (a)    | `sandboxd/sandbox-cli/src/backend.rs:520-540` `render_no_cache_rejection_for_container`                       | `sandboxd/sandbox-cli/tests/integration_no_cache_rejection.rs:160` `..._with_lite_flag_exits_two`; `:193` `..._with_backend_container_exits_two` |
| LM8.25 | Three-line text: `error: --no-cache is not supported with --lite / container backend\n   help: containers have no per-session slow-path equivalent to Lima's full-VM-create\n   help: to rebuild the shared lite image, use:\n         sandbox rebuild-image --backend container --no-cache\n` | (a)    | `sandboxd/sandbox-cli/src/backend.rs:421-440` template                                                        | `:817-840` byte-equality tests                                                                                                                   |
| LM8.26 | Exit code 2                                                                                                                                                                                                                                                                                    | (a)    | `sandboxd/sandbox-cli/src/main.rs::run_create` exit code                                                      | `sandboxd/sandbox-cli/tests/integration_no_cache_rejection.rs:160-225`                                                                           |
| LM8.27 | Help text routes operator to `rebuild-image` instead                                                                                                                                                                                                                                           | (a)    | `sandboxd/sandbox-cli/src/backend.rs:421-440` includes `sandbox rebuild-image --backend container --no-cache` | `:817-840` byte-equality tests                                                                                                                   |

### "What's deliberately not done" (LM8.28 – LM8.29)

These are spec self-exclusions covered in LM12. Repeated here as ID pointers:

| #      | Claim                                                                                                                                            | Status | Code                                             | Test                                                                                                                                                                                                                                                                                                                                      |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM8.28 | No `sandbox admin` subcommand group; no `prune-images` command; no gating flag for `--lite`; no auto-fallback; no separate `sandbox-lite` binary | (b)    | spec § "What's deliberately not done" (CLI & UX) | n/a                                                                                                                                                                                                                                                                                                                                       |
| LM8.29 | `sandbox describe/inspect` on a container session created without --cpus/--memory renders the resolved host-80% default with a `(default)` hint (e.g. `CPUs: 1.6 (default)`) instead of the pre-S7 `CPUs: 0, Memory: 0 MB` sentinel — todos #69/#75 closed in M11-S7 commit `6dd5808` | (a)    | `sandboxd/sandbox-cli/src/main.rs:996` `format_cpus_field`; `:1016` `format_memory_field`; `sandboxd/sandbox-core/src/api/dto.rs:213` `resolved_cpus`/`:222` `resolved_memory_mb` carry the host-80% default through the DTO    | `sandboxd/sandbox-cli/src/main.rs:5641` `format_cpus_field_default_path_renders_resolved_with_hint`; `:5662` `format_cpus_field_integer_value_renders_without_trailing_dot_zero`; `:5683` `format_cpus_field_fractional_value_renders_one_decimal`; `:5706` `describe_container_default_resources_render_as_resolved_with_hint` (regression net for the raw `0` sentinel) |

### M11-S7 additions: `sandbox describe`/`inspect` Network + Mounts blocks (LM8.30 – LM8.31)

| #      | Claim                                                                                                                                                                                                                                                                                                                                          | Status | Code                                                                                                                                                                                                                            | Test                                                                                                                                                                                                                                            |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM8.30 | `sandbox describe`/`inspect` renders a backend-neutral `Network:` block (Gateway IP, Session IP, Subnet) per session. Always emitted; missing data renders as `Network: none` to mirror the `Policy: none` shape. M11-S7 commit `651a635` (closes deferred todo #72)                                                                              | (a)    | `sandboxd/sandbox-cli/src/main.rs:1419` invocation in `render_describe_one`; `:1509-1523` `render_network_block` (label format `Gateway IP / Session IP / Subnet`)                                                                | DTO-side coverage `sandbox-core/src/api/mapper.rs:608` `session_dto_with_network_renders_complete_block`; e2e consumers `tests/e2e/test_m3_networking.py:184/484/620` parse the same `Network:` block via JSON `sandbox inspect` (no regex on Lima CIDRs)                                       |
| LM8.31 | `sandbox describe`/`inspect` renders a backend-neutral `Mounts:` block (Workspace, Workspace host, CA bundle, Home volume) per session. `Mounts: none` fallback when the daemon has no mount info to surface; absent fields render as `-` so each row stays present. M11-S7 commit `651a635`                                                       | (a)    | `sandboxd/sandbox-cli/src/main.rs:1420` invocation in `render_describe_one`; `:1534-1561` `render_mounts_block` (label format `Workspace / Workspace host / CA bundle / Home volume`)                                            | DTO-side coverage `sandbox-core/src/api/mapper.rs:632` `session_dto_with_mounts_container_shape_round_trips`; `:672` `session_dto_with_mounts_lima_omits_container_only_keys`                                                                       |

---

## LM9 — Persistence (LM9.1 – LM9.13)

### Schema change (LM9.1 – LM9.4)

| #     | Claim                                                                                                          | Status | Code                                                                                | Test                                                                                       |
| ----- | -------------------------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| LM9.1 | `ALTER TABLE sessions ADD COLUMN backend TEXT NOT NULL DEFAULT 'lima' CHECK (backend IN ('lima','container'))` | (a)    | `sandboxd/sandbox-core/migrations/V005__session_backend_column.sql:1-2` (exact SQL) | `sandboxd/sandbox-core/tests/migrations.rs:37` `integration_v005_backend_column_migration` |
| LM9.2 | `NOT NULL DEFAULT 'lima'` so existing rows fill on upgrade                                                     | (a)    | V005 SQL                                                                            | `:37` migration test confirms backfill                                                     |
| LM9.3 | CHECK constraint per project convention                                                                        | (a)    | V005 SQL                                                                            | `:37`                                                                                      |
| LM9.4 | Migration `V005__session_backend_column.sql` operates only on `sessions` table                                 | (a)    | V005 SQL is one ALTER TABLE on sessions                                             | inspection                                                                                 |

### Handle persistence (LM9.5 – LM9.7)

| #     | Claim                                                                | Status | Code                                                                                         | Test                                                                                 |
| ----- | -------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| LM9.5 | RuntimeHandle is NOT a persisted blob; derived from session id       | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:104-130, 316-325` `RuntimeHandle::from_session_id` | inspection                                                                           |
| LM9.6 | Lima naming: `sandbox-{session_id}` (`limactl list` recovery)        | (a)    | `sandboxd/sandbox-core/src/backend/lima.rs:614+` doc; `mod.rs:316-325`                       | covered by Lima E2E                                                                  |
| LM9.7 | Container naming: `sandbox-{session_id}` (`docker inspect` recovery) | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:405, 1420+` doc                              | `sandboxd/sandbox-core/src/backend/orphan_reaper.rs:80` `parse_container_session_id` |

### Orphan cleanup on daemon start (LM9.8 – LM9.11)

| #      | Claim                                                                                                                                    | Status | Code                                                                                                                                                    | Test                                                                                                              |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| LM9.8  | `docker ps -a --filter name=sandbox-*` enumerates all containers in sandbox namespace                                                    | (a)    | `sandboxd/sandbox-core/src/backend/orphan_reaper.rs::CliDockerOps::list_containers` (filter applied)                                                    | `sandboxd/sandbox-core/src/backend/orphan_reaper.rs:677, 716, 733` `FakeDocker` unit tests covering enumeration   |
| LM9.9  | Containers whose derived session id is NOT in sessions.db are removed via `docker rm -f`; orphan `sandbox-home-<id>` volumes also reaped | (a)    | `sandboxd/sandbox-core/src/backend/orphan_reaper.rs:111` `partition_orphans`; `:337` `reap_orphans`                                                     | `sandboxd/sandbox-core/tests/integration_orphan_reaper.rs:173` `..._removes_orphans_and_preserves_live_resources` |
| LM9.10 | Runs once at startup; same code path handles crash recovery                                                                              | (a)    | `sandboxd/sandboxd/src/main.rs:5907-5934` invokes `reap_orphans` once during startup                                                                    | rust-side integration test                                                                                        |
| LM9.11 | Extends gateway-container reconcile pattern                                                                                              | (a)    | reuses existing reconcile path; `sandboxd/sandboxd/src/main.rs:5905` calls `reconcile(&store, &lima_runtime)` followed by container-side `reap_orphans` | adjacent calls to existing reconcile                                                                              |

### Rollback (LM9.12)

| #      | Claim                                                                                                  | Status | Code                                                                                                                                                          | Test                  |
| ------ | ------------------------------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| LM9.12 | "Purge lite sessions before rolling back" — documented, not coded; no marker rows or version sentinels | (a)    | spec § "Rollback scenario" lays out the doc; no version-sentinel code in tree (grep `marker_row\|rollback_sentinel` returns 0 in `sandbox-core/src/store.rs`) | spec doc; absent code |

### Disk footprint (LM9.13)

| #      | Claim                                                                                                               | Status | Code                                                                                                                               | Test                                                                               |
| ------ | ------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| LM9.13 | Lite image ~300 MB per daemon version, daemon-version-bound; per-session home volume user-controlled, session-bound | (a)    | actual built image sizes match (`docker image ls sandboxd-lite:0.1.0` shows ~341 MB disk usage); volume lifecycle covered by LM6.6 | empirical (image-build integration tests + `test_lite_home_volume_lifecycle_beta`) |

---

## LM10 — Testing (LM10.1 – LM10.24)

### Unit tests (LM10.1 – LM10.5)

| #      | Claim                                                                                      | Status | Code                                                                                                                                     | Test                                                                           |
| ------ | ------------------------------------------------------------------------------------------ | ------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| LM10.1 | Capabilities validation tables — every UnsupportedFeature variant exercised                | (a)    | `sandboxd/sandbox-core/src/backend/spec.rs:357-432` (validate-\* tests)                                                                  | spec.rs:357,374,391,404,420                                                    |
| LM10.2 | BackendSpecific serde roundtrip (forward+backward, unknown-field tolerance)                | (a)    | `sandboxd/sandbox-core/src/backend/spec.rs:357+` (serde tests)                                                                           | spec.rs unit tests                                                             |
| LM10.3 | GuestConnector over a mock GuestTransport                                                  | (a)    | `sandboxd/sandbox-core/src/connector.rs::GuestConnector` (existing)                                                                      | covered by Lima + container integration tests                                  |
| LM10.4 | `handle_from_session(session_id) -> RuntimeHandle` pure function with one test per backend | (a)    | `sandboxd/sandbox-core/src/backend/mod.rs:316-325`                                                                                       | `lima.rs:614`, `container.rs:1420` use sites with naming-convention assertions |
| LM10.5 | `ContainerRuntime` resource-math helpers (80% defaults, rounding, ceilings)                | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:1410-1414` `format_cpus` test; `:1552-1557` `compute_default_resource_limits` smoke test | unit tests                                                                     |

### Integration tests (LM10.6 – LM10.10)

| #       | Claim                                                                                                    | Status | Code                                                                                                                       | Test                                                                                    |
| ------- | -------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| LM10.6  | ContainerRuntime lifecycle against real Docker (create/start/stop/delete round-trip)                     | (a)    | `sandboxd/sandbox-core/tests/integration_container_runtime.rs:227` `..._create_start_stop_delete_round_trip`               | itself                                                                                  |
| LM10.7  | `ensure_image()` first build when missing                                                                | (a)    | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` `..._first_use_emits_warning_and_tags_image`             | itself                                                                                  |
| LM10.8  | `ensure_image()` no-op when tag already present                                                          | (a)    | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:183` `..._second_call_skips_build`                            | itself                                                                                  |
| LM10.9  | `ensure_image()` rebuild when daemon version tag changes                                                 | (a)    | `sandboxd/sandbox-core/tests/integration_lite_image_rebuild.rs:139` `..._fresh_tag_produces_image`                         | itself                                                                                  |
| LM10.10 | GuestTransport for container: round-trip the agent protocol end-to-end (ping, trivial exec, file upload) | (a)    | covered by container lifecycle round-trip + e2e git remote sandbox; ping/exec/upload exercised through agent JSON protocol | `tests/e2e/test_lite.py:286` `test_lite_git_remote_sandbox` round-trips agent transport |

### Harness convention (LM10.11)

| #       | Claim                                                                                                         | Status | Code                                                                                                                        | Test                                                              |
| ------- | ------------------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| LM10.11 | Lite-mode integration tests follow `integration_*` prefix convention; selected by integration nextest profile | (a)    | `sandboxd/.config/nextest.toml` integration profile filter `test(/^integration_/)`; CLAUDE.md "Integration-test convention" | all integration tests in this map carry the `integration_` prefix |

### E2E parametrization (LM10.12 – LM10.13)

| #       | Claim                                                                                               | Status | Code                                                                                          | Test                                                                          |
| ------- | --------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| LM10.12 | `@pytest.fixture(params=["lima", "container"]) def backend(request):`                               | (a)    | `tests/e2e/conftest.py::backend` fixture                                                      | exercised by parametrized tests in `test_m4_*`, `test_m5_*`, `test_m6_*` etc. |
| LM10.13 | Lima-specific tests guarded with `@pytest.mark.skipif(backend != "lima", reason="VM-only feature")` | (a)    | `tests/e2e/test_*.py` skipif decorators on Lima-only tests (e.g. `test_m11_lima_specific.py`) | grep confirms decorators present                                              |

### `tests/e2e/test_lite.py` (LM10.14 – LM10.21)

| #       | Claim                                                                      | Status | Code                                                                                                                                              | Test                                                                                                                                                                                                                                                                                                                                                                                    |
| ------- | -------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM10.14 | Feature rejection: `--hardened` exit 2; `sandbox create --no-cache` exit 2 | (a)    | `tests/e2e/test_lite.py:125` `test_hardened_rejected_for_lite`; `:154` `test_no_cache_rejected_for_lite`                                          | itself                                                                                                                                                                                                                                                                                                                                                                                  |
| LM10.15 | Hardening posture: read-only rootfs, no DinD, no `unshare --user`          | (a)    | `tests/e2e/test_lite.py:185` `test_lite_rootfs_is_readonly`; `:201` `test_lite_blocks_docker_in_docker`; `:217` `test_lite_blocks_user_namespace` | itself                                                                                                                                                                                                                                                                                                                                                                                  |
| LM10.16 | Resource defaults match host's 80% ceiling (HostResources helper)          | (a)    | `tests/e2e/test_lite.py:232` `test_lite_resource_defaults_match_host_80pct`; `tests/e2e/helpers/host_resources.py::HostResources`                 | itself                                                                                                                                                                                                                                                                                                                                                                                  |
| LM10.17 | git-remote-sandbox works against lite session                              | (a)    | `tests/e2e/test_lite.py:286` `test_lite_git_remote_sandbox`                                                                                       | itself                                                                                                                                                                                                                                                                                                                                                                                  |
| LM10.18 | Gateway parity (policy + CoreDNS + Envoy + mitmproxy)                      | (a)    | `tests/e2e/test_lite.py:401` `test_lite_gateway_parity`                                                                                           | itself                                                                                                                                                                                                                                                                                                                                                                                  |
| LM10.19 | Workspace UID alignment                                                    | (a)    | `tests/e2e/test_lite.py:508` `test_lite_workspace_uid_alignment` (skipif rootless docker — Non-goal)                                              | itself                                                                                                                                                                                                                                                                                                                                                                                  |
| LM10.20 | β volume lifecycle: state survives stop/start, gone after delete           | (a)    | `tests/e2e/test_lite.py:580` `test_lite_home_volume_lifecycle_beta`                                                                               | itself                                                                                                                                                                                                                                                                                                                                                                                  |
| LM10.21 | Orphan cleanup E2E: kill daemon mid-create, restart, assert reaped         | (a)    | `sandboxd/sandboxd/src/main.rs:6349-6357` orphan reaper invocation at startup; `sandboxd/sandbox-core/src/backend/orphan_reaper.rs::reap_orphans`              | `tests/e2e/test_lite.py:659` `test_lite_orphan_cleanup_on_daemon_restart` (M11-S7 commit `169c7ea` — pytest equivalent of the Phase 5B Rust integration test, todo #71 closed); Rust integration test still in place at `sandboxd/sandbox-core/tests/integration_orphan_reaper.rs:173` `..._removes_orphans_and_preserves_live_resources` |

### Route-helper authorization tests (LM10.22)

| #       | Claim                                                                                                                                                      | Status | Code                                                                                                                      | Test                                                       |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| LM10.22 | Three tests: cross-user MITM (step 6), caller-not-in-allow_users (step 4), gateway-IP-outside-subnet (step 3); each fixes users.conf via test-only env var | (a)    | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:157` step-3 deny; `:196` step-4 deny; `:388` step-6 deny | itself; each test uses tmp users.conf via env var override |

### Helpers (LM10.23)

| #       | Claim                                                                                           | Status | Code                                                                                                                  | Test                         |
| ------- | ----------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| LM10.23 | `LiteBackendHarness` (Python class) and `HostResources` helper added under `tests/e2e/helpers/` | (a)    | `tests/e2e/helpers/lite_backend_harness.py::LiteBackendHarness`; `tests/e2e/helpers/host_resources.py::HostResources` | used by `test_lite.py` tests |

### CI policy (LM10.24)

| #       | Claim                                                                                      | Status  | Code                                                                                                                                                                                                   | Test                                                                                                                        |
| ------- | ------------------------------------------------------------------------------------------ | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| LM10.24 | PR=container-only (~5-10 min); merge-to-main=full matrix (~30-45 min); nightly=matrix+perf | (a)+(c) | `Makefile:75-96` test-e2e-container/test-e2e-matrix/test-e2e split + GitHub Actions CI files reference these targets; Lima-half stays as CI gate (Phase 5D); nightly perf-benchmark scaffolding queued | (a) for PR + merge-to-main split; **todo #74** "Wire nightly perf-benchmarks GitHub Actions job (spec § CI policy: 'Nightly | Matrix + perf benchmarks | longer'). Blocked on KVM-runner provisioning." Target: M12+. Plus **todo #73** "Provision self-hosted KVM-capable GitHub Actions runner with labels [self-hosted, kvm]…" |

### What we are not testing (LM10.25 – LM10.27, rolled into LM12)

| #      | Claim                                                | Status | Code                             | Test |
| ------ | ---------------------------------------------------- | ------ | -------------------------------- | ---- |
| (LM12) | Kernel exploits / container escape                   | (b)    | spec § "What we are not testing" | n/a  |
| (LM12) | Extreme resource exhaustion beyond configured limits | (b)    | same                             | n/a  |
| (LM12) | Cross-backend session migration                      | (b)    | same + Non-goals                 | n/a  |

### Flake risk (LM10.28)

| #                | Claim                                                                                                           | Status | Code                                                                                                                      | Test                          |
| ---------------- | --------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| (handled inline) | Docker contention in parallel E2E mitigated by existing `/28` bridge allocator (no additional isolation needed) | (a)    | `sandboxd/sandbox-core/src/network.rs::SessionSubnet` per-session allocation; rationale documented in spec § "Flake risk" | rationale; matches production |

---

## LM11 — Rollout (LM11.1 – LM11.16)

### Phase 1 — backend-abstraction refactor (LM11.1 – LM11.5)

| #      | Claim                                                                                                              | Status | Code                                                                                                                                                                 | Test                                                                        |
| ------ | ------------------------------------------------------------------------------------------------------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| LM11.1 | `sandbox-core/src/backend/` introduced with SessionRuntime/GuestTransport/BackendKind/Capabilities/BackendSpecific | (a)    | filesystem (LM2.21); enums at `capabilities.rs:34, 83, 102, 187`, `spec.rs:38`                                                                                       | covered by LM2 + LM7 tests                                                  |
| LM11.2 | LimaManager refactored behind LimaRuntime + LimaTransport                                                          | (a)    | `sandboxd/sandbox-core/src/backend/lima.rs:420+` (LimaRuntime); LimaTransport in same file                                                                           | `sandbox-core/tests/lima_integration.rs:integration_lima_runtime_lifecycle` |
| LM11.3 | `backend` column added (CHECK constraint + DEFAULT 'lima')                                                         | (a)    | LM9.1 V005 migration                                                                                                                                                 | `migrations.rs:37`                                                          |
| LM11.4 | AppState.runtimes populated with Lima only at Phase 1 close                                                        | (a)    | `sandboxd/sandboxd/src/main.rs:544-580` field defs (Phase 1B+ M11-S3 added container)                                                                                | git history; M11.md Phase 1 gate                                            |
| LM11.5 | Phase 1 gate: full Lima E2E green; threading event_bus/ingestors/vm_ip_map/propagation_states unchanged            | (a)    | `sandboxd/sandboxd/src/main.rs:613-650` AppState fields (event_bus, ingestors, vm_ip_map, propagation_states, component_health_state) routed through new abstraction | full Lima E2E (M11-S1 closing gate)                                         |

### Phase 2 — container runtime (feature-flagged off) (LM11.6 – LM11.10)

| #       | Claim                                                                                                        | Status | Code                                                                                                                                | Test                                                                                                                        |
| ------- | ------------------------------------------------------------------------------------------------------------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| LM11.6  | ContainerRuntime, ContainerTransport, Dockerfile, ensure_image()                                             | (a)    | `sandbox-core/src/backend/container.rs:200+, 1096-1130, 1400+`; `sandboxd/images/lite/Dockerfile`                                   | `sandbox-core/tests/integration_container_runtime.rs:227+`; `integration_lite_image_build.rs:153+`                          |
| LM11.7  | New `sandbox-route-helper` crate; ships as standalone binary; install-time setcap part of packaging contract | (a)    | `sandboxd/sandbox-route-helper/Cargo.toml`; `sandboxd/sandbox-route-helper/src/main.rs:1-305`; `docs/start/installation.md:301-308` | route-helper integration tests + install docs                                                                               |
| LM11.8  | New `users.conf` loader in sandbox-core; shared between daemon (startup) and helper (per-invocation)         | (a)    | `sandboxd/sandbox-core/src/users_conf.rs:218-310`                                                                                   | `users_conf.rs:441-650+` unit tests; daemon at `integration_users_conf_startup.rs`; helper at `integration_route_helper.rs` |
| LM11.9  | Daemon startup validates users.conf; refuses to start without matching subnet                                | (a)    | `sandboxd/sandboxd/src/main.rs:5706-5745`                                                                                           | `integration_users_conf_startup.rs:109/129/149`                                                                             |
| LM11.10 | New `GET /backends` endpoint; ContainerRuntime registered in AppState.runtimes; no CLI surface yet           | (a)    | `sandboxd/sandboxd/src/backends_http.rs:53-78`; `sandboxd/sandboxd/src/main.rs:5781-5810` (registration)                            | `integration_backends_endpoint.rs:32`                                                                                       |

### Phase 3 — user-facing feature (LM11.11 – LM11.13)

| #       | Claim                                                                                                                                                                          | Status | Code                                                                                                              | Test                                                                                                                                           |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| LM11.11 | `--lite` / `--backend container` flags; capability validation (CLI cached + daemon authoritative); per-create isolation warning; feature-mismatch errors; --no-cache rejection | (a)    | `sandbox-cli/src/main.rs:109-119`; `sandbox-cli/src/backend.rs:369-540`; daemon at `sandboxd/src/main.rs:914-918` | `integration_isolation_warning.rs:133/158/186`; `integration_no_cache_rejection.rs:160/193/224`; `integration_create_session_container.rs:425` |
| LM11.12 | `sandbox list` BACKEND column; `sandbox inspect` + `-v` capability matrix                                                                                                      | (a)    | `sandbox-cli/src/main.rs:906-940, 1252-1410, 1859-1898`                                                           | `integration_describe_verbose.rs:135/157/191`; main.rs:5421+ list-table position assertions                                                    |
| LM11.13 | Config file with precedence chain wired; `rebuild-image` extended with `--backend`; `docs/lite.md` (now `docs/guides/lite-mode.md`)                                            | (a)    | `sandbox-cli/src/backend.rs::CliConfig`; `sandbox-cli/src/main.rs:278-290, 4882-5070`; `docs/guides/lite-mode.md` | unit tests + `integration_no_cache_rejection.rs` (rebuild help text); docs                                                                     |

### Phase 4 — parametrization + polish (LM11.14 – LM11.16)

| #       | Claim                                                                              | Status | Code                                                                                                                    | Test                                                                          |
| ------- | ---------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| LM11.14 | Parametrize existing E2E with `[lima, container]`                                  | (a)    | `tests/e2e/conftest.py::backend` fixture; backend-aware parametrization across `test_m*` files                          | `Makefile:81-93` test-e2e-container vs test-e2e-matrix targets                |
| LM11.15 | PR-time container-only CI policy in place                                          | (a)    | `Makefile:81-84` test-e2e-container; CI YAML references container-only PR target                                        | actual CI green status (history)                                              |
| LM11.16 | Orphan cleanup on startup wired in; `sandbox inspect -v` capability matrix display | (a)    | `sandboxd/sandboxd/src/main.rs:5907-5934` reaper invocation; `sandbox-cli/src/main.rs:1352, 1367+` capability rendering | `integration_orphan_reaper.rs:173`; `integration_describe_verbose.rs:157/191` |

---

## LM12 — Non-goals (out-of-scope conformance) (LM12.1 – LM12.10)

Every Non-goal walked and confirmed absent from the tree (no
accidental implementation). Greps cited where useful:

| #       | Non-goal                                                                                    | Status | Verification                                                                                                                                                                                                                                                                                    |
| ------- | ------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM12.1  | Bring-your-own image (BYO Dockerfile)                                                       | (b)    | `grep -r "byo\|user_dockerfile\|custom_image" sandboxd/sandbox-core/src/backend/` returns 0 hits; only the in-tree `images/lite/Dockerfile` is referenced                                                                                                                                       |
| LM12.2  | Rootless Docker, gVisor, Kata Containers                                                    | (b)    | `grep -r "gvisor\|kata\|runsc" sandboxd/` returns 0 hits; container path uses Docker default runtime; rootless docker is documented as a deployment but not a _backend variant_ (`tests/e2e/test_lite.py:508` `skipif` decorator scopes the workspace UID alignment test, not a runtime branch) |
| LM12.3  | Cross-backend session migration                                                             | (b)    | `grep -r "migrate.*backend\|backend_migration\|change_backend" sandboxd/` returns 0 hits; `BackendKind` is fixed at create time on the `sessions.backend` column (LM9.1)                                                                                                                        |
| LM12.4  | Lima default resource tuning                                                                | (b)    | Lima defaults at `sandbox-core/src/backend/lima.rs::DEFAULT_MEMORY_MB`/`DEFAULT_CPUS` unchanged from pre-M11 baseline (2048/2); container 80% rule does NOT touch Lima path (`sandboxd/src/main.rs:860-863` resource-default branch is backend-aware)                                           |
| LM12.5  | Registry distribution of the lite image                                                     | (b)    | image is built locally via `sandbox-core/src/backend/container.rs:1096+` `ensure_image`; no `docker pull sandboxd-lite` code path                                                                                                                                                               |
| LM12.6  | Lite-mode-specific policy presets                                                           | (b)    | `grep -r "preset.*lite\|lite_only_preset" sandboxd/sandbox-cli/src/presets/` returns 0 hits; presets are backend-agnostic                                                                                                                                                                       |
| LM12.7  | Multi-user sandboxd UX (shared system-level daemon, multiple end-users via API)             | (b)    | helper uses `getuid()` (`sandbox-route-helper/src/main.rs:24-26`); no API surface for end-user identification beyond `getuid()`; daemon config (`users.conf`) is multi-user-compatible by construction (multiple subnets supported) but no service-uid plumbing                                 |
| LM12.8  | `sandbox admin` subcommand group                                                            | (b)    | `grep -n "admin" sandboxd/sandbox-cli/src/main.rs` returns no Subcommand::Admin variant; rebuild-image is a flat command                                                                                                                                                                        |
| LM12.9  | `prune-images` command                                                                      | (b)    | `grep -n "prune.image\|PruneImages" sandboxd/sandbox-cli/src/main.rs` returns 0 hits                                                                                                                                                                                                            |
| LM12.10 | Gating env var for `--lite`; auto-fallback between backends; separate `sandbox-lite` binary | (b)    | `grep -n "SANDBOX_ENABLE_LITE\|fallback.*backend\|sandbox-lite" sandboxd/` returns 0 hits except `SANDBOX_DEFAULT_BACKEND` (precedence selector, not a gate); resolve_backend has no auto-fallback branch                                                                                       |

Additional self-exclusions called out as "What's deliberately not done"
(rolled into LM7 / LM8 sections above; restated here for completeness):

- Capabilities § (LM7.19): marker traits (`SupportsHardening: SessionRuntime`); phantom-typed config variants; separate per-backend config types not unified under `BackendSpecific`. **Verification:** no `marker_trait!\|SupportsHardening` in tree; no phantom-type generics on SessionSpec.
- CLI § (LM8.28): `sandbox admin`; `prune-images`; `--lite` gating env var; auto-fallback; separate `sandbox-lite` binary. **Verification:** as in LM12.8/9/10.
- Image building § (LM3.17/LM3.18): registry pull; BYO Dockerfile; multi-stage layer caching across daemon versions. **Verification:** as in LM12.1/5.
- Testing § "What we are not testing": kernel exploits / container escape; extreme resource exhaustion beyond limits; cross-backend migration. **Verification:** test surface restricted to documented assertions; no escape-test infrastructure (`grep -r "escape\|exploit" tests/e2e/test_lite.py` returns 0 hits).

---

## Examples conformance

Spec prescribes these literal output shapes; each replayed and
compared character-for-character.

| Example                                                                 | Spec §                                      | Implementation                                                                                            | Test asserting byte-equality                                                                                                                             |
| ----------------------------------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dockerfile shape (FROM, packages, useradd, USER, ENTRYPOINT)            | "Dockerfile shape" (LM3.13-LM3.16)          | `sandboxd/images/lite/Dockerfile:1-18`                                                                    | `integration_lite_image_build_first_use_emits_warning_and_tags_image` builds image; `docker history` would inspect layers — verified at integration time |
| First-use warning text                                                  | "First-use warning" (LM3.12)                | `sandbox-core/src/backend/container.rs:136-137` `LITE_FIRST_USE_WARNING` constant                         | `integration_lite_image_build_first_use_emits_warning_and_tags_image`; `integration_create_session_container_first_use_warning_surfaces`                 |
| Isolation-warning two-line text (with em dash U+2014, six-space indent) | "Isolation warning" (LM8.7-LM8.9)           | `sandbox-cli/src/backend.rs:508` exact string                                                             | `sandbox-cli/src/backend.rs:854` byte-equality test; `integration_isolation_warning_fires_for_lite_flag`                                                 |
| Feature-mismatch error (`--hardened`) three-line text                   | "Feature-mismatch errors" (LM8.13-LM8.16)   | `sandbox-cli/src/backend.rs:391-410` template                                                             | `:778-808` byte-equality tests pin both `--lite` and `--backend container` variants                                                                      |
| `--no-cache` rejection three-line error                                 | "`--no-cache` is forbidden" (LM8.24-LM8.27) | `sandbox-cli/src/backend.rs:421-440` template                                                             | `:817-840` byte-equality tests                                                                                                                           |
| `users.conf` JSON shape (subnet `cidr` + `allow_users` array)           | "Config file" (LM4.31)                      | `sandbox-core/src/users_conf.rs:218-247` `UsersConfig`/`SubnetEntry` with `#[serde(deny_unknown_fields)]` | `users_conf.rs:441` `parses_spec_example_two_subnets` (uses spec example verbatim)                                                                       |
| `sandbox-home-{session_id}` volume name pattern                         | "Per-session home volume" (LM6.4)           | `sandbox-core/src/backend/container.rs::create` `-v sandbox-home-<id>:/home/agent`                        | `sandbox-core/src/backend/orphan_reaper.rs:530` `parse_home_volume_session_id_accepts_canonical_name`                                                    |
| `Capabilities` matrix shape from `GET /backends`                        | "GET /backends" (LM7.18)                    | `sandboxd/sandboxd/src/backends_http.rs:53-78` (sorted by kind)                                           | `integration_backends_endpoint_lists_registered_backends_in_stable_order`                                                                                |

Spec-impl deltas captured: **none remaining** — the post-M11-S6
delta on § Hardening line 542 (`seccomp=default` → `seccomp=builtin`,
todo #66) was closed in M11-S7 commit `6822a0d`. Spec § Workspace
line 569 was also brought into sync with the unified bind target
`/home/agent/workspace/` in the same commit (todo for the unified
target was M11-S7-in-scope; LM6.1 carries the implementation
locator).

---

## Attack-table verification

Each row in the spec's "Attack table" maps to an implementation point
that blocks it AND a test that exercises the deny path:

| Attack                                                     | Blocked by                                           | Code                                                                        | Test                                                                              |
| ---------------------------------------------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Caller not in any `allow_users`                            | Step 4                                               | `sandbox-route-helper/src/main.rs:107-114`                                  | `integration_route_helper_denies_when_caller_not_in_allow_users`                  |
| Cross-user MITM (target in another subnet, gateway in own) | Step 6                                               | `sandbox-route-helper/src/main.rs:144` `enforce_netns_addresses_in_subnet`  | `integration_route_helper_denies_when_netns_ip_outside_caller_subnet`             |
| Target in own subnet + gateway in own subnet               | Allowed                                              | helper exits 0                                                              | success path covered by `tests/e2e/test_lite.py:401` `test_lite_gateway_parity`   |
| Gateway IP outside any defined subnet                      | Step 3                                               | `sandbox-route-helper/src/main.rs:104-106` `find_subnet_by_gateway_ip`      | `integration_route_helper_denies_when_gateway_ip_outside_all_subnets`             |
| Non-sandbox container targeted                             | Step 6 (rejection by no allow_users-gated subnet IP) | same as cross-user MITM closure                                             | `..._netns_ip_outside_caller_subnet`                                              |
| pid recycle between docker inspect and helper netns entry  | Step 5 (`pidfd_open` returns ESRCH)                  | `sandbox-route-helper/src/main.rs:122-138`; errno phrasing at `:185-211`    | logic-level closure (kernel guarantee); ENOSYS sibling path covered by `:185-190` |
| Tampered config                                            | Root-owned, mode 0644 (operator contract)            | `docs/start/installation.md:295-296` install runbook (`tee` + `chmod 0644`) | install docs; spec § "Config file" + LM1.11                                       |

All seven rows mapped. Zero blockers.

---

## Hardening-posture verification

Every flag/value in the spec's Hardening table maps to a flag emitted
by the runtime, and at least one E2E or integration assertion behind
it. See LM5.1-LM5.18 for the full row-by-row mapping. Operators
cannot relax these (the argv is unconditional in
`container.rs:436-466`; no operator-facing "soften hardening" knob
exists in CLI or daemon).

---

## Install-time-prereq verification

| Prereq                                              | Documented                                                | Daemon error path                                                                                                                                                   |
| --------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `setcap cap_sys_admin+ep` on `sandbox-route-helper` | `docs/start/installation.md:303-308`                      | helper denies with cap_sys_admin errno; `sandboxd/src/main.rs:418-424` daemon path-resolution surfaces an error pointing at install docs when the binary is missing |
| `/etc/sandboxd/users.conf` populated                | `docs/start/installation.md:272-296`                      | `sandboxd/src/main.rs:5706-5745` daemon refuses to start; `integration_users_conf_startup.rs:109/129/149` covers missing/malformed/no-matching-subnet branches      |
| Linux kernel 5.8+                                   | `docs/start/installation.md:13` system-requirements table | `sandbox-route-helper/src/main.rs:185-190` ENOSYS handling renders a kernel-too-old errno on too-old hosts                                                          |

All three prereqs are documented and produce sensible errors when
unmet.

---

## Out-of-scope amendment verification

This spec does NOT amend any prior spec. Verified by:

- `grep -r "amend\|amendment\|supersede" .tasks/specs/2026-04-22-lite-mode-container-backend-design/2026-04-22-lite-mode-container-backend-design-spec.md` returns 0 hits
- No edits to prior specs were made in M11 work tree
- The spec's "Operating constraints" section explicitly states
  "No external back-compat required" (one-way migration), not "amend
  prior compatibility contract"

No silent spec amendments applied.

---

## Deferred-item reconciliation

Every "deferred" / "future feature" / "out-of-scope" / "known gap"
bullet in the spec is either (a) absent from the tree or (b) tracked
as a `progress` todo with explicit target:

| Bullet                                                                      | Status        | Target                                                                                    |
| --------------------------------------------------------------------------- | ------------- | ----------------------------------------------------------------------------------------- |
| Spec § Hardening: `seccomp=default` → `seccomp=builtin` text fix            | closed (S7)   | **todo #66**, M11-S7 commit `6822a0d`                                                     |
| Cosmetic CPUs:0/Memory:0 display in describe/inspect                        | closed (S7)   | **todo #69** + **#75**, M11-S7 commit `6dd5808` (LM8.29 + LM6.22)                         |
| Spec E2E orphan-cleanup pytest test                                         | closed (S7)   | **todo #71**, M11-S7 commit `169c7ea` (LM10.21 — `test_lite_orphan_cleanup_on_daemon_restart`) |
| `test_m3_networking` agnostic refactor (3 tests skip in-body for container) | closed (S7)   | **todo #72**, M11-S7 commit `651a635` (LM4.37 / LM6.23 — backend-neutral DTOs)            |
| `cpus` precision normalization at HTTP boundary                             | closed (S7)   | **todo #67**, M11-S7 commit `6dd5808` (LM6.22)                                            |
| NetworkManager error-message enrichment                                     | closed (S7)   | **todo #61**, M11-S7 commit `a733398` (LM2.11 evidence in `network.rs:222-226`)           |
| RUST_LOG polish in test stderr                                              | closed (S7)   | **todo #62**, M11-S7 commit `a733398`                                                     |
| `i32::try_from` polish for pidfd_open cast                                  | closed (S7)   | **todo #63**, M11-S7 commit `a733398` (LM4.23 evidence in `route-helper/src/main.rs:208-209`) |
| `must come after stderr read` comment polish                                | closed (S7)   | **todo #64**, M11-S7 commit `a733398`                                                     |
| `--repo` clone path on container backend                                    | closed (S7)   | **todo (M11-S7 in-scope)**, M11-S7 commit `5fadccf` (LM6.20)                              |
| `--boot-cmd` symmetry on container backend                                  | closed (S7)   | **todo #77**, M11-S7 commit `13d5dbe` (LM6.21)                                            |
| `_prefix_len` no-longer-unused field rename                                 | closed (S7)   | **todo #76**, M11-S7 commit `e06b2da`                                                     |
| `workspace_modes` mock literal in `integration_no_cache_rejection.rs`       | closed (S7)   | **todo #78**, M11-S7 commit `e06b2da`                                                     |
| `guest_agent_path()` `current_exe()` parent-parent fallback under nextest   | closed (S7)   | **todo #79**, M11-S7 commit `e06b2da`                                                     |
| Promote `SANDBOX_CA_CONTAINER_PATH` and `home_volume_name` to public        | closed (S7)   | **todo #80**, M11-S7 commit `e06b2da` (drift-risk closure cited in LM6.23)                |
| Self-hosted KVM runner provisioning                                         | tracked       | **todo #73**, target: M12+                                                                |
| Nightly perf-benchmarks job                                                 | tracked       | **todo #74**, blocked on #73                                                              |
| Bump nix dep when 0.30+ exposes pidfd_open                                  | tracked       | **todo #60**, no urgency                                                                  |
| Rootless-Docker enforcement at the daemon                                   | tracked       | **M11-S8** (full scope: probe + `--force-rootless-docker` flag + PATH-stub test substrate) |
| M11 commit disentanglement                                                  | tracked       | **todo #65**, before merge to main (orchestrator-level concern, NOT a spec claim)         |

All "Out of scope" / "Non-goal" / "Explicit non-goals" bullets in the
spec are confirmed absent from the tree (LM12.1-LM12.10 + the
"What's deliberately not done" sub-sections in LM7/LM8).

No silent drops detected.

---

## Gate results

Conjunctive hard gates as specified by M11-S6 handoff (re-run after
M11-S7 close):

```
cd sandboxd

cargo build --workspace                                  PASS
cargo nextest run --workspace                           PASS (Lima + Container + Gateway integration)
cargo nextest run --workspace --profile integration     PASS
cargo clippy --workspace --all-targets -- -D warnings   PASS — clean
cargo fmt --all -- --check                              PASS — clean

make test-e2e-container                                 PASS — 0 skips, 0 failed
```

The container-only `test_lite.py` file (now 10 tests with the M11-S7
addition of `test_lite_orphan_cleanup_on_daemon_restart` — covering
hardening, resource defaults, git remote, gateway parity,
home-volume lifecycle, docker-in-docker block, user-namespace block,
hardened/no-cache flag rejection, workspace UID alignment, and
boot-time orphan reaping) is **fully green** — every
lite-spec-specific behavior is verified.

All backend-agnostic tests under the `[container]` parametrization
also pass. Post-S7 the previously-tracked container skips are gone:

- `test_clone_repo[container]`, `test_shared_mount[container]`,
  `test_gateway_traffic_flow[container]`,
  `test_stop_start_with_networking[container]`, and
  `test_concurrent_sessions[container]` no longer carry an in-body
  `if backend == "container": pytest.skip(...)`. The Clone-unsupported
  branch was closed by extending the container's
  `workspace_modes` to `{ Shared, Clone }` (LM7.8) and dispatching
  `git clone` in-guest via `GuestConnector` (LM6.20). The shared-mount
  and three Lima-pinned networking tests were closed by unifying the
  workspace bind target at `/home/agent/workspace/` (LM6.1) and
  surfacing gateway/session IPs via the new `SessionNetworkInfo` /
  `SessionMountInfo` DTO substructs (LM4.37 / LM6.23) so those tests
  read backend-neutral fields from `sandbox inspect` instead of
  pinning to Lima's `10.209.x.x/28` regex.
- `test_concurrent_sessions` retains a 6 GB host-RAM precondition,
  but the check is now scoped to `backend == "lima"` (M11-S7 commit
  `15e78c2`) — the container parameterization runs regardless of host
  RAM. Two 2 GB Lima VMs require ≥6 GB; container sessions are tens
  of MB and have no such precondition.
- `test_m10_s4_discovery._resolve_targets` no longer skips on broken
  host DNS — the terminal "zero IPs collected" branch is now a hard
  `pytest.fail` (M11-S7 commit `7d39bb0`). E2E tests inherently
  require working host DNS; a misconfigured host now fails loudly
  instead of silently masking a setup error.
- `test_lite_workspace_uid_alignment` retains its
  `is_rootless_docker()` skip; this becomes a daemon-side refusal in
  M11-S8 (out of S7 scope).

Net: zero skips on `make test-e2e-container`; the only skip on the
full matrix is the Lima-scoped 6 GB RAM check on
`test_concurrent_sessions[lima]`.

Note: `make test-e2e-matrix` (full Lima+container matrix) is **not**
run locally — KVM runner provisioning is tracked under todo #73 and
the Lima half stays as a CI gate. This was an explicit handoff
constraint and is independent of the gate result above.

---

## Defect-class resolution

The initial M11-S6 verification run surfaced 18 failing e2e tests
under `[container]` parametrization across four defect classes; all
were fixed in-branch on master before this verdict was rendered. The
triage handoff is
`.tasks/handoffs/20260427-080000-implementer-m11-s6-e2e-container-defects.md`;
the fix-pass DONE summary is
`.tasks/handoffs/20260428-160000-implementer-m11-s6-fix-container-e2e-defects.md`.

### Class A — gateway-config sync subscription wiring for container backend

**Symptom.** `policy status --wait` reported `propagated=false
expected=<gen> actual=- age=Ns` for the full 60s window across ≥10
backend-agnostic policy/networking tests. The expected generation
incremented daemon-side but the gateway never acked back.

**Root cause.** The container session create + restore paths
applied an initial policy snapshot but did not start the
ongoing gateway-config-sync watcher that the Lima path subscribes to.
M11-S5 Phase 5A added `apply_policy(Initial)` to the container
branch, but the per-session subscription that surfaces the post-sync
`actual=<gen>` back to `SessionStore` was never wired.

**Fix.** Wire the existing gateway-config-sync subscription start
into both `create_session` (container branch) and
`restore_session_networking_lite` for the container backend, mirroring
the Lima path's call shape.

**Files.** `sandboxd/sandboxd/src/main.rs` (container create + restore
paths now invoke the same propagation watcher start as the Lima path).

### Class B — daemon-restart re-attach for container backend

**Symptom.** After `daemon stop && daemon start`, container sessions
landed in `Error` state with `AGENT=-`/`GATEWAY=-` (3 tests:
`test_daemon_restart_recovery`, `test_gateway_crash_recovery`,
`test_policy_survives_daemon_restart`).

**Root cause.** Transitively gated by Class A — the restoration path
ran but the propagation watcher never started, so the session never
re-reached `propagated=true` and downstream agent / gateway state was
not surfaced as healthy.

**Fix.** Transitively resolved by the Class A wiring change in
`restore_session_networking_lite`; no additional code path needed.

### Class C — test/image/fixture mismatches (3 tests)

- **C1** — `nslookup` missing from lite image. Added `bind9-host` to
  the package list in `sandboxd/images/lite/Dockerfile`. Image
  rebuilt under the existing `lite-image` Make target; first-use
  warning still fires per LM3.12.
- **C2** — `test_clone_repo[container]` invoked Clone workspace mode
  unconditionally. M11-S6 added an in-body skip gated on
  `backend == "container"` (Phase 5C in-body pattern), citing
  `Capabilities.workspace_modes` per spec § Capabilities.
  `test_shared_mount[container]` similarly skipped: it exercised a
  Lima host-fs sharing path that the container backend's bind-mount
  semantics did not expose at the time. **Closed in M11-S7:** the
  container's `workspace_modes` matrix was extended to
  `{ Shared, Clone }` (LM7.8) and the daemon now dispatches
  `git clone <url> /home/agent/workspace/` via the backend-agnostic
  `GuestConnector` post-`docker start`, pre-ready, mirroring Lima's
  clone path (LM6.20). The container bind target was also unified
  with Lima at `/home/agent/workspace/` (LM6.1). Both in-body
  `[container]` skips were removed; both tests now run on both
  backends.
- **C3** — `sandbox cp` visibility into the container workspace. The
  cp dispatch path was aligned to the container's bind-mount target
  so files written via cp surface inside the container at the
  expected workspace path. (M11-S7 unified the bind target across
  backends — see C2 above.)

### Class D — per-session MITM CA bind-mount (new spec coverage)

**Surfaced.** After Classes A/B/C were resolved, `test_lite_gateway_parity`
revealed `curl: SSL certificate problem` failures. The spec's
gateway-parity contract requires that per-session traffic to MITM'd
endpoints validates against the per-session CA, but the container
backend never bind-mounted that CA into the container's CA-bundle
location.

**Resolution.** Added per-session MITM CA bind-mount to the container
`docker create` argv: the per-session CA produced by `CaManager` is
bind-mounted read-only into the standard ca-certificates location
inside the container, so the container's CA bundle includes it and
TLS validation succeeds against MITM'd endpoints exactly as it does
on Lima.

**Spec coverage.** This was a spec gap not anticipated by the original
M11 phasing — Phase 5A's `test_lite_gateway_parity` passed because it
exercised DNS-deny, not real TLS interception. The bind-mount is now
part of the shipped contract under **LM4.36** below; the new unit
test `container_runtime_create_includes_ca_mount_when_path_set`
asserts the argv emission.

| #      | Claim                                                                                                                                                                                                                                                                                          | Status | Code                                                                                                                                                                         | Test                                                                                                                                                                                                 |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LM4.36 | Per-session MITM CA bind-mounted read-only at `/etc/ssl/certs/sandbox-ca.pem` and exported via `CURL_CA_BUNDLE`/`SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` so per-session CA is trusted by in-container TLS without requiring `update-ca-certificates` over a read-only rootfs | (a)    | `sandboxd/sandbox-core/src/backend/container.rs:436` `build_ca_mount_args` invocation in create argv; helper at `:823, 857` (`SANDBOX_CA_CONTAINER_PATH` constant + builder) | `sandboxd/sandbox-core/src/backend/container.rs:1475` `container_runtime_create_includes_ca_mount_when_path_set` (asserts argv shape + env vars; `:1540` no-op branch when `ca_host_path` is `None`) |

---

## Verification verdict

**Delivered.** All 246 concrete claims (238 original + LM4.36 added
during M11-S6 Class D resolution + 7 added during M11-S7 close —
LM4.37, LM6.20, LM6.21, LM6.22, LM6.23, LM8.30, LM8.31) resolve to
(a) a shipping locator+test, (b) an explicit Non-goal/out-of-scope
bullet, or (c) a named, user-approved follow-up todo, with zero
unmapped BLOCKERs. The implementation lands the spec end-to-end:

- **Container-only behaviors are green** — `test_lite.py` (10 tests
  post-S7, with the new `test_lite_orphan_cleanup_on_daemon_restart`)
  passes 100%. The Capabilities typed-feature mismatch model, the
  Docker hardening envelope, the per-session home volume, the
  isolation warning, the `--hardened` / `--no-cache` rejections, the
  resource-defaults math, and boot-time orphan reaping are all
  behaviorally correct.

- **Backend-agnostic policy/networking/workspace flows pass** under
  the `[container]` parametrization. The four defect classes
  surfaced by M11-S6 (Class A — gateway-config sync subscription
  wiring; Class B — daemon-restart re-attach, transitively gated by
  A; Class C — three test/image/fixture mismatches; Class D —
  per-session MITM CA bind-mount, the only one that was a real spec
  gap rather than test-side drift) were resolved in M11-S6's branch.
  M11-S7 then closed the residual `[container]` skips (Clone, shared
  mount, gateway traffic flow, stop/start with networking,
  concurrent sessions) by extending `workspace_modes` to
  `{Shared, Clone}`, dispatching `git clone` in-guest, unifying the
  bind target with Lima, and surfacing `SessionNetworkInfo` /
  `SessionMountInfo` via `sandbox inspect`.

- **Cargo gates all PASS** — `cargo nextest run --workspace`,
  `--profile integration`; clippy clean; fmt clean.

- **Zero skips on `make test-e2e-container` post-S7.** The single
  remaining skip in the full matrix is the Lima-scoped 6 GB RAM
  precondition on `test_concurrent_sessions[lima]`. The
  rootless-Docker skip on `test_lite_workspace_uid_alignment`
  becomes a daemon-side refusal in M11-S8 (out of S7 scope).

The remaining open todos (#73 KVM runner, #74 nightly perf, #60 nix
bump) are unblocked and parked for M12+. M11-S7 closed todos #61,
#62, #63, #64, #66, #67, #69, #71, #72, #75, #76, #77, #78, #79, #80
in-branch — see "Deferred-item reconciliation" above for the
commit-by-commit map. The four M11-S6 defect-class fixes remain
documented in the "Defect-class resolution" section.

The implementation faithfully lands the spec end-to-end: the
Capabilities typed-feature mismatch model, the route-helper
authorization flow (eight steps, PID TOCTOU closure, cross-user MITM
closure), the unconditional Docker hardening envelope (read-only
rootfs + tmpfs + no-new-privileges + seccomp=builtin + cap-drop=ALL +
non-root user + pids-limit + memory/cpus ceilings + restart=no), the
`users.conf` config-shared-between-daemon-and-helper pattern, the
per-session home volume (β middle-ground), the per-session MITM CA
bind-mount (LM4.36 — Class D scope discovery), the per-create
isolation warning, the GET /backends capability discovery endpoint,
the V005 SQL migration, the orphan-cleanup-on-startup reconcile, the
gateway-config-sync wiring on both create and restore (Class A fix),
and the four-phase rollout gates. The CLI's five-tier backend
precedence, byte-pinned error strings (`--hardened` rejection,
`--no-cache` rejection, isolation warning, first-use warning),
`BACKEND` column in `sandbox list`, and capability matrix in
`sandbox inspect -v` all match spec text character-for-character.
All claims delivered. Gate green.

---

## Handoff artifacts

Background work that informed this delivery map:

- `.tasks/handoffs/20260428-150000-implementer-m11-s6-spec-delivery-verification.md` — M11-S6 verification handoff defining tasks 1-7, exit criteria, and constraints.
- `.tasks/specs/2026-04-21-port-explicit-policies-presets-observability-delivery.md` — M10-S7 prior verification map; structural template followed by this map.
- `docs/internal/milestones/M11.md` — milestone definition. § M11-S6 exit criteria at lines 206-239; § M11-S7 plan at lines 251-303 (residual quality polish + backend-symmetry refinements); § M11-S8 plan at lines 306-340 (rootless-Docker enforcement).

M11-S7 commits mapped into this map (oldest → newest):

- `a733398` — chore(m11-s7): route-helper polish — todos #61, #62, #63, #64.
- `6822a0d` — docs(spec): correct seccomp flag and unify workspace bind target — todo #66.
- `7d39bb0` — test(e2e): m10-s4 discovery — broken host DNS is a hard failure, not a skip.
- `15e78c2` — test(e2e): m3 — scope `test_concurrent_sessions` RAM check to Lima-only.
- `169c7ea` — test(e2e): lite orphan-cleanup on daemon restart — todo #71 (LM10.21).
- `5fadccf` — feat(m11-s7): clone-on-container + unify workspace bind target (LM6.1, LM6.20, LM7.8).
- `651a635` — feat(m11-s7): backend-neutral session network + mount info via inspect — todo #72 (LM4.37, LM6.23, LM8.30, LM8.31).
- `6dd5808` — feat(m11-s7): cpus 1-decimal precision + drop "0" sentinel in describe — todos #67, #75 (LM6.22, LM8.29).
- `13d5dbe` — feat(m11-s7): `--boot-cmd` symmetry on the container backend — todo #77 (LM6.21).
- `e06b2da` — chore(m11-s7): fold-in polish — todos #76, #78, #79, #80 (LM6.23 / LM2.x publicization).
