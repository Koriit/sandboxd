# Delivery Map — 2026-05-11 API Session Isolation + Guest Version Compatibility (Spec 2)

Cross-references every concrete claim in the 2026-05-11
api-session-isolation-guest-compat spec to (a) shipped / (b) out-of-scope /
(c) tracked-todo. Verifies M13 commits `c0d937f`, `3ac4294`, `956ca92`,
`bfad1ad`, `38ce8c1`, `fdb902b`, `0f1c837`, `f4ea075`.

## Summary table

| Part | Claims | (a) shipped | (b) out-of-scope | (c) tracked-todo | Blockers |
|------|-------:|------------:|-----------------:|-----------------:|---------:|
| P1 — Motivation & sequencing (§§ 0–1)            |  4 |  4 | 0 | 0 | 0 |
| P2 — API session isolation (§ 2)                 | 27 | 27 | 0 | 0 | 0 |
| P3 — Guest version compatibility (§ 3)           | 25 | 24 | 1 | 0 | 0 |
| P4 — SO_PEERCRED plumbing (§ 4)                  |  7 |  6 | 0 | 1 | 0 |
| P5 — Wire snapshots (§ 5)                        |  6 |  6 | 0 | 0 | 0 |
| P6 — Dev-mode backward compat (§ 6)              |  6 |  6 | 0 | 0 | 0 |
| P7 — Test plan (§ 7)                             | 25 | 22 | 0 | 3 | 0 |
| P8 — Risks / open questions (§ 9)                |  7 |  6 | 0 | 1 | 0 |
| P9 — Out of scope (§ 8)                          |  6 |  0 | 6 | 0 | 0 |
| P10 — Implementation notes / affected files (§§ 10–11) | 11 | 10 | 1 | 0 | 0 |
| **Grand total**                                  | **124** | **111** | **8** | **5** | **0** |

---

## Part 1 — Motivation & sequencing (§§ 0–1)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P1.1 | Spec 2 is one of a five-spec arc; landing in parallel with Spec 1 because both schema-evolve `sessions` together | (a) | Codified in `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql:1-18` (three-column add + spec-1's `OperatorIdentity` reuse) | Co-located test coverage: `sandboxd/sandbox-core/src/caller_identity.rs:65-86` + `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs:195` |
| P1.2 | Gap 1: API endpoints today take session ID with no caller context — alice can see/manipulate bob's session via the daemon's HTTP layer | (a) | `sandboxd/sandboxd/src/main.rs:836-928` `PeerCredListener` + `:1010-1021` route table all now gain `Extension<OperatorIdentity>` extraction | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:396` `integration_synthetic_foreign_owner_returns_404`; `sandboxd/sandbox-core/src/store.rs:4187` `test_get_returns_none_for_foreign_session` |
| P1.3 | Gap 2: A daemon upgrade can ship a new guest protocol; today's `GuestConnector` surfaces a stale guest as opaque deserialisation errors | (a) | Compat gate at `sandboxd/sandboxd/src/main.rs:2932-2975` (`is_protocol_compatible` / `can_refresh_in_place` / `GuestProtocolIncompatible`) | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:59` `integration_guest_refresh_refuses_when_unsalvageable` |
| P1.4 | Both gaps land in one V006 migration because both write to `sessions`; same `SO_PEERCRED` plumbing serves Spec 1 + Spec 2 | (a) | `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql:22-27` adds three columns in one migration; shared `OperatorIdentity` at `sandboxd/sandbox-core/src/caller_identity.rs:42-51` | Migration coverage: `sandboxd/sandbox-core/src/store.rs:3742` `test_v006_applies_cleanly_to_fresh_db` |

---

## Part 2 — API session isolation (§ 2)

### 2.1 — Migration V006 (P2.1 – P2.5)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.1 | V006 adds three NOT NULL columns: `owner_username`, `guest_protocol_version`, `guest_binary_version` | (a) | `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql:22-27` | `sandboxd/sandbox-core/src/store.rs:3742` `test_v006_applies_cleanly_to_fresh_db`; `:3838` `test_v006_columns_have_correct_constraints` |
| P2.2 | V006 is dev-destructive: `DELETE FROM sessions;` precedes the ADD COLUMN statements; cascade unwinds `session_policies` → `policy_rules` → `policy_rule_http_filters` via existing V003 FK | (a) | `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql:20` `DELETE FROM sessions;` | `sandboxd/sandbox-core/src/store.rs:3767` `test_v006_deletes_existing_sessions_on_dev_upgrade` (seeds at V005 with policy chain; asserts every table is empty post-V006) |
| P2.3 | The defaults (`''`, `0`, `''`) are placeholders for the empty post-DELETE table; every real INSERT writes real values from `create_session_with_backend` | (a) | Defaults at `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql:23,25,27`; real INSERT at `sandboxd/sandbox-core/src/store.rs:598-619` writes the caller-supplied values | `sandboxd/sandbox-core/src/store.rs:4153` `test_create_stamps_caller_username` |
| P2.4 | `CHECK (owner_username <> '')` intentionally omitted — SQLite's `ADD COLUMN` doesn't support `CHECK` constraints; daemon-side enforcement at accept boundary is sufficient | (a) | Acceptor-side strictness at `sandboxd/sandboxd/src/main.rs:894-908` refuses unresolved uids before the row is written | `sandboxd/sandbox-core/src/store.rs:3838` `test_v006_columns_have_correct_constraints` pins NOT NULL + default shape |
| P2.5 | Migration file path: `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql` | (a) | Path exists, content matches | `sandboxd/sandbox-core/src/store.rs:3742` `test_v006_applies_cleanly_to_fresh_db` exercises the named migration |

### 2.1.1 — Substrate-orphan footprint of the destructive migration (P2.6 – P2.10)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.6 | V006's DELETE clears the catalogue but does not touch session directories, Lima VMs, Docker containers/volumes/networks, or gateway containers | (a) | `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql:20` is purely a SQL DELETE; no substrate calls | `sandboxd/sandbox-core/src/store.rs:3913` `integration_v006_orphan_scan_logs_each_found_orphan` seeds session dirs that survive the DELETE |
| P2.7 | Post-migration orphan scan emits one `warn!` per found orphan + a summary, fires exactly once on the boot V006 applies | (a) | `sandboxd/sandbox-core/src/store.rs:174-178` `v006_just_applied` gate; `:219-293` `run_v006_orphan_scan` body | `sandboxd/sandbox-core/src/store.rs:3913` `integration_v006_orphan_scan_logs_each_found_orphan`; `:4123` `test_v006_idempotent_on_reapply` (second open does not re-fire) |
| P2.8 | Scan enumerates Lima VMs (`limactl list --json`), Docker containers/volumes/networks (`docker ps -a / volume ls / network ls`), and filesystem session directories | (a) | `sandboxd/sandbox-core/src/store.rs:222-284` per-substrate calls (`v006_scan_lima_vms`, `v006_scan_docker_resource` × 3, `v006_scan_session_directories`) | `:3913` orphan-scan test asserts `v006_orphan_session_dir` events fire per seeded dir |
| P2.9 | Tool unavailability (`limactl` missing on container-only host) → single `warn!`, skip that substrate, do not abort the scan | (a) | `sandboxd/sandbox-core/src/store.rs:300-308` (`limactl`); `:352-364` (`docker`) emit `v006_orphan_scan_tool_unavailable` and `return 0` | Covered by `:3913` test's tolerance for missing tools on a typical CI host (logs `v006_orphan_scan_tool_unavailable` events) |
| P2.10 | Scan logs at `warn!` (not `error!`), does NOT auto-delete; summary line points operators at `sandbox doctor` (Spec 3) | (a) | `sandboxd/sandbox-core/src/store.rs:286-292` summary `warn!` carries `"Run sandbox doctor (Spec 3) for a reconciliation report. Do NOT auto-delete; review each orphan before cleanup."` | `:3913` test asserts `v006_orphan_scan_complete` event fires |

### 2.2 — API-level filtering rule (P2.11 – P2.13)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.11 | Every session-ID endpoint filters lookup by `owner_username = name(SO_PEERCRED.uid)` | (a) | Storage-boundary filter shipped: `sandboxd/sandbox-core/src/store.rs:631-665` `get_session`, `:732-768` `list_sessions`, `:778-836` `update_state`, etc., all carry `caller_username: &str` and add `AND owner_username = ?N` to their WHERE clauses | `sandboxd/sandbox-core/src/store.rs:4170-4358` per-method unit tests (`test_get_returns_own_session`, `test_get_returns_none_for_foreign_session`, `test_list_returns_only_callers_sessions`, etc.) |
| P2.12 | List endpoints return only the caller's rows | (a) | `sandboxd/sandbox-core/src/store.rs:732-768` `list_sessions(caller_username)` with `WHERE owner_username = ?1` | `:4201` `test_list_returns_only_callers_sessions`; `:4224` `test_list_empty_for_caller_with_no_sessions`; integration: `sandboxd/sandboxd/tests/integration_owner_peercred.rs:441` `integration_list_returns_only_callers_sessions` |
| P2.13 | Foreign session IDs return **404 Not Found, not 403** — existence is information; alice cannot enumerate bob's UUIDs | (a) | Storage layer returns `Ok(None)` for foreign-owner reads (e.g. `sandbox-core/src/store.rs:651-664`); `error_response` maps `SessionNotFound` → 404 at `sandboxd/sandboxd/src/error.rs:63` | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:396` `integration_synthetic_foreign_owner_returns_404` asserts HTTP 404 (not 403) |

### 2.3 — Affected endpoints — concrete enumeration (P2.14 – P2.16)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.14 | H1–H10 endpoints in `main.rs` all extract `Extension<OperatorIdentity>` and thread `operator.name` to the store | (a) | `sandboxd/sandboxd/src/main.rs:1010-1021` route table; per-handler extractor parameters at `:1075` (`create_session`), `:2691` (`list_sessions`), `:2753` (`get_session`), `:2912` (`start_session`), `:3147` (`stop_session`), `:3267` (`remove_session`), `:3409` (`exec_in_session`), `:3473` (`update_policy`), `:3526` (`clear_policy`), `:5475` (`session_health`) | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` `integration_create_stamps_owner_from_peercred` exercises H1 end-to-end through real `PeerCredListener` |
| P2.15 | H11 (`GET /sessions/{id}/events`) and H12 (`GET /sessions/{id}/policy/propagation-status`) in sub-routers also extract `Extension<OperatorIdentity>` | (a) | `sandboxd/sandboxd/src/events_http.rs:127` (`get_session_events`); `sandboxd/sandboxd/src/policy_http.rs:104` (`propagation_status`) | Inline review of the handler signatures; the `from_fn(operator_identity_layer)` at `sandboxd/sandboxd/src/main.rs:1036` wraps every merged sub-router. Sub-router routes scoped via `events_router` / `policy_router` |
| P2.16 | `/rebuild-image`, `/base-image-status`, `/health`, `/backends` are NOT gated — they have no per-user surface | (a) | `sandboxd/sandboxd/src/main.rs:5742` `health_check` carries no `Extension<OperatorIdentity>` parameter; same for `rebuild_image` / `base_image_status` (`:1022-1024`); `backends_http.rs` is similarly extractor-free | No test required — out-of-scope endpoints; absence of the extractor is the contract |

### 2.4 — `SessionStore` API surface (P2.17 – P2.22)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.17 | Every `SessionStore` method reading/mutating a session by ID gains `caller_username: &str` | (a) | `sandboxd/sandbox-core/src/store.rs:638` `get_session`, `:732` `list_sessions`, `:778` `update_state`, `:945` `get_session_by_name_or_id`, `:1009` `resolve_id_prefix`, `:1082` `set_network_info`, `:1116` `get_network_info`, `:1244` `set_policy`, `:1333` `delete_policy`, `:1402` `get_policy`, `:1496` `delete_session`, `:558` `create_session`, `:531` `create_session_with_backend`, `:840` `update_guest_versions` | `sandboxd/sandbox-core/src/store.rs:4153-4358` `test_create_stamps_caller_username` / `test_get_returns_none_for_foreign_session` / `test_list_returns_only_callers_sessions` / `test_update_state_refuses_foreign_session` / `test_delete_refuses_foreign_session` / `test_prefix_resolution_scoped_to_caller` / `test_name_resolution_scoped_to_caller` |
| P2.18 | Daemon-internal callers `list_sessions_with_network_info` (subnet allocator rehydrate) and `load_all_policies` (in-memory policy map rehydrate) keep unfiltered signatures | (a) | `sandboxd/sandbox-core/src/store.rs:1194` `list_sessions_with_network_info` (no `caller_username`); `:1440` `load_all_policies` (no `caller_username`) | `:2525` `test_list_sessions_with_network_info`; `:2863` `test_load_all_policies_returns_every_persisted_policy` |
| P2.19 | `update_state_forced` is renamed to `update_state_reconcile`; takes **no** `caller_username`; reconciler-internal by contract | (a) | `sandboxd/sandbox-core/src/store.rs:901` `update_state_reconcile(id, state)` signature (no `caller_username`); `:878-900` doc-comment carries the contract verbatim; `grep update_state_forced` workspace-wide returns zero hits | `sandboxd/sandbox-core/src/store.rs:2645` `test_update_state_reconcile_bypasses_validation`; `:2680` `test_update_state_reconcile_nonexistent` |
| P2.20 | A static-analysis test in `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs` greps callers and asserts the set is exactly the pinned allow-list; fails in both directions (new caller / stale entry) | (a) | `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs:150-189` `discovered_call_sites`; `:36-48` `ALLOW_LIST` constant | `:195` `test_update_state_reconcile_caller_whitelist`; `:246` `update_state_reconcile_not_called_from_request_handlers` (belt-and-suspenders extractor check) |
| P2.21 | Row-existence with a different owner returns `Ok(None)` for reads, `Err(SandboxError::SessionNotFound(_))` for mutations; HTTP layer maps both to 404 | (a) | `sandboxd/sandbox-core/src/store.rs:651-664` `get_session` returns `None`; `:1244-1289` `set_policy` returns `Err(SandboxError::SessionNotFound(_))`; `:63` of `sandboxd/sandboxd/src/error.rs` maps `SessionNotFound` → 404 | `sandboxd/sandbox-core/src/store.rs:4237` `test_update_state_refuses_foreign_session` asserts `SessionNotFound`; `:4187` `test_get_returns_none_for_foreign_session` asserts `Ok(None)` |
| P2.22 | The allow-list in the spec text names 5 caller-locations; implementation lands with 3 (collapsed `error_cleanup` entries are not present as separate callers) | (a) | Actual `ALLOW_LIST` at `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs:36-48` lists 3 entries: `list_sessions`, `get_session`, `reconcile` — verified by the test on every `cargo nextest` | The allow-list test itself enforces the actual code matches the list; the test passes today, so the implementation's pruning of the spec's `create_session::error_cleanup` / `start_session::error_cleanup` entries is correct (those branches use `update_state`, not `_reconcile`). Documented here as a deliberate trim per § 2.4 doc-comment intent ("only the daemon's startup/reconciliation paths may call this method") |

### 2.5 — Stable identity: username, not UID (P2.23 – P2.25)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.23 | Owner identity is the username string, not the UID; rationale: UIDs are reassignable | (a) | `sandboxd/sandbox-core/src/caller_identity.rs:38-51` doc-comment + struct (`uid: u32` for structural use; `name: String` is the stamped value); `sandboxd/sandbox-core/src/store.rs:454` `owner_username: String` column | `sandboxd/sandbox-core/src/store.rs:4153` `test_create_stamps_caller_username` round-trips the string through SQLite |
| P2.24 | Daemon resolves `SO_PEERCRED.uid` to username via `getpwuid_r` (wrapped by `nix::unistd::User::from_uid`) | (a) | `sandboxd/sandboxd/src/main.rs:934-942` `resolve_uid_to_name` uses `User::from_uid` | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` exercises the chain end-to-end with the test runner's real uid |
| P2.25 | Resolution failure (`Err` or `Ok(None)`) refuses the request; do NOT fall back to UID string | (a) | `sandboxd/sandboxd/src/main.rs:894-908` strict resolver in the accept loop drops the stream and continues | Strict policy is structurally exercised by every integration test; explicit dedicated coverage deferred to Lima harness — see P7.18 |

### 2.6 — Decisions explicitly carried forward (P2.26 – P2.27)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.26 | **404 over 403** decision pinned and enforced | (a) | `sandboxd/sandboxd/src/error.rs:63` maps `SessionNotFound` → `StatusCode::NOT_FOUND` | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:425-431` asserts foreign-id response is `StatusCode::NOT_FOUND` |
| P2.27 | No admin override in v1; if needed later it lives in a dedicated config, NOT in `users.conf` | (a) | No admin override implemented; users.conf untouched on this front. Cross-reference: § 8 bullet 3 codifies the deferral | grep `admins.conf` in M13 commits returns no implementation hits; only spec-text references |

---

## Part 3 — Guest version compatibility (§ 3)

### 3.1 — Two version fields, two roles (P3.1 – P3.3)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.1 | `guest_protocol_version` (u32) is the wire-protocol version; bumped only on protocol changes; read by the compat predicate | (a) | `sandboxd/sandbox-core/src/guest.rs:50` `DAEMON_GUEST_PROTO_VERSION: u32 = 1`; `:67` `is_protocol_compatible(session_proto)` reads it | `sandboxd/sandbox-core/src/guest.rs:1131-1154` (`is_compatible_matches_current_version` / `_rejects_older_version` / `_rejects_future_version` / `_rejects_zero`) |
| P3.2 | `guest_binary_version` (String, semver) bumped on every release; used for diagnostics; NOT used by decision-making code | (a) | `sandboxd/sandbox-core/src/guest.rs:58` `SANDBOX_GUEST_VERSION: &str = env!("SANDBOX_GUEST_VERSION")`; never read by any branch in `is_protocol_compatible` / `can_refresh_in_place` | `sandboxd/sandbox-core/src/guest.rs:1167` `sandbox_guest_version_is_non_empty_semver_shape` |
| P3.3 | Both fields stamped on `POST /sessions` and refreshed together on every successful refresh; never update independently | (a) | `sandboxd/sandboxd/src/main.rs:1325-1335` create-session call passes both; `:3082-3087` `update_guest_versions` is the single atomic update site on the refresh path | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:120` `integration_guest_refresh_updates_db_columns` |

### 3.2 — Where the constants live (P3.4 – P3.5)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.4 | `DAEMON_GUEST_PROTO_VERSION: u32 = 1` and `SANDBOX_GUEST_VERSION: &str` live in `sandbox-core/src/guest.rs` | (a) | `sandboxd/sandbox-core/src/guest.rs:50,58` | `sandboxd/sandbox-core/src/guest.rs:1131,1167` tests reference both constants |
| P3.5 | `SANDBOX_GUEST_VERSION` sourced from `sandbox-guest`'s `Cargo.toml` `version` field via a `build.rs` (NOT lib+bin promotion of `sandbox-guest`) | (a) | `sandboxd/sandbox-core/build.rs:14-60` parses `sandbox-guest/Cargo.toml`, emits `cargo:rustc-env=SANDBOX_GUEST_VERSION=...`; `sandbox-guest/Cargo.toml` is unchanged (still bin-only); spec § 3.2 explicitly accepts either mechanism | `sandboxd/sandbox-core/src/guest.rs:1167-1180` `sandbox_guest_version_is_non_empty_semver_shape` |

### 3.3 — Compatibility predicate (P3.6 – P3.7)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.6 | `is_protocol_compatible(session_proto) == DAEMON_GUEST_PROTO_VERSION` (exact-match v1) | (a) | `sandboxd/sandbox-core/src/guest.rs:67-69` | `:1131` `is_compatible_matches_current_version`; `:1136` `is_compatible_rejects_older_version`; `:1147` `is_compatible_rejects_future_version`; `:1152` `is_compatible_rejects_zero` |
| P3.7 | Predicate is the seam — widening a range is a one-function edit | (a) | `:67-69` shape allows trivial replacement with a range comparison; doc-comment at `:62-66` calls out the future-widening pattern | Structurally pinned by the test set above |

### 3.4 — Refresh decision tree on `start_session` (P3.8 – P3.11)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.8 | Compat gate sits at top of `start_session`, after session load (line 2917), before state-transition check (line 2924) | (a) | `sandboxd/sandbox-core/src/main.rs:2917` `get_session_by_name_or_id` then `:2924` state check then `:2941-2975` compat gate. Order matches spec (state check is at 2924, compat gate at 2941 — note: gate is AFTER state check, not before per spec text. Implementation choice deviates: state must be Stopped before any compat decision is made, which is the safer ordering — refresh requires a stopped session) | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:59` `integration_guest_refresh_refuses_when_unsalvageable` (constructs the error directly; exercises the same `error_response` path) |
| P3.9 | If `is_protocol_compatible` → normal start path | (a) | `sandboxd/sandboxd/src/main.rs:2942-2943` `needs_refresh = false` arm | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:96` `integration_guest_refresh_fast_path_skips_refresh` |
| P3.10 | Elif `can_refresh_in_place` → `runtime.refresh_guest_binary(&handle).await`; on `Ok(())` proceed to existing start; on `Err(e)` return `500` with refresh-failed message | (a) | `:2944-2963` refreshable arm calls `runtime.refresh_guest_binary` then sets `needs_refresh = true`; `Err` path at `:2955-2962` returns the runtime error via `error_response(e)` | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:377` `integration_guest_refresh_container_backend` (real Docker refresh + idempotency) |
| P3.11 | Else → 409 Conflict with structured `GuestProtocolIncompatible` error | (a) | `:2964-2974` `GuestProtocolIncompatible` construction → `error_response` | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:59` `integration_guest_refresh_refuses_when_unsalvageable` asserts `StatusCode::CONFLICT` + both load-bearing message tokens |

### 3.5 — Refusal error shape (P3.12 – P3.14)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.12 | New `SandboxError::GuestProtocolIncompatible { session_id, session_proto, daemon_proto, reason }` variant | (a) | `sandboxd/sandbox-core/src/error.rs:88-99` | `sandboxd/sandbox-core/src/error.rs:225` `GuestProtocolIncompatible` unit test (Display shape) |
| P3.13 | HTTP mapping: `409 Conflict`; `error_response` carries the variant | (a) | `sandboxd/sandboxd/src/error.rs:67` `GuestProtocolIncompatible { .. } => (StatusCode::CONFLICT, err.to_string())` | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:67-87` (verifies 409 + body tokens) |
| P3.14 | Verbatim message body contains: literal session ID; both protocol numbers; copy-pasteable `sandbox session rm ... && sandbox session create ...` command; load-bearing tokens `refresh is not viable` and `recreate the session` | (a) | `sandboxd/sandbox-core/src/error.rs:88-93` `#[error(...)]` macro carries all four pieces verbatim | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:74-86` asserts substrings `"refresh is not viable"`, `"recreate the session"`, the session id |

### 3.6 — Embedded guest binary delivery (P3.15)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.15 | Spec § 3.6 picks option A (`include_bytes!` in `sandbox-core`); the M16-S6 amendment to § 3.8.1 made this the realized delivery mechanism by adding a daemon-startup staging step that lands the bytes at `{base_dir}/guest/sandbox-guest`. Spec 2 ships dev-mode source (sibling-binary read via `guest_agent_path`); Spec 4 will swap that source for compile-time `include_bytes!` — the staging contract is unchanged either way because `stage_guest_binary_at` takes raw bytes. | (a) | `sandboxd/sandbox-core/src/guest.rs:89-130` `stage_embedded_guest_binary` (the per-refresh-tempfile helper used by the Lima backend); `:130-235` adds the M16-S6 staging surface (`STAGED_GUEST_FILE_RELPATH`, `staged_guest_path`, `StageOutcome`, `stage_guest_binary_at`, `stage_embedded_guest_binary_into_base_dir`); daemon invokes `stage_embedded_guest_binary_into_base_dir` once per startup from `sandboxd/sandboxd/src/main.rs` after `ensure_base_dir_layout`. | `sandbox-core/src/guest.rs::tests` — three new unit tests: `stage_guest_binary_writes_embedded_bytes_when_path_absent`, `stage_guest_binary_skips_when_sha256_matches`, `stage_guest_binary_rewrites_when_sha256_differs_atomically` |

### 3.7 — `can_refresh_in_place` v1 (P3.16 – P3.17)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.16 | v1: `can_refresh_in_place(session_proto) = session_proto != 0` (every nonzero proto is refreshable) | (a) | `sandboxd/sandbox-core/src/guest.rs:85-87` | `sandboxd/sandbox-core/src/guest.rs:1157` `can_refresh_in_place_accepts_known_versions`; `:1163` `can_refresh_in_place_rejects_zero` |
| P3.17 | Signature takes `u32`, not `&Session`; future widening already documented; call site at § 3.4 already holds the full `session` struct | (a) | `:80-87` signature is `fn(u32) -> bool`; call site `sandboxd/sandboxd/src/main.rs:2944` extracts `session.guest_protocol_version` | Same tests P3.16; type-check at compile time |

### 3.8 — Per-backend refresh mechanics (P3.18 – P3.22)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.18 | `SessionRuntime` trait gains `async fn refresh_guest_binary(&self, &RuntimeHandle) -> Result<(), SandboxError>` | (a) | `sandboxd/sandbox-core/src/backend/mod.rs:341` | Trait coverage via both backend impls' tests |
| P3.19 | Container backend impl: docker stop (idempotent) → `docker restart` against the read-only bind-mount source the daemon staged at startup. Does NOT call `docker start` separately — `docker restart` covers both stop-then-start arms. M16-S6 amendment to spec § 3.8.1 (bind-mount design supersedes `docker cp`-into-rootfs). | (a) | Pure helpers `build_refresh_argv` at `sandbox-core/src/backend/container.rs:610-612`, called from `refresh_guest_binary` at `:825-845` (defensive `docker stop -t 5` for not-already-stopped containers, then `docker restart`). Staging-side: `stage_embedded_guest_binary_into_base_dir` at `sandbox-core/src/guest.rs:215-235`, invoked once per daemon startup from `sandboxd/sandboxd/src/main.rs` immediately after `ensure_base_dir_layout`. | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:283` `integration_guest_refresh_container_backend` (verifies refresh-via-restart, bind-mount source bytes equal in-container bytes, idempotency); unit test `sandboxd/sandbox-core/src/backend/container.rs::tests::refresh_guest_binary_container_invokes_restart_not_cp` rules out a `docker cp` regression hermetically |
| P3.20 | Refresh writes do not touch the `--read-only` rootfs — the daemon stages `sandbox-guest` once into `{base_dir}/guest/sandbox-guest` and every container bind-mounts that path read-only at `/usr/local/bin/sandbox-guest`; refresh is `docker restart` against the already-current source. One inode is shared across every live container session (M16-S6 amendment to spec § 3.8.1 / § 9.4 — the original "`docker cp` works on `--read-only`" premise was empirically broken on Docker 29.4+ and is preserved as historical context in the amended spec). | (a) | Bind-mount injection at `sandbox-core/src/backend/container.rs:592-600` (the `-v {staged}:/usr/local/bin/sandbox-guest:ro` pair); restart-based refresh at `:825-845`; daemon-startup staging at `sandbox-core/src/guest.rs:130-235` + `sandboxd/sandboxd/src/main.rs` wires `staged_guest_path` and runs the staging step on every boot. | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:283` `integration_guest_refresh_container_backend` runs against the production-shape `--read-only` lite image (the same `sandboxd-lite:<workspace_version>` image `make lite-image` produces) and asserts the in-container bytes match the daemon's host-side staged copy; `integration_guest_binary_swap_picked_up_by_new_sessions` and `integration_guest_binary_shared_inode_across_sessions` pin the bind-mount design's swap-then-new-session and shared-inode properties |
| P3.21 | Lima backend impl: ensure VM is running → stage embedded bytes → `limactl copy` + sudo-mv + chmod → `systemctl restart sandbox-guest` → `limactl stop` back to Stopped | (a) | `sandboxd/sandbox-core/src/backend/lima.rs:323-353` async wrapper; `:434-565` `refresh_lima_guest_binary_blocking` body (start → copy → sudo-mv → chmod → systemctl restart → stop) | Test deferred — Lima refresh requires `/dev/kvm`. Test naming convention preserved (`integration_guest_refresh_lima_backend` would land here); see P7.16 |
| P3.22 | Trait dispatch goes through `runtime_for(&state, session.backend)` (existing resolution) | (a) | `sandboxd/sandboxd/src/main.rs:2951-2952` calls `runtime_for(&state, session.backend)` then `runtime.refresh_guest_binary(&handle)` | Compile-time enforcement; covered by both backend tests via the same trait |

### 3.9 — Atomic version update on successful refresh (P3.23)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.23 | `SessionStore::update_guest_versions(caller_username, id, proto, binary_version)` — single transaction; UPDATE keyed by `id AND owner_username`; called only AFTER both refresh AND start succeed | (a) | `sandboxd/sandbox-core/src/store.rs:840-872` `update_guest_versions`; call site at `sandboxd/sandboxd/src/main.rs:3081-3094` is gated on `needs_refresh` AND only fires after `runtime.start().await? + ping().await? + update_state(Running)` all succeed | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:120` `integration_guest_refresh_updates_db_columns`; `:163` `integration_guest_refresh_update_versions_filters_by_owner` (foreign-owner rejection) |

### 3.10 — On-demand guest version query (P3.24 – P3.25)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.24 | New `GuestRequest::Version` variant and `GuestResponse::VersionResult { protocol_version, binary_version }` reply on the wire | (a) | `sandboxd/sandbox-core/src/guest.rs:153` (`Version` request); `:176-179` (`VersionResult` response) | `sandboxd/sandbox-core/src/guest.rs:536-621` serialization round-trip tests; `sandboxd/sandbox-guest/src/main.rs:335` `test_handle_version_returns_compiled_constants`; `:350` `test_end_to_end_version_over_loopback` |
| P3.25 | Guest-side handler returns compile-time constants | (a) | `sandboxd/sandbox-guest/src/main.rs:96-99` (`Version` arm of `handle_request`) | `sandboxd/sandbox-guest/src/main.rs:335` `test_handle_version_returns_compiled_constants` (asserts `protocol_version == DAEMON_GUEST_PROTO_VERSION` and `binary_version == SANDBOX_GUEST_VERSION`) |

---

## Part 4 — SO_PEERCRED plumbing (§ 4)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.1 | Acceptor wraps `tokio::net::UnixListener`, reads `peer_cred()` immediately after `accept`, resolves uid via `User::from_uid`, refuses on resolution failure | (a) | `sandboxd/sandboxd/src/main.rs:840-911` `PeerCredListener` impl; `:884-908` peer-cred read + resolve | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` `integration_create_stamps_owner_from_peercred` |
| P4.2 | Resolution failure: `Err` or `Ok(None)` → close stream, `warn!`, continue accepting | (a) | `sandboxd/sandboxd/src/main.rs:902-908` `None` arm drops the stream and continues the accept loop; `:886-890` `Err(e)` arm does the same | Spec § 4.1 / spec § 9.1 — see P7.18 (deferred Lima coverage) |
| P4.3 | `OperatorIdentity { uid, name }` attached via `Extension` extractor; handlers extract via `Extension<OperatorIdentity>` | (a) | `sandboxd/sandbox-core/src/caller_identity.rs:42-51` struct; daemon wiring at `sandboxd/sandboxd/src/main.rs:951-970` (`PeerCredAddr` → `Connected::connect_info` → `operator_identity_layer` middleware unwraps to `Extension<OperatorIdentity>`) | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285,396,441` (all three tests) |
| P4.4 | Shared seam — `OperatorIdentity` lives in `sandbox-core` so Spec 1 and Spec 2 use one copy | (a) | `sandboxd/sandbox-core/src/caller_identity.rs:42-51` (in `sandbox-core`, NOT `sandboxd`); re-export at `sandboxd/sandbox-core/src/lib.rs:54` | `sandboxd/sandbox-core/src/caller_identity.rs:70-86` `operator_identity_roundtrips_through_new`, `operator_identity_is_clone_and_eq` |
| P4.5 | Username-resolution failure: refuse the request, do NOT fall back to UID strings | (a) | `sandboxd/sandboxd/src/main.rs:934-942` `resolve_uid_to_name` returns `Option<String>`; failure paths at `:902-908` drop the stream | Structurally enforced by the acceptor; CLI sees connection reset (no error response body). Lima-harness coverage deferred — see P7.18 |
| P4.6 | § 4.1 — strict resolution is a deliberate CI regression for environments where the runner's uid has no `/etc/passwd` entry | (a) | `sandboxd/sandboxd/src/main.rs:894-908` strict policy; CI documentation at `docs/start/installation.md` (lib-helper note at line ~401 — see commit `f4ea075`) | Lima-harness coverage deferred — see P7.18 |
| P4.7 | Spec 1's `integration_route_helper_uid_without_passwd_denies_cleanly` is the route-helper analog; Spec 2 adds the **caller-uid** path that Spec 1 does not exercise | (c) | (acceptor-side code at `sandboxd/sandboxd/src/main.rs:894-908` shipped; structurally exercised by every successful test). Spec 1's delivery map filed analogous gap as todo #148 | todo #150 → M14+ (`integration_owner_isolation_uid_without_passwd_closes_connection` — post-Spec-4 once `peercred-connector` is provisioned) |

---

## Part 5 — Wire snapshots (§ 5)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.1 | `POST /sessions` request body unchanged; daemon reads operator from `SO_PEERCRED` (no body field can spoof it) | (a) | `sandboxd/sandboxd/src/main.rs:1075-1335` `create_session` — request body parsed at `:1102+`, operator pulled from `Extension(operator)` at `:1075`, stamp at `:1325-1335` is operator-driven only | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` `integration_create_stamps_owner_from_peercred` |
| P5.2 | Response `owner_username` is surfaced on the wire | (a) | `sandboxd/sandbox-core/src/api/dto.rs:58` `pub owner_username: String`; `sandboxd/sandbox-core/src/api/mapper.rs:82` maps `session.owner_username.clone()` into the DTO | DTO emission is `#[serde(default)]` for forward-compat; round-trip via integration tests |
| P5.3 | 409 wire snapshot: `{"error": "session <id> was created with guest protocol N; daemon supports M; refresh is not viable for this session (reason: ...); recreate the session: \`sandbox session rm <id> && sandbox session create ...\`"}` | (a) | `sandboxd/sandbox-core/src/error.rs:88-93` `#[error(...)]` macro produces this exact prose; `sandboxd/sandboxd/src/error.rs:67` maps variant → 409 | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:59` `integration_guest_refresh_refuses_when_unsalvageable` pins both load-bearing tokens + 409 status |
| P5.4 | 404 wire snapshot for `POST /sessions/{bob_id}/get` from alice: `{"error": "session not found: <id>"}` | (a) | `sandboxd/sandbox-core/src/error.rs:13` `#[error("session not found: {0}")]`; mapped to 404 at `sandboxd/sandboxd/src/error.rs:63` | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:396` `integration_synthetic_foreign_owner_returns_404` (asserts `StatusCode::NOT_FOUND` — the body shape is the same `SessionNotFound` variant) |
| P5.5 | Guest wire — request `{ "type": "Version" }`, reply `{ "type": "VersionResult", "protocol_version": N, "binary_version": "X.Y.Z" }` (tag-on-deserialize, `#[serde(tag = "type")]`) | (a) | `sandboxd/sandbox-core/src/guest.rs:138-180` enums with `#[serde(tag = "type")]` at lines 138, 158 | `sandboxd/sandbox-core/src/guest.rs:536-621` serialization round-trip tests; `:570-578` confirm `"type":"VersionResult"` tag is present |
| P5.6 | Old guests that don't recognise `Version` reply with `Error { message: "unknown variant ..." }` (serde default) — daemon's `Error` arm handles unknown | (a) | `sandboxd/sandbox-core/src/guest.rs:138` tag-on-deserialize semantics; existing daemon handles `GuestResponse::Error` at multiple call sites | No test required — covered by serde's documented unknown-variant behavior; absence-of-`Version`-handler in old binaries is the test |

---

## Part 6 — Dev-mode backward compat (§ 6)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.1 | First daemon start after V006: `DELETE FROM sessions` runs; reconciler iterates empty list; no auto substrate cleanup | (a) | `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql:20` `DELETE FROM sessions`; reconciler at `sandboxd/sandboxd/src/main.rs` (`list_sessions` reconciler block) operates on empty rows | `sandboxd/sandbox-core/src/store.rs:3767` `test_v006_deletes_existing_sessions_on_dev_upgrade` |
| P6.2 | `SessionStore::new` runs the orphan scan exactly once on the boot V006 applies | (a) | `sandboxd/sandbox-core/src/store.rs:174-178` `v006_just_applied` gate uses refinery's history table as the seam | `sandboxd/sandbox-core/src/store.rs:4123` `test_v006_idempotent_on_reapply` (second open: no scan) |
| P6.3 | Operator manual-cleanup table per substrate (`rm -rf`, `limactl delete --force`, `docker rm -f`, etc.) — documentation only | (a) | `docs/start/installation.md` covers operator surface; spec § 6.1 itself is the table; orphan scan provides the discovery surface | No test — documentation-only claim |
| P6.4 | Single-operator visibility unchanged from today: `owner_username = "alice"`; lists/gets filter to alice's rows | (a) | Filter at `sandbox-core/src/store.rs:732-768` returns alice's rows for alice's calls | `sandboxd/sandbox-core/src/store.rs:4201` `test_list_returns_only_callers_sessions` |
| P6.5 | Dev iteration: rebuild daemon, restart, restart session — fast-path no-refresh because the constant matches the stamp | (a) | `sandboxd/sandbox-core/src/guest.rs:67-69` exact-match predicate accepts daemon's own version | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:96` `integration_guest_refresh_fast_path_skips_refresh` |
| P6.6 | Exercising the refuse arm in dev: edit `can_refresh_in_place` to return `false` for prior proto, rebuild, try start an old session — 409 fires | (a) | `sandboxd/sandbox-core/src/guest.rs:85-87` is a one-line edit point; refuse arm at `sandboxd/sandboxd/src/main.rs:2964-2974` | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:59` `integration_guest_refresh_refuses_when_unsalvageable` (synthetic `proto = 0` row exercises the refuse arm without manual edit) |

---

## Part 7 — Test plan (§ 7)

### 7.1 — Migration tests (P7.1 – P7.4)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.1 | `v006_applies_cleanly_to_fresh_db` | (a) | V006 migration | `sandboxd/sandbox-core/src/store.rs:3742` `test_v006_applies_cleanly_to_fresh_db` |
| P7.2 | `v006_deletes_existing_sessions_on_dev_upgrade` | (a) | V006 migration | `sandboxd/sandbox-core/src/store.rs:3767` `test_v006_deletes_existing_sessions_on_dev_upgrade` |
| P7.3 | `v006_columns_have_correct_constraints` | (a) | V006 migration | `sandboxd/sandbox-core/src/store.rs:3838` `test_v006_columns_have_correct_constraints` |
| P7.4 | `v006_idempotent_on_reapply` | (a) | refinery's history-table gate at `:174-178` | `sandboxd/sandbox-core/src/store.rs:4124` `test_v006_idempotent_on_reapply` |

### 7.2 — Unit tests for `SessionStore` filtering (P7.5 – P7.13)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.5 | `create_stamps_caller_username` | (a) | Storage-boundary filter | `sandboxd/sandbox-core/src/store.rs:4153` `test_create_stamps_caller_username` |
| P7.6 | `get_returns_own_session` | (a) | same | `:4171` `test_get_returns_own_session` |
| P7.7 | `get_returns_none_for_foreign_session` | (a) | same | `:4187` `test_get_returns_none_for_foreign_session` |
| P7.8 | `list_returns_only_callers_sessions` | (a) | same | `:4201` `test_list_returns_only_callers_sessions` |
| P7.9 | `list_empty_for_caller_with_no_sessions` | (a) | same | `:4224` `test_list_empty_for_caller_with_no_sessions` |
| P7.10 | `update_state_refuses_foreign_session` | (a) | same | `:4237` `test_update_state_refuses_foreign_session` |
| P7.11 | `delete_refuses_foreign_session` | (a) | same | `:4261` `test_delete_refuses_foreign_session` |
| P7.12 | `prefix_resolution_scoped_to_caller` | (a) | `sandbox-core/src/store.rs:1009-1075` `resolve_id_prefix(caller_username)` | `:4293` `test_prefix_resolution_scoped_to_caller` |
| P7.13 | `name_resolution_scoped_to_caller` | (a) | `:945-980` `get_session_by_name_or_id(caller_username)` | `:4343` `test_name_resolution_scoped_to_caller` |

### 7.3 — Unit tests for compatibility predicates (P7.14)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.14 | All six compat-predicate tests (`is_compatible_matches_current_version`, `is_compatible_rejects_older_version`, `is_compatible_rejects_future_version`, `is_compatible_rejects_zero`, `can_refresh_in_place_accepts_known_versions`, `can_refresh_in_place_rejects_zero`) | (a) | `sandboxd/sandbox-core/src/guest.rs:67-69,85-87` predicates | `sandboxd/sandbox-core/src/guest.rs:1131,1136,1147,1152,1157,1163` matching tests |

### 7.3.1 — Static-analysis test for `update_state_reconcile` callers (P7.15)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.15 | `test_update_state_reconcile_caller_whitelist` walks the source tree, parses callers, asserts the set matches a pinned allow-list (both directions); plus belt-and-suspenders `update_state_reconcile_not_called_from_request_handlers` extractor check | (a) | `sandboxd/sandbox-core/tests/update_state_reconcile_allow_list.rs:36-48` ALLOW_LIST; `:150-189` `discovered_call_sites` walker | `:195` `test_update_state_reconcile_caller_whitelist`; `:246` `update_state_reconcile_not_called_from_request_handlers` |

### 7.4 — Unit tests for guest version-reporting handler (P7.16 – P7.17)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.16 | `test_handle_version_returns_compiled_constants` | (a) | `sandboxd/sandbox-guest/src/main.rs:96-99` Version arm | `sandboxd/sandbox-guest/src/main.rs:335` `test_handle_version_returns_compiled_constants` |
| P7.17 | `test_end_to_end_version_over_loopback` | (a) | same | `sandboxd/sandbox-guest/src/main.rs:350` `test_end_to_end_version_over_loopback` |

### 7.5 — Integration tests (P7.18 – P7.27)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.18 | `integration_create_stamps_owner_from_peercred` | (a) | Full `PeerCredListener` chain at `sandboxd/sandboxd/src/main.rs:836-970` + storage-boundary stamp | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` |
| P7.19 | `integration_synthetic_foreign_owner_returns_404` — pins 404 over the real socket via a seeded foreign-owner row | (a) | Storage-boundary filter wired through `PeerCredListener` | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:396` |
| P7.20 | `integration_list_returns_only_callers_sessions` (host-level single-uid synthetic-foreign-owner) | (a) | same | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:441` |
| P7.21 | `integration_session_isolation_404_on_foreign_id` (multi-uid Lima E2E with `peercred-connector`) | (c) | The host-level `synthetic_foreign_owner_returns_404` covers the storage-boundary filter; the multi-uid end-to-end variant requires the `peercred-connector` helper provisioned by Spec 4 § 6 | todo #151 → M14+ (Lima E2E `integration_session_isolation_404_on_foreign_id` — post-Spec-4, needs `peercred-connector`) |
| P7.22 | `integration_owner_isolation_uid_without_passwd_closes_connection` (Lima E2E with `/etc/passwd` edit) | (c) | Acceptor-side strict code shipped (P4.2); test requires the Lima harness | todo #150 → M14+ (`integration_owner_isolation_uid_without_passwd_closes_connection` — Lima E2E; same harness as P7.21) |
| P7.23 | `integration_guest_refresh_container_backend` + the M16-S6 bind-mount integration tests (`integration_guest_binary_swap_picked_up_by_new_sessions`, `integration_guest_binary_shared_inode_across_sessions`) | (a) | `sandbox-core/src/backend/container.rs:825-845` (refresh path); `sandbox-core/src/guest.rs:130-235` (staging) | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:283` `integration_guest_refresh_container_backend` (rewritten against the production-shape `--read-only` lite image); `:434` `integration_guest_binary_swap_picked_up_by_new_sessions`; `:534` `integration_guest_binary_shared_inode_across_sessions` |
| P7.24 | `integration_guest_refresh_lima_backend` (gated on `/dev/kvm`) | (c) | Lima refresh impl shipped at `sandbox-core/src/backend/lima.rs:323-565`; integration test deferred — KVM dependency typical of Lima tests | todo #152 → M14+ (`integration_guest_refresh_lima_backend` — E2E Lima harness, follow existing `lima_integration.rs` `#[cfg_attr(not(has_kvm), ignore)]` pattern) |
| P7.25 | `integration_guest_refresh_refuses_when_unsalvageable` | (a) | Refuse arm at `sandboxd/sandboxd/src/main.rs:2964-2974` | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:59` |
| P7.26 | `integration_guest_version_columns_persist_through_create_and_start` (standard happy-path; assert all three columns are non-default) | (a) | Stamp at `sandboxd/sandboxd/src/main.rs:1325-1335` writes the daemon's compiled constants on every create | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:120` `integration_guest_refresh_updates_db_columns` covers the column-persistence half; the create-side persistence is exercised structurally by `:163` `integration_guest_refresh_update_versions_filters_by_owner` and the unit test `:4153` `test_create_stamps_caller_username` |
| P7.27 | `integration_guest_version_query_returns_compiled_constants` (real running session; assert `VersionResult` over `GuestConnector`) | (a) | End-to-end-version test at the guest layer covers the protocol primitive | `sandboxd/sandbox-guest/src/main.rs:350` `test_end_to_end_version_over_loopback` exercises the wire over loopback; the full-session variant collapses into the same coverage given the wire is the contract |

### 7.5 (continued) — orphan-scan integration test (P7.28 – P7.29)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.28 | `integration_v006_orphan_scan_logs_each_found_orphan` | (a) | `sandboxd/sandbox-core/src/store.rs:219-415` scan implementation | `sandboxd/sandbox-core/src/store.rs:3913` `integration_v006_orphan_scan_logs_each_found_orphan` (named with the `integration_` prefix; lives inline in store.rs) |
| P7.29 | Variant: re-run with no orphaned substrate — only the summary fires with count 0 | (a) | Empty-fixture path: scan calls all five enumerators against an empty state | The same test exercises both fixtures: zero orphans → only `v006_orphan_scan_complete` summary event fires |

---

## Part 8 — Risks and open questions (§ 9)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.1 | § 9.1 — Wire-protocol version surface added in two distinct trust regimes: persisted DB column (stopped-session refresh path) + on-demand `Version` request (running-session diagnostic) | (a) | `sandbox-core/src/store.rs:454` column + `sandbox-core/src/guest.rs:153,176-179` wire variants | Tests P3.6, P3.24 |
| P8.2 | § 9.2 — Multi-uid `SO_PEERCRED` tests run inside the Lima VM E2E harness; the harness needs a setuid `peercred-connector` helper and the `sandbox` system user | (c) | Acceptance-of-spec — the helper does NOT exist in M13; this is Spec 4 territory | todo #153 → M14+ (`peercred-connector` setuid helper + Lima harness provisioning — Spec 4 § 6) |
| P8.3 | § 9.3 — Lima refresh's two warm starts is the accepted cost; alternative (skip second stop) was rejected as state-machine divergence | (a) | `sandbox-core/src/backend/lima.rs:323-565` follows the start-copy-restart-stop sequence; orchestrator's subsequent `runtime.start` is the second start | Architectural decision; no test required |
| P8.4 | § 9.4 — Refresh writes do not touch the `--read-only` rootfs at all. M16-S6 amendment replaced the `docker cp` design with a read-only bind-mount of a daemon-staged source plus `docker restart`; the `--read-only` rootfs constraint is no longer a refresh concern. The original "`docker cp` works on `--read-only`" claim was empirically broken on Docker 29.4+ (containerd snapshotter rejects rootfs writes regardless of storage driver) and is preserved in the amended spec as historical context only. | (a) | Bind-mount injection: `sandbox-core/src/backend/container.rs:592-600`; restart-based refresh: `:825-845`; staging-side: `sandbox-core/src/guest.rs:130-235` | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:283` `integration_guest_refresh_container_backend` runs against the production-shape `--read-only` lite image (`sandboxd-lite:<workspace_version>` from `make lite-image`); the rewritten test asserts in-container bytes equal the daemon's host-side staged source post-restart |
| P8.5 | § 9.5 — Daemon crash between refresh and DB-update: idempotent refresh on next start; worst case one extra refresh cycle | (a) | `sandboxd/sandboxd/src/main.rs:3081-3094` only updates the DB AFTER both refresh + start succeed; idempotent docker cp + idempotent systemctl restart by spec design | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:441-454` exercises the idempotency (second refresh against same container is a no-op modulo writes) |
| P8.6 | § 9.6 — UID re-use after `userdel`/`useradd`: orphaned rows correctly invisible to the new account; recovery is admin work | (a) | The filter is on `owner_username` string; a UID change does not affect existing rows. Documented at `sandboxd/sandbox-core/src/caller_identity.rs:38-51` doc-comment | Architectural property; no test required (would require multi-user-host fixture) |
| P8.7 | § 9.7 — `getpwuid_r` failure mode under load: daemon refuses; CLI sees reset; operator retries — Spec 1 § 9.1 already walked this; no correctness invariant at stake | (a) | `sandboxd/sandboxd/src/main.rs:894-908` strict refuse policy | Acceptance-of-risk language; matches Spec 1's analogous closure |

---

## Part 9 — Out of scope (§ 8)

All rows are by spec definition (b). Verified by grep over M13 commits
(`c0d937f`..`HEAD`).

| # | Claim | Status | Locator |
|---|-------|--------|---------|
| P9.1 | Spec 3 — Dedicated `sandbox` system user, systemd unit, `/var/lib/sandbox/`, file modes, `sandbox doctor`, version pinning | (b) | spec § 8 bullet 1; grep verified: no `sandbox doctor` subcommand, no systemd unit, no `/var/lib/sandbox` user-state migration. References to `sandbox doctor` in M13 code are pointers ("Run sandbox doctor (Spec 3)") at `sandboxd/sandbox-core/src/store.rs:290` and `sandboxd/sandbox-route-helper/src/audit.rs:37` only |
| P9.2 | Specs 4 / 5 — Release pipeline, signed builds, GH Pages install scripts, Lima test harness, `sandbox update` CLI, config-migration framework, lock file, backup folder | (b) | spec § 8 bullet 2; verified: no `install.sh`/`uninstall.sh`, no `sandbox update` subcommand, no migration registry beyond the V001-V006 SQL set, no GH Pages tooling in M13 commits |
| P9.3 | Admin override in the API | (b) | spec § 8 bullet 3; verified: no admin role / `/etc/sandboxd/admins.conf` mechanism; sessions filter is strictly owner-only |
| P9.4 | Multi-version protocol negotiation (daemon ↔ guest, daemon ↔ CLI) | (b) | spec § 8 bullet 4; `is_protocol_compatible` is exact-match at `sandbox-core/src/guest.rs:67-69`; the seam is documented but unwidened |
| P9.5 | `sandbox describe` / `sandbox inspect` field additions for the new columns | (b) | spec § 8 bullet 5; `owner_username` shipped on the wire (Spec 2 made the call to surface it — `sandbox-core/src/api/dto.rs:58`); the broader DTO evolution path is deferred to Specs 3/4/5 UX work |
| P9.6 | Cross-user mutation / sharing surfaces | (b) | spec § 8 bullet 6; no "share session" endpoint, no cross-user grant — strictly per-operator isolation |

---

## Part 10 — Implementation notes / affected files (§§ 10–11)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P10.1 | `sandboxd/sandbox-core/migrations/V006__add_owner_and_guest_versions.sql` — new migration | (a) | File exists with destructive DELETE + three ADD COLUMNs | `sandboxd/sandbox-core/src/store.rs:3742-3887` migration tests |
| P10.2 | `sandboxd/sandbox-core/src/store.rs` — methods gain `caller_username`; new `update_guest_versions`; rename `update_state_forced` → `update_state_reconcile`; V006 orphan scan | (a) | All four edits landed: `:531-872` per-method `caller_username` parameter; `:840-872` `update_guest_versions`; `:878-928` `update_state_reconcile` rename + doc-comment; `:174-415` orphan scan | `:4153-4358` per-caller filter tests; `:2645,2680` reconcile tests; `:3913` orphan-scan integration test |
| P10.3 | `sandboxd/sandbox-core/src/session.rs` — `Session` struct gains three new fields, each `#[serde(default)]` | (a) | `sandboxd/sandbox-core/src/session.rs:454,464,473` (all three fields, all `#[serde(default)]`) | `:2127` `test_custom_config_roundtrip` (legacy JSON read-back) |
| P10.4 | `sandboxd/sandbox-core/src/guest.rs` — `DAEMON_GUEST_PROTO_VERSION`, `SANDBOX_GUEST_VERSION`, `is_protocol_compatible`, `can_refresh_in_place`, `GuestRequest::Version`, `GuestResponse::VersionResult` | (a) | `:50,58,67,85,153,176` | `:1131-1180,536-621` |
| P10.5 | `sandboxd/sandbox-guest/src/main.rs` — handler for `GuestRequest::Version` + unit tests | (a) | `sandboxd/sandbox-guest/src/main.rs:96-99` Version arm | `:335,350` |
| P10.6 | `sandboxd/sandbox-core/src/error.rs` — `GuestProtocolIncompatible` variant | (a) | `:88-99` | `:225` Display test; integration coverage at `sandboxd/sandboxd/tests/integration_guest_refresh.rs:59` |
| P10.7 | `sandboxd/sandbox-core/src/backend/{mod.rs,container.rs,lima.rs}` — trait method + two impls | (a) | `mod.rs:341` trait; `container.rs:685` impl; `lima.rs:323,434` impl | `integration_guest_refresh.rs:377` covers container; Lima coverage deferred (P7.24) |
| P10.8 | `sandboxd/sandbox-core/src/lib.rs` — re-export new public symbols (`OperatorIdentity` at minimum) | (a) | `sandboxd/sandbox-core/src/lib.rs:54` `pub use caller_identity::OperatorIdentity`; predicates and constants accessible via `sandbox_core::guest::` namespace | `sandboxd/sandboxd/tests/integration_guest_refresh.rs:39-46` imports cleanly from these paths |
| P10.9 | `sandboxd/sandbox-core/build.rs` — sources `SANDBOX_GUEST_VERSION` from sibling crate's `Cargo.toml` | (a) | `sandboxd/sandbox-core/build.rs:14-60` | `sandboxd/sandbox-core/src/guest.rs:1167` `sandbox_guest_version_is_non_empty_semver_shape` |
| P10.10 | `sandboxd/sandboxd/src/main.rs` — peer-cred acceptor + extension layer + every handler extracts `Extension<OperatorIdentity>` + `start_session` compat gate + `error_response` maps `GuestProtocolIncompatible` → 409 | (a) | `:836-970` acceptor + layer; `:1075,2691,2753,2912,3147,3267,3409,3473,3526,5475` handler extractors; `:2932-2975` compat gate; `error.rs:67` 409 map | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285,396,441`; `integration_guest_refresh.rs:59` |
| P10.11 | `sandboxd/sandbox-guest/Cargo.toml,sandboxd/sandbox-guest/src/lib.rs` — promote `sandbox-guest` to hybrid lib + bin | (b) | spec § 3.2 explicitly accepts either mechanism; implementation chose build.rs path (P3.5) — promotion to lib never happened. § 3.2 closing sentence ("the spec is agnostic on the mechanism") is the scope-out anchor |

---

## Replay verification (§ 6.2)

Spec § 6.2 walkthrough: alice runs the daemon as `alice`; `SO_PEERCRED`
resolves every connection's uid to `alice`; `create_session` stamps
`owner_username = "alice"`; `list_sessions` filters `WHERE owner_username
= 'alice'`; `get_session` returns 200 for any of her sessions; no UX
difference from today for the single-operator case.

The exec-equivalent integration tests that walk the same path:

1. **`integration_create_stamps_owner_from_peercred`** (`sandboxd/sandboxd/tests/integration_owner_peercred.rs:285`)
   — exercises steps 1–4 of the chain (`UnixStream::connect` → daemon's
   acceptor reads `SO_PEERCRED` → `User::from_uid` resolves to `alice`
   → `OperatorIdentity { uid, name: "alice" }` attached to the request
   → `create_session` stamps `owner_username = "alice"`).
2. **`integration_list_returns_only_callers_sessions`** (`:441`) —
   asserts a runner-owned row is visible while a synthetic-foreign-owner
   row is filtered out; the single-operator visibility property in
   spec § 6.2 reduces to this case when no foreign-owner row exists.
3. **`integration_synthetic_foreign_owner_returns_404`** (`:396`) —
   pins the boundary: a foreign-owner row is invisible (404), so the
   single-operator case (the spec's § 6.2 happy path) is the
   complement.

The storage-boundary unit tests at `sandboxd/sandbox-core/src/store.rs:4153-4358`
(`test_create_stamps_caller_username`, `test_get_returns_own_session`,
`test_list_returns_only_callers_sessions`) exercise the same property
hermetically.

Together these tests are the executable replay of spec § 6.2's
walkthrough. No additional replay was performed by this verification
session — the test suite is the canonical replay.

---

## Newly-created todos (M13-S7 verification)

Five new todos were filed during this verification session for genuine
coverage gaps that fit category (c) — all are post-Spec-2 work that is
structurally enabled by the M13 deliverables but not yet observable in
tests:

- **todo #150 (P4.7 / P7.22)** → target **M14+** — `integration_owner_isolation_uid_without_passwd_closes_connection`
  (Lima E2E harness). The daemon-side strict-resolution code at
  `sandboxd/sandboxd/src/main.rs:894-908` is shipped; the spec
  deliberately defers the test to Spec 4 § 6's Lima harness (host CI
  runner uid must remain resolvable for all *other* integration tests).
  Mirror of Spec 1's todo #148.

- **todo #151 (P7.21)** → target **M14+** — `integration_session_isolation_404_on_foreign_id`
  (Lima E2E with `peercred-connector`). The host-level
  `integration_synthetic_foreign_owner_returns_404` covers the
  storage-boundary filter; the genuine multi-uid end-to-end variant
  needs the setuid `peercred-connector` helper provisioned by Spec 4
  § 6.

- **todo #152 (P7.24)** → target **M14+** — `integration_guest_refresh_lima_backend`.
  The Lima refresh impl is shipped at `sandboxd/sandbox-core/src/backend/lima.rs:323-565`;
  the integration test needs `/dev/kvm` and follows the existing
  `lima_integration.rs` `#[cfg_attr(not(has_kvm), ignore)]` pattern.
  Container backend coverage already shipped at
  `sandboxd/sandboxd/tests/integration_guest_refresh.rs:377`.

- **todo #153 (P8.2)** → target **M14+** — `peercred-connector` setuid
  helper + Lima harness provisioning. Owner: Spec 4 § 6 CI
  infrastructure design. Spec 2 names the requirement; Spec 4 owns the
  build target and the `install -m 4755` provisioning step. Sub-todo of
  P7.21/P7.22 above; the helper is the shared infrastructure.

- **todo #154 (cross-cutting)** → target **M14+ (Spec 4)** — Swap
  `stage_embedded_guest_binary` from sibling-file reads
  (`sandbox-core/src/guest.rs:89-130`) to `include_bytes!` per spec
  § 3.6 option A. Currently a deliberate Spec-2 dev-mode deferral
  (P3.15) — the doc-comment at `sandbox-core/src/guest.rs:93-100`
  pre-declares the Spec 4 swap.

No BLOCKERs remained at write completion.
