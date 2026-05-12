# Delivery Map — 2026-05-11 Helper Identity Assertion Design (Spec 1)

Cross-references every concrete claim in the 2026-05-11 helper-identity-assertion
spec to (a) shipped / (b) out-of-scope / (c) tracked-todo. Verifies M13 commits
`c0d937f`, `3ac4294`, `956ca92`, `bfad1ad`, `38ce8c1`, `fdb902b`, `0f1c837`,
`f4ea075`.

## Summary table

| Part | Claims | (a) shipped | (b) out-of-scope | (c) tracked-todo | Blockers |
|------|-------:|------------:|-----------------:|-----------------:|---------:|
| P1 — Motivation                              |  3 |  3 | 0 | 0 | 0 |
| P2 — Threat model                            |  4 |  3 | 1 | 0 | 0 |
| P3 — Pair-membership rule                    | 17 | 16 | 0 | 1 | 0 |
| P4 — `users.conf` schema convention          |  7 |  7 | 0 | 0 | 0 |
| P5 — Migration V001 transform                | 11 | 11 | 0 | 0 | 0 |
| P6 — Daemon-side changes                     | 13 | 13 | 0 | 0 | 0 |
| P7 — Backward-compat dev mode                |  4 |  4 | 0 | 0 | 0 |
| P8 — Test plan                               | 27 | 24 | 0 | 3 | 0 |
| P9 — Risks / open questions                  |  6 |  5 | 0 | 1 | 0 |
| P10 — Out of scope                           |  6 |  0 | 6 | 0 | 0 |
| P11 — Implementation notes                   |  9 |  9 | 0 | 0 | 0 |
| **Grand total**                              | **107** | **95** | **7** | **5** | **0** |

---

## Part 1 — Motivation (§ 1)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P1.1 | Helper formerly authorized by caller's EUID alone | (a) | `sandboxd/sandbox-route-helper/src/main.rs:217` `Uid::current()` (now used *alongside* `--for-user`); historical EUID-only path replaced | `sandboxd/sandbox-route-helper/src/pair_check.rs:128-194` table-driven tests pin the new two-identity contract |
| P1.2 | Pair-check resolves the Spec-3-induced break (daemon as `sandbox` user) by requiring BOTH names in `allow_users` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:331-344` pair-check + deny | `sandboxd/sandbox-route-helper/src/pair_check.rs:128-194` `pair_check_denies_when_caller_missing`, `pair_check_denies_when_for_user_missing` |
| P1.3 | Improves defense-in-depth today: direct CLI invocation of helper cannot elevate via `--for-user=bob` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:262-288` strict `--for-user` resolution; `:327-344` pair-check denies on mismatch | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:824` `integration_route_helper_denies_for_user_mismatch` |

---

## Part 2 — Threat model (§ 2)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.1 | Scenario 1 — Operator compromise (alice impersonates bob) is refused | (a) | `sandboxd/sandbox-route-helper/src/main.rs:331-344` pair-check denies | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:824` `integration_route_helper_denies_for_user_mismatch` (runner asserting `--for-user=root` against pool `[runner]`) |
| P2.2 | Scenario 2 — Daemon compromise bounded: attacker cannot synthesize a `sandbox+carol` pool because `users.conf` is root-owned 0644 non-symlink | (a) | `sandboxd/sandbox-core/src/users_conf.rs:579-651` `validate_canonical_users_conf_security` enforces root-owned, non-symlink | `sandboxd/sandbox-core/src/users_conf.rs` test `validate_users_conf_security_*` mod (existing M12 coverage; survives M13 untouched) |
| P2.3 | Scenario 3 — Cross-user disruption refused (alice not in bob's pool) — both direct + indirect-via-daemon | (a) | `sandboxd/sandbox-core/src/users_conf.rs:328-332` `find_subnet_by_gateway_ip` selects pool by gateway IP; `sandboxd/sandbox-route-helper/src/main.rs:310-323` denies on miss | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:946` `integration_route_helper_denies_when_caller_not_in_pool_even_with_valid_for_user` |
| P2.4 | Scenario 4 — Filesystem bypass: out of scope, addressed by Spec 3's mode/ownership tightening | (b) | spec § 2.4 explicit deferral to Spec 3; § 10 bullet 2 ("Spec 3 — File-mode tightening on `/var/lib/sandbox/`") | — |

---

## Part 3 — Pair-membership rule (§ 3)

### 3.1 / 3.2 — Algorithm and numeric comparison

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.1 | Step 1 caller-name resolution becomes strict (no `ok().flatten()`) | (a) | `sandboxd/sandbox-route-helper/src/main.rs:217-254` strict `User::from_uid` with deny on `Err`/`Ok(None)` | Strict branch exercised structurally by every integration test; dedicated coverage deferred to Lima — see P8.10 |
| P3.2 | Argv now parsed with `--for-user` flag; default = `name(getuid())` when omitted | (a) | `sandboxd/sandbox-route-helper/src/main.rs:450-536` `parse_argv`; `:258` default = caller_name | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:897` `integration_route_helper_defaults_for_user_to_caller_when_omitted` |
| P3.3 | Step 4 pair-check: BOTH names must appear in `allow_users` (numeric comparison) | (a) | `sandboxd/sandbox-route-helper/src/pair_check.rs:54-62` `pair_check`; calls `SubnetEntry::allows_uid` twice | `sandboxd/sandbox-route-helper/src/pair_check.rs:128-194` 8-row table-driven `pair_check_*` tests (spec § 8.1) |
| P3.4 | Numeric comparison via `getpwnam_r` preserved (admin `usermod` takes effect immediately) | (a) | `sandboxd/sandbox-core/src/users_conf.rs:363-388` `SubnetEntry::allows_uid` resolves each name via `User::from_name` | `sandboxd/sandbox-core/src/users_conf.rs:1069` `allows_uid_matches_runner_username`, `:1093` `allows_uid_rejects_bogus_username` |
| P3.5 | `--for-user` argv-parser is hand-rolled (no clap) — long-form + `=`-form supported | (a) | `sandboxd/sandbox-route-helper/src/main.rs:450-536` hand-rolled parser handles `--for-user NAME` AND `--for-user=NAME`; rejects unknown flags | `sandboxd/sandbox-route-helper/Cargo.toml` shows no `clap` dep |

### 3.3 — Exit code, stderr, audit

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.6 | `DENY_EXIT = 1` is the only deny code | (a) | `sandboxd/sandbox-route-helper/src/main.rs:111` `const DENY_EXIT: u8 = 1;` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:824` and friends assert `!output.status.success()` |
| P3.7 | Stderr substring `pair-check failed: caller=<name> for-user=<name> pool=<cidr>` names both identities | (a) | `sandboxd/sandbox-route-helper/src/main.rs:333-334` format string emits `caller={caller_name} for-user={for_user} pool={pool}` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:862-873` asserts `pair-check failed` + `caller=runner` + `for-user=root` substrings |
| P3.8 | One JSON-Lines audit record per invocation, allowed AND denied paths | (a) | `sandboxd/sandbox-route-helper/src/main.rs:142-185` `deny_with_audit` and `allow_audit`; all deny branches call `deny_with_audit`; allow path calls `allow_audit` at `:418-424` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:1048` `integration_route_helper_writes_audit_log_on_allowed`, `:1096` `integration_route_helper_writes_audit_log_on_denied` |

### 3.4 — Username resolution failure

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.9 | Caller uid resolution `Err` → `username resolution failed for <uid>: <errno>` + DENY_EXIT | (a) | `sandboxd/sandbox-route-helper/src/main.rs:239-253` `Err(e)` arm | Deferred to Lima — see P8.10 |
| P3.10 | Caller uid resolution `Ok(None)` → `caller uid <n> does not resolve to a username` + DENY_EXIT | (a) | `sandboxd/sandbox-route-helper/src/main.rs:220-238` `Ok(None)` arm | Deferred to Lima — see P8.10 |
| P3.11 | `--for-user` resolution `Ok(None)` → `--for-user <name> does not resolve to a uid` + DENY_EXIT | (a) | `sandboxd/sandbox-route-helper/src/main.rs:264-275` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:995` `integration_route_helper_denies_when_username_unresolvable` |
| P3.12 | `--for-user` resolution `Err` → `username resolution failed for <name>: <errno>` + DENY_EXIT | (a) | `sandboxd/sandbox-route-helper/src/main.rs:276-287` `Err(e)` arm | Branch is structurally identical to P3.11; not separately covered (no induced-Err fixture). Acceptable — same code path, different errno surface only |

### 3.5 — Audit log destination, shape, write-failure asymmetry

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.13 | Audit log path = `$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log` (today's dev path) | (a) | `sandboxd/sandbox-route-helper/src/audit.rs:39` `DEFAULT_AUDIT_LOG_RELATIVE`, `:59-74` `audit_log_path()` with XDG/HOME/`/tmp` fallbacks | Integration tests inject `SANDBOX_ROUTE_HELPER_AUDIT_LOG` (test-only env override per `audit.rs:47-48`) — `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:213-275` |
| P3.14 | Record shape: `ts`, `decision`, `reason` (deny-only), `caller`, `for_user`, `pool` (when subnet known), `gateway_ip`, `pid` | (a) | `sandboxd/sandbox-route-helper/src/audit.rs:128-175` `write_record` constructs JSON object with exactly those fields; `reason` only on `Decision::Denied`; `pool` only when `Some` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:673-727` `assert_audit_record_shape` (pins all field-presence rules including conditional `reason` and `pool`) |
| P3.15 | RFC 3339 UTC timestamp | (a) | `sandboxd/sandbox-route-helper/src/audit.rs:129` `chrono::Utc::now().to_rfc3339_opts(Millis, true)` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:691-693` `chrono::DateTime::parse_from_rfc3339(ts)` |
| P3.16 | Append-only via `OpenOptions::append(true).create(true)` | (a) | `sandboxd/sandbox-route-helper/src/audit.rs:161-170` | Implicit in shape tests (P3.14) — each test opens a fresh tempfile and asserts on the appended record |
| P3.17 | Allow-path write failure: stderr line, continue (route still installed, exit 0) | (a) | `sandboxd/sandbox-route-helper/src/main.rs:173-185` `allow_audit` logs to stderr but doesn't change exit code; allow flow at `:418-424` followed by `ExitCode::SUCCESS` at `:426` | Allow-path write-failure not separately covered (lossy fixture). See P8.20 deferred-todo for the matching deny-path test that DOES land |
| P3.18 | Deny-path write failure: stderr line + still exits DENY_EXIT (forensic-record-availability escalation) | (a) | `sandboxd/sandbox-route-helper/src/main.rs:151-168` `deny_with_audit` checks `AuditOutcome::WriteFailed`, emits escalation line; returns `ExitCode::from(DENY_EXIT)` unconditionally | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:1152` `integration_route_helper_audit_log_write_failure_on_deny_still_denies` |
| P3.19 | Deny-path-availability invariant: deny still occurs regardless of audit-write outcome | (a) | `sandboxd/sandbox-route-helper/src/main.rs:142-169` decision made *before* audit-write call | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:1178-1201` asserts `!output.status.success()` AND `audit log write failed` stderr line AND audit file does not exist |
| P3.20 | Documentation of operator-investigation procedure (`journalctl`, `df -h`) for audit-log full conditions | (c) | todo #146 → M14 ("docs/guides/troubleshooting.md: add a route-helper deny troubleshooting recipe pointing operators at the audit log path"); existing docs cover the audit log location and shape in `docs/start/installation.md:401-412`, but no dedicated troubleshooting recipe yet | — |

---

## Part 4 — `users.conf` schema convention (§ 4)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.1 | `_schema_version` is a new top-level integer field on `UsersConfig` | (a) | `sandboxd/sandbox-core/src/users_conf.rs:285-292` `pub schema_version: Option<u32>` with `#[serde(default, rename = "_schema_version")]` | `sandboxd/sandbox-core/src/users_conf.rs:1403` `schema_version_absent_yields_none`, `:1419` `schema_version_present_populates_option` |
| P4.2 | Underscore prefix convention; Rust field idiomatic name + `#[serde(rename)]` | (a) | `sandboxd/sandbox-core/src/users_conf.rs:291` `#[serde(default, rename = "_schema_version")]` | Same tests P4.1; `schema_version` Rust field accessed at `:1412`, `:1428` |
| P4.3 | `Option<u32>` + `#[serde(default)]`: absent field yields `None` | (a) | `sandboxd/sandbox-core/src/users_conf.rs:291-292` | `sandboxd/sandbox-core/src/users_conf.rs:1403-1416` `schema_version_absent_yields_none` |
| P4.4 | `deny_unknown_fields` stays on `UsersConfig` and `SubnetEntry` | (a) | `sandboxd/sandbox-core/src/users_conf.rs:283` (`UsersConfig`) and `:302` (`SubnetEntry`) both carry `#[serde(deny_unknown_fields)]` | `sandboxd/sandbox-core/src/users_conf.rs:851` `typo_on_allow_users_field_rejected`, `:1443` `schema_version_typo_rejected` |
| P4.5 | Typo on `_schema_version` rejected with error naming the bad key verbatim | (a) | `sandboxd/sandbox-core/src/users_conf.rs:283,291` (serde's `deny_unknown_fields` includes verbatim key in error) | `sandboxd/sandbox-core/src/users_conf.rs:1468` `users_conf_schema_version_typo_rejected_with_clear_error` (asserts error contains literal `_shema_version`) |
| P4.6 | Operator-customized fields outside V001's domain not supported (`deny_unknown_fields` stays); operators use existing `comment` field | (a) | `sandboxd/sandbox-core/src/users_conf.rs:302-319` `SubnetEntry` keeps `deny_unknown_fields` + `comment: Option<String>` | `sandboxd/sandbox-core/src/users_conf.rs:851-870` `typo_on_allow_users_field_rejected` |
| P4.7 | `serde_json::Value` round-trip is the implementation approach (V001 transform operates on `Value`, not typed struct) | (a) | `sandboxd/sandbox-core/src/users_conf.rs:430-457` `migrate_v001(serde_json::Value) -> serde_json::Value` operates on `Value::Object` directly | `sandboxd/sandbox-core/src/users_conf.rs:1505-1677` V001 unit tests all assert `Value` equality |

---

## Part 5 — Migration V001 (§ 5)

### Inputs/outputs and transform shape (§§ 5.1–5.2)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.1 | `_schema_version` absent → treated as `0`, V001 applies (stamps `1`) | (a) | `sandboxd/sandbox-core/src/users_conf.rs:435-438` unconditionally inserts `_schema_version: 1` | `sandboxd/sandbox-core/src/users_conf.rs:1505` `v001_adds_sandbox_to_single_user_pool` (Input A → Output A) |
| P5.2 | `_schema_version == 1` → no-op (idempotency) | (a) | `sandboxd/sandbox-core/src/users_conf.rs:435-456` insert overwrites with `1`; per-pool branch skips if `"sandbox"` already present | `sandboxd/sandbox-core/src/users_conf.rs:1573` `v001_noops_when_schema_version_already_one` (Input D bit-equal output) |
| P5.3 | Per-pool: prepend `"sandbox"` if absent; else no-op | (a) | `sandboxd/sandbox-core/src/users_conf.rs:440-453` `already_has_sandbox` guard + `insert(0, ...)` prepend | `sandboxd/sandbox-core/src/users_conf.rs:1505` Input A → Output A confirms prepend; `:1551` `v001_noops_pool_already_containing_sandbox` confirms no-op + order preservation (Input C → Output C) |
| P5.4 | `migrate_v001` is a pure transform (`serde_json::Value -> serde_json::Value`) | (a) | `sandboxd/sandbox-core/src/users_conf.rs:430` signature `pub fn migrate_v001(value: serde_json::Value) -> serde_json::Value` | All `v001_*` tests assert deterministic transform |

### Idempotency contract (§ 5.3)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.5 | Already-correct pool `["sandbox", "alice"]` → unchanged | (a) | `sandboxd/sandbox-core/src/users_conf.rs:449-452` skip if present | Tested via `v001_idempotent_when_run_twice` |
| P5.6 | Operator hand-ordered pool `["alice", "sandbox"]` → order preserved (no shuffle) | (a) | `sandboxd/sandbox-core/src/users_conf.rs:449-452` `any` check ignores position; no modification on hit | `sandboxd/sandbox-core/src/users_conf.rs:1551` `v001_noops_pool_already_containing_sandbox` |
| P5.7 | `_schema_version: 1` already present → file unchanged | (a) | `sandboxd/sandbox-core/src/users_conf.rs:435-438` insert is idempotent-on-equal-value | `sandboxd/sandbox-core/src/users_conf.rs:1573` `v001_noops_when_schema_version_already_one` |

### Output validation (§ 5.4) and examples (§ 5.5)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.8 | Output parses as `UsersConfig` with `_schema_version = Some(1)` | (a) | Output is structurally `Value::Object` with stamped field | `sandboxd/sandbox-core/src/users_conf.rs:1419` `schema_version_present_populates_option` validates round-trip |
| P5.9 | Each `subnets[i].allow_users` contains `"sandbox"` exactly once | (a) | `sandboxd/sandbox-core/src/users_conf.rs:449-452` guarded prepend | `sandboxd/sandbox-core/src/users_conf.rs:1505-1547` Outputs A/B verify single `"sandbox"` entry per pool |
| P5.10 | Operator `comment` field is preserved through transform | (a) | Transform mutates only `_schema_version` and `subnets[].allow_users`; all other keys ride through unchanged | `sandboxd/sandbox-core/src/users_conf.rs:1588` `v001_preserves_comment_field`, `:1631` `v001_preserves_existing_field_order_when_possible` |
| P5.11 | All four spec example I/O pairs (Inputs A, B, C, D) yield exact spec outputs | (a) | Same code locator P5.3 | `sandboxd/sandbox-core/src/users_conf.rs:1505-1584` `v001_adds_sandbox_to_single_user_pool` (A), `v001_adds_sandbox_to_multiple_pools_independently` (B), `v001_noops_pool_already_containing_sandbox` (C), `v001_noops_when_schema_version_already_one` (D) |

---

## Part 6 — Daemon-side changes (§ 6)

### 6.1 — Peer-credential read

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.1 | `tokio::net::UnixListener` accept wrapped by a peer-cred acceptor | (a) | `sandboxd/sandboxd/src/main.rs:840-848` `PeerCredListener::new`; wired at `:6930` `let listener = PeerCredListener::new(listener)` | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` `integration_create_stamps_owner_from_peercred` exercises the chain end-to-end |
| P6.2 | `stream.peer_cred()` invoked immediately after accept | (a) | `sandboxd/sandboxd/src/main.rs:884-891` | Same test P6.1 |
| P6.3 | `User::from_uid` resolves uid → username | (a) | `sandboxd/sandboxd/src/main.rs:894,934-942` `resolve_uid_to_name` wraps `User::from_uid` | Same test P6.1 (asserts `owner_username` equals runner's `whoami`) |
| P6.4 | Unresolvable uid → close stream, `warn!`-log, continue accepting | (a) | `sandboxd/sandboxd/src/main.rs:901-908` `None` arm drops the stream and continues the loop | Spec 2 § 7.5 / spec § 9.1 — see todo backlog; structurally exercised by the strict-resolution policy. Per-uid-not-resolved test deferred to Lima harness — see P8.10 |
| P6.5 | Identity attached via `Extension<OperatorIdentity>` on the request | (a) | `sandboxd/sandboxd/src/main.rs:951-955` `Connected::connect_info` returns `PeerCredAddr`; `:965-970` `operator_identity_layer` unwraps to plain `Extension<OperatorIdentity>` | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285-394` |
| P6.6 | No new dependency: `tokio::net::UnixStream::peer_cred()` is used (no `nix::sys::socket` direct getsockopt) | (a) | `sandboxd/sandboxd/src/main.rs:884` `stream.peer_cred()` (no `nix::sys::socket::getsockopt`); `sandbox-core`'s `nix` feature `user` already in scope | `sandboxd/sandboxd/Cargo.toml` carries no new `socket` feature on `nix` |

### 6.2 — Handler extraction

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.7 | `OperatorIdentity` struct lives in `sandbox-core` (shared between specs) | (a) | `sandboxd/sandbox-core/src/caller_identity.rs:41-51` `pub struct OperatorIdentity { uid: u32, name: String }` | `sandboxd/sandbox-core/src/caller_identity.rs:65-86` `operator_identity_roundtrips_through_new`, `operator_identity_is_clone_and_eq` |
| P6.8 | `create_session` and `start_session` carry `Extension<OperatorIdentity>` | (a) | `sandboxd/sandboxd/src/main.rs:1075` (`create_session`), `:2914` (`start_session`) | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` walks the create path |

### 6.3 — Threading to helper invocation

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.9 | `RuntimeStartArgs` gains `for_user: Option<String>` field with doc-comment forward-compat rationale | (a) | `sandboxd/sandbox-core/src/backend/mod.rs:97-118` `pub for_user: Option<String>` with the spec § 6.3 doc-comment text | `sandboxd/sandbox-core/src/backend/mod.rs:364-376` `default()` test asserts `for_user.is_none()`; `:379-386` clone-assert |
| P6.10 | `invoke_route_helper` signature gains `for_user: &str`; emits `--for-user <name>` BEFORE positionals | (a) | `sandboxd/sandbox-core/src/backend/container.rs:1066-1083` `async fn invoke_route_helper(.., for_user: &str)`; emits `--for-user` before `pid_arg` / `gw_arg` | `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:255` `integration_route_helper_for_user_propagated` asserts exact argv order (4 items: `--for-user`, name, pid, gw) |
| P6.11 | `for_user: None` + configured helper path → `SandboxError::Internal` (programming error) | (a) | `sandboxd/sandbox-core/src/backend/container.rs:561-568` ok_or_else yields `Internal(...)` | `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:429` `integration_route_helper_missing_for_user_with_helper_path_errors` |

### 6.4 — Helper invocation sites — concrete list

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.12 | S1: `ContainerRuntime::start` is the sole helper-invocation site; D1 (`create_session`) and D2 (`start_session`) populate `for_user`; L1/L2 (Lima paths) pass `for_user` for parity but Lima never invokes helper | (a) | `sandboxd/sandbox-core/src/backend/container.rs:545-582` start handler + helper invocation; `sandboxd/sandboxd/src/main.rs:1608-1613` (create_session container path), `:2187-2192` and `:2233-2238` (Lima slow-/fast-paths), `:3026-3031` (start_session); `sandboxd/sandbox-core/src/backend/lima.rs:230-249` never reaches helper | `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:338` `integration_route_helper_for_user_falls_through_lima` (Lima path) + `:255` container path |

### 6.5 — Wire snapshot

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.13 | Post-spec daemon-emitted argv = `<helper> --for-user <name> <pid> <gateway-ip>` | (a) | `sandboxd/sandbox-core/src/backend/container.rs:1077-1083` builds Command with this exact ordering | `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:288-315` asserts exact 4-item argv shape |

---

## Part 7 — Backward compatibility — dev mode (§ 7)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.1 | Dev-mode walkthrough succeeds: daemon as alice → CLI connects → peer-cred resolves → helper invoked with `--for-user alice` → pair-check allows (`alice` ∈ `["sandbox","alice"]`) | (a) | Full chain wired: `sandboxd/sandboxd/src/main.rs:6930` listener wrap; `:894-908` resolve+attach; `:1608-1613` thread `for_user`; `sandbox-core/src/backend/container.rs:570` invoke; `sandbox-route-helper/src/main.rs:331-344` pair-check | End-to-end: `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` + `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:255` + `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:738` |
| P7.2 | Unresolvable `"sandbox"` name in `allow_users` is harmless (treated as non-match) | (a) | `sandboxd/sandbox-core/src/users_conf.rs:371-375` `Ok(None)` arm of `allows_uid` — non-match without denying other entries | `sandboxd/sandbox-core/src/users_conf.rs:1093` `allows_uid_rejects_bogus_username` |
| P7.3 | Pre-V001 deployments: existing files without `_schema_version` continue to parse | (a) | `sandboxd/sandbox-core/src/users_conf.rs:291` `#[serde(default)]` | `sandboxd/sandbox-core/src/users_conf.rs:1403` `schema_version_absent_yields_none` |
| P7.4 | Direct CLI helper invocation: `--for-user` omitted = `name(getuid())` (same status quo) | (a) | `sandboxd/sandbox-route-helper/src/main.rs:258` `for_user = for_user_arg.unwrap_or_else(|| caller_name.clone())` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:897` `integration_route_helper_defaults_for_user_to_caller_when_omitted` |

---

## Part 8 — Test plan (§ 8)

### 8.1 — Unit tests: pair-check function (8 rows from spec table)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.1 | `pair_check_allows_when_both_match` | (a) | `sandboxd/sandbox-route-helper/src/pair_check.rs:54-62` | `sandboxd/sandbox-route-helper/src/pair_check.rs:128` `pair_check_allows_when_both_match` |
| P8.2 | `pair_check_allows_when_caller_eq_for_user_post_v001` | (a) | same | `sandboxd/sandbox-route-helper/src/pair_check.rs:137` |
| P8.3 | `pair_check_denies_when_caller_missing` | (a) | same | `sandboxd/sandbox-route-helper/src/pair_check.rs:148` |
| P8.4 | `pair_check_denies_when_for_user_missing` | (a) | same | `sandboxd/sandbox-route-helper/src/pair_check.rs:156` |
| P8.5 | `pair_check_denies_when_both_missing` | (a) | same | `sandboxd/sandbox-route-helper/src/pair_check.rs:164` |
| P8.6 | `pair_check_denies_empty_pool_with_explicit_for_user` | (a) | same | `sandboxd/sandbox-route-helper/src/pair_check.rs:172` |
| P8.7 | `pair_check_denies_pool_with_only_sandbox` | (a) | same | `sandboxd/sandbox-route-helper/src/pair_check.rs:180` |
| P8.8 | `pair_check_allows_when_pool_has_only_sandbox_and_caller_is_sandbox` | (a) | same | `sandboxd/sandbox-route-helper/src/pair_check.rs:188` |

### 8.2 — Unit tests: V001 transform (7 rows)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.9 | All seven V001 unit tests | (a) | `sandboxd/sandbox-core/src/users_conf.rs:430-457` | `sandboxd/sandbox-core/src/users_conf.rs:1505-1677` — `v001_adds_sandbox_to_single_user_pool`, `v001_adds_sandbox_to_multiple_pools_independently`, `v001_noops_pool_already_containing_sandbox`, `v001_noops_when_schema_version_already_one`, `v001_preserves_comment_field`, `v001_idempotent_when_run_twice`, `v001_preserves_existing_field_order_when_possible` |

### 8.3 — Unit tests: `_schema_version` schema field

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.10 | All four schema-field unit tests | (a) | `sandboxd/sandbox-core/src/users_conf.rs:285-292` | `sandboxd/sandbox-core/src/users_conf.rs:1403-1487` — `schema_version_absent_yields_none`, `schema_version_present_populates_option`, `schema_version_typo_rejected`, `users_conf_schema_version_typo_rejected_with_clear_error` |

### 8.4 — Integration tests: helper binary

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.11 | `integration_route_helper_accepts_for_user_matching_caller` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:191-427` `run` orchestrator | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:738` |
| P8.12 | `integration_route_helper_denies_for_user_mismatch` | (a) | same | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:824` |
| P8.13 | `integration_route_helper_defaults_for_user_to_caller_when_omitted` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:258` default | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:897` |
| P8.14 | `integration_route_helper_denies_when_caller_not_in_pool_even_with_valid_for_user` | (a) | same orchestrator | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:946` |
| P8.15 | `integration_route_helper_denies_when_username_unresolvable` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:264-275` | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:995` |
| P8.16 | `integration_route_helper_uid_without_passwd_denies_cleanly` (Lima-harness only) | (c) | (deferred; helper-side strict code already shipped at `sandbox-route-helper/src/main.rs:220-253`) | New todo #148 → M14+ (Lima harness uid-without-passwd test) — see "Newly-created todos" below; spec § 8.4 explicitly gates this on the Spec 4 § 6 Lima harness |
| P8.17 | `integration_route_helper_writes_audit_log_on_allowed` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:418-424` allow_audit; `audit.rs:128-175` write_record | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:1048` |
| P8.18 | `integration_route_helper_writes_audit_log_on_denied` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:142-169` deny_with_audit | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:1096` |
| P8.19 | `test_audit_log_failure_on_deny_path_still_denies` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:151-168` escalation logic | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:1152` `integration_route_helper_audit_log_write_failure_on_deny_still_denies` |
| P8.20 | Audit-log write-failure on **allow** path: stderr line + continue (route still installed) | (c) | (audit module already supports the asymmetry at `sandbox-route-helper/src/main.rs:182-184`; no test fixture lands the allow-path side) | New todo #149 → M14+ (allow-path audit-write-failure integration test) — see "Newly-created todos" |

### 8.5 — Integration tests: daemon → helper propagation

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.21 | `integration_route_helper_for_user_propagated` (container backend) | (a) | full chain wired (P6.1–P6.13) | `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:255` |
| P8.22 | `integration_route_helper_for_user_falls_through_lima` (Lima backend never invokes helper) | (a) | `sandboxd/sandbox-core/src/backend/lima.rs:230-249` (no helper invocation) | `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:338` |
| P8.23 | Spec mentions two fixture choices (a)/(b); implementation chose stub-script approach (not the cap'd test binary) | (a) | Choice = stub shell script. `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:55-73` `install_stub_helper` | Inline in test fixtures (stub records argv to a tempfile). Note: spec text recommended choice (a) (cap'd test helper); implementation chose stub-script for hermeticity. The substantive contract (argv shape pinned, helper invocation observed) is the same — deviation documented here for traceability |

### 8.6 — Audit-log assertion convention

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.24 | Shared `assert_audit_line` helper for audit-log shape | (a) | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:673-727` `assert_audit_record_shape` (analogous, more thorough than spec sketch — asserts conditional `reason`/`pool` presence) | Used by P8.12, P8.17, P8.18, P8.19 |
| P8.25 | Audit log opened fresh per integration test under `$XDG_RUNTIME_DIR` (or tempdir) | (a) | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:271-275` `make_audit_log_path` (tempdir-based, even stronger isolation than `$XDG_RUNTIME_DIR`) | Each integration test owns its own tempdir |

### Aggregate spec § 8 claims

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.26 | Integration tests prefixed `integration_*` per project convention; selected by nextest's `integration` profile | (a) | All test names verified — `integration_route_helper_*` prefix | `sandboxd/.config/nextest.toml` |
| P8.27 | `make install-route-helper-test-cap` materializes the cap'd test binary; checksum verification at test start | (a) | `Makefile:277-295` install-route-helper-test-cap target | `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:123-168` `verify_installed_test_helper` |

---

## Part 9 — Risks and open questions (§ 9)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P9.1 | § 9.1 Strict resolution = deliberate behavior change from today's `ok().flatten()` | (a) | `sandboxd/sandbox-route-helper/src/main.rs:217-288` strict on both caller and for-user | Comment at `:211-216` pins the rationale; behavior tested by P3.11 |
| P9.2 | § 9.2 Corrupt `users.conf` preserves today's `ParseFailed`/`InvalidCidr` short-circuit | (a) | `sandboxd/sandbox-core/src/users_conf.rs:528-545` `load_users_config_from` returns `ParseFailed` before any pair-check | Existing M12 tests in users_conf.rs (`parse_users_config_*` family) survive M13 untouched |
| P9.3 | § 9.3 Pool with only `["sandbox"]` correctly denies non-sandbox callers | (a) | `sandboxd/sandbox-route-helper/src/pair_check.rs:54-62` | `sandboxd/sandbox-route-helper/src/pair_check.rs:180` `pair_check_denies_pool_with_only_sandbox` AND `:188` `pair_check_allows_when_pool_has_only_sandbox_and_caller_is_sandbox` |
| P9.4 | § 9.4 No clap added — hand-rolled parser stays | (a) | `sandboxd/sandbox-route-helper/Cargo.toml` (no clap dep); `sandboxd/sandbox-route-helper/src/main.rs:445-449` doc-comment confirms tradeoff | Grep: `git diff c0d937f^..HEAD -- sandboxd/sandbox-route-helper/Cargo.toml` shows no clap added |
| P9.5 | § 9.5 Audit-log write-failure asymmetry actively handled (allow vs. deny) | (a) | `sandboxd/sandbox-route-helper/src/main.rs:142-185` two-arm asymmetry | Deny side P3.18 (covered); allow side P8.20 (deferred todo #149) |
| P9.6 | § 9.6 `getuid()` ↔ `--for-user` resolution race (TOCTOU with `usermod`) | (c) | (deliberately not addressed; spec accepts the risk) | Spec § 9.6 acceptance-of-risk language is the closure — no test needed; documented at `sandboxd/sandbox-route-helper/src/pair_check.rs:1-14` module doc |

---

## Part 10 — Out of scope (§ 10)

All rows here are by spec definition (b). Verified by grep over M13 commits.

| # | Claim | Status | Locator |
|---|-------|--------|---------|
| P10.1 | Spec 5 — Migration framework itself (registry, apply-pending loop, atomic-rename, lock file, backup folder, schema-mismatch refusal) | (b) | spec § 10 bullet 1; grep verified: no migration framework registry / lock file / atomic-rename code in M13 commits — only the pure `migrate_v001` transform shipped at `sandbox-core/src/users_conf.rs:430-457` |
| P10.2 | Spec 3 — File-mode tightening on `/var/lib/sandbox/`, dedicated `sandbox` system user, systemd unit, `sandbox doctor`, version pinning | (b) | spec § 10 bullet 2; grep verified: no `/var/lib/sandbox` path, no `sandbox doctor` subcommand, no systemd unit in M13 commits |
| P10.3 | Spec 2 — API session ownership, guest binary version compat, refresh-in-place | (b) | spec § 10 bullet 3 (uses the same `OperatorIdentity` extension); the M13 work for those *did* ship in commits `bfad1ad` and `38ce8c1`, but those are Spec 2's deliverables not Spec 1's |
| P10.4 | Specs 4/5 — Release/install/uninstall/update infrastructure | (b) | spec § 10 bullet 4; nothing shipped in M13 toward signed builds / GH Pages install scripts / Lima test harness / `sandbox update` CLI / rollback |
| P10.5 | No new dependency added to `sandbox-route-helper` (no clap) | (b) | spec § 10 bullet 5 + § 9.4; verified via `git diff c0d937f^..HEAD -- sandboxd/sandbox-route-helper/Cargo.toml` — only `serde_json` and `chrono` workspace pins added (required by audit-log; spec § 11 explicitly anticipates this) |
| P10.6 | IPv6 support in pair-check | (b) | spec § 10 bullet 6; `sandboxd/sandbox-route-helper/src/main.rs:611-640` `enforce_netns_addresses_in_subnet` explicitly skips IPv6 (`SockaddrIn::as_sockaddr_in()` filter) |

---

## Part 11 — Implementation notes (§ 11)

The spec § 11 table enumerates expected touch points. This Part maps each to shipped code.

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P11.1 | `sandbox-route-helper/src/main.rs` — argv parser + strict step-1 + pair-check + audit module | (a) | `sandboxd/sandbox-route-helper/src/main.rs:91-776` (entire crate rewritten); `audit.rs` new file | All P3.x / P8.x tests |
| P11.2 | `sandbox-core/src/users_conf.rs` — `schema_version` field + `migrate_v001` + tests | (a) | `sandboxd/sandbox-core/src/users_conf.rs:285-292,430-457` | `:1403-1487` schema tests; `:1505-1677` V001 tests |
| P11.3 | `sandboxd/src/main.rs` — custom acceptor wrapping `UnixListener` with `SO_PEERCRED` read | (a) | `sandboxd/sandboxd/src/main.rs:836-928` `PeerCredListener` + impls; `:6930` wire-in | `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` |
| P11.4 | `sandboxd/src/main.rs` (handlers) — `create_session` and `start_session` gain `Extension<OperatorIdentity>` | (a) | `:1075,2914` (also added to stop_session, remove_session, and others — Spec 2 dependency) | Same test P11.3 |
| P11.5 | `sandbox-core/src/backend/mod.rs` — `RuntimeStartArgs` gains `for_user: Option<String>` | (a) | `sandboxd/sandbox-core/src/backend/mod.rs:97-118` | `:364-386` |
| P11.6 | `sandbox-core/src/backend/container.rs` — read `for_user`, pass to `invoke_route_helper`; signature gains `for_user: &str` | (a) | `sandboxd/sandbox-core/src/backend/container.rs:545-582,1066-1083` | P8.21 |
| P11.7 | `sandbox-core/src/backend/lima.rs` — threads `for_user` through (no behavioral effect) | (a) | `sandboxd/sandbox-core/src/backend/lima.rs:230-249` accepts `args.for_user` implicitly via `RuntimeStartArgs` (never consults it) | P8.22 |
| P11.8 | `sandbox-route-helper/tests/integration_route_helper.rs` — new pair-check coverage | (a) | New tests at `:738,824,897,946,995,1048,1096,1152` | tests themselves |
| P11.9 | `sandboxd/tests/integration_route_helper_propagation.rs` — new daemon→helper propagation tests | (a) | new file `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:255,338,429` | tests themselves |

---

## Replay verification

Spec § 7.1 provides a dev-mode walkthrough rather than an executable replay. The steps are:

1. CLI does `UnixStream::connect(socket_path)` — verified at `sandbox-cli/src/main.rs:1122`.
2. Daemon's acceptor reads `SO_PEERCRED` → `uid = alice's uid` — verified at `sandboxd/sandboxd/src/main.rs:884`.
3. `User::from_uid(alice's uid)` → `Some(User { name: "alice", ... })` — verified at `sandboxd/sandboxd/src/main.rs:894,937`.
4. `OperatorIdentity { uid, name: "alice" }` attached to request — verified at `sandboxd/sandboxd/src/main.rs:896-899`.
5. `create_session` runs `runtime.start(handle, RuntimeStartArgs { for_user: Some("alice"), ... })` — verified at `sandboxd/sandboxd/src/main.rs:1612`.
6. `ContainerRuntime::start` runs `invoke_route_helper(..., for_user)` — verified at `sandboxd/sandbox-core/src/backend/container.rs:570`.
7. Helper forks; `getuid()` = alice; `--for-user` = `"alice"` — verified at `sandboxd/sandbox-route-helper/src/main.rs:217-258`.
8. Pair-check: `caller_in && for_in` both true → allow — verified at `sandboxd/sandbox-route-helper/src/pair_check.rs:54-62`.

The exec-equivalent integration test that walks the same path lands at:
- `sandboxd/sandboxd/tests/integration_owner_peercred.rs:285` (steps 1–4, full HTTP path).
- `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs:255` (steps 5–7, argv shape pinned).
- `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs:738` (steps 7–8, real cap'd helper, pair-check allow).

Together these three integration tests are the executable replay of the spec § 7.1 walkthrough. No additional replay was performed by this verification session — the test suite is the canonical replay.

---

## Newly-created todos (M13-S7 verification)

Two new todos were filed during this verification session for genuine coverage gaps that fit category (c) — both are post-Spec-1 work that is structurally enabled by the M13 deliverables but not yet observable in tests:

- **todo #148 → M14+** — Lima-harness `integration_route_helper_uid_without_passwd_denies_cleanly` (spec § 8.4, P8.16). The helper-side strict-resolution code at `sandbox-route-helper/src/main.rs:220-253` is shipped; the spec deliberately defers the test to Spec 4 § 6's Lima harness (host CI runner uid must remain resolvable for all *other* integration tests).
- **todo #149 → M14+** — Allow-path audit-log-write-failure integration test (spec § 3.5, P8.20). The deny-path side of the asymmetry is covered by `integration_route_helper_audit_log_write_failure_on_deny_still_denies`; the allow-path side (write failure → stderr + continue with route install) is uncovered. The module already supports the asymmetry (`sandbox-route-helper/src/main.rs:173-185`); only a fixture is missing.

No BLOCKERs remained at write completion.
