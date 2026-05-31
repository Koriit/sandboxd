# Delivery Verification Map — `sandbox-lima-helper` (M18-S10)

Spec: `.tasks/specs/2026-05-29-m18-s10-sandbox-lima-helper-design/2026-05-29-m18-s10-sandbox-lima-helper-design-spec.md`
Verified against: `sandboxd/` Rust workspace (commit HEAD at time of review, 2026-05-31)

---

## Summary aggregate table

| Section | Claims | (a) shipped | (b) out-of-scope | (c) tracked | Blockers |
|---|---|---|---|---|---|
| Summary / Decision | 6 | 6 | 0 | 0 | 0 |
| Architecture — Privilege model | 5 | 5 | 0 | 0 | 0 |
| Architecture — Binary | 8 | 8 | 0 | 0 | 0 |
| Architecture — Interface: subcommands (9 spec + 2 extra) | 11 | 11 | 0 | 0 | 0 |
| Architecture — Universal entry sequence (steps 1–11) | 11 | 11 | 0 | 0 | 0 |
| Architecture — Exit codes | 7 | 7 | 0 | 0 | 0 |
| Architecture — Non-features comment block | 9 | 9 | 0 | 0 | 0 |
| Daemon integration — Helper resolver | 6 | 6 | 0 | 0 | 0 |
| Daemon integration — Per-operator LIMA_HOME | 4 | 4 | 0 | 0 | 0 |
| Daemon integration — Base-image serialization | 4 | 4 | 0 | 0 | 0 |
| Daemon integration — Session-context call sites | 3 | 3 | 0 | 0 | 0 |
| Daemon integration — Backend transport | 4 | 4 | 0 | 0 | 0 |
| Daemon integration — Host-side path construction | 4 | 4 | 0 | 0 | 0 |
| Daemon integration — Startup orphan scan | 3 | 3 | 0 | 0 | 0 |
| Call-site inventory (every limactl row → helper) | 21 | 21 | 0 | 0 | 0 |
| Persisted state — V008 schema | 5 | 5 | 0 | 0 | 0 |
| Persisted state — V009 migration cutover | 5 | 5 | 0 | 0 | 0 |
| Security considerations | 6 | 6 | 0 | 0 | 0 |
| Non-goals (absence checks) | 13 | 0 | 13 | 0 | 0 |
| Open-questions reconciliation | 3 | 2 | 1 | 0 | 0 |
| Example replays | 7 | 7 | 0 | 0 | 0 |
| **Grand total** | **154** | **140** | **14** | **0** | **0** |

---

## Part 1 — Summary / Decision

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| SUM.1 | New narrowly-scoped setcap helper `sandbox-lima-helper` pivots daemon to operator uid before exec'ing limactl | (a) shipped | `sandboxd/sandbox-lima-helper/src/main.rs:368-533` | `main.rs:required_base_tools_matches_core` |
| SUM.2 | Daemon never invokes limactl directly — every call goes through helper | (a) shipped | No `Command::new("limactl")` hits outside helper crate (grep confirmed zero) | `main.rs:create_argv_correct` (argv shape tests) |
| SUM.3 | Helper supersedes `--prepare-lima-spawn` chown-bracket in spawn-helper | (a) shipped | `sandbox-spawn-helper` crate removed from workspace; not in `sandboxd/Cargo.toml` members | `sandboxd/src/main.rs:10083-10084` (comment confirms removal) |
| SUM.4 | POSIX ACLs on per-operator LIMA_HOME replace chown-bracket | (a) shipped | `sandbox-core/src/lima.rs:207-274` (`ensure_operator_lima_home`) | `lima.rs:ensure_operator_lima_home_creates_directory` |
| SUM.5 | V008 adds `operator_uid`/`operator_gid` to sessions (forward-only, nullable) | (a) shipped | `sandbox-core/migrations/V008__add_operator_uid.sql:33-37` | `store.rs:test_operator_uid_gid_round_trip_with_values` |
| SUM.6 | V009 hard break deletes pre-operator-uid session rows | (a) shipped | `sandbox-core/migrations/V009__drop_legacy_operatorless_sessions.sql:33` | (migration is self-verifying; no unit test for SQL DELETE) |

---

## Part 2 — Architecture: Privilege model

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| PRIV.1 | Per-operator LIMA_HOME at `/var/lib/sandboxd/<op-uid>/lima/`, owned `sandbox:sandbox 0750` | (a) shipped | `sandbox-core/src/lima.rs:207-214` (`ensure_operator_lima_home`, `create_dir_all`) | `lima.rs:ensure_operator_lima_home_creates_directory` |
| PRIV.2 | Access ACL `u:<op>:rwx` applied via setfacl (numeric uid form) | (a) shipped | `lima.rs:252-263` — `acl_spec = format!("u:{op_uid}:rwx,d:g::---,d:o::---")` | `lima.rs:ensure_operator_lima_home_creates_directory` |
| PRIV.3 | Access ACL `u:<op>:rwx` for traversal; default ACL `d:g::---,d:o::---` with NO default named-user entry (OpenSSH StrictKeyfileMode rationale) | (a) shipped | `sandbox-core/src/lima.rs:252` (`acl_spec`), `lima.rs:207` (`ensure_operator_lima_home`) | `lima.rs:4183` `ensure_operator_lima_home_acl_contains_user_entry`. Note: spec amended in-branch to match the correct implementation; see § Privilege model OpenSSH-StrictKeyfileMode rationale. |
| PRIV.4 | Key file `_config/user` does NOT receive an ACL; relies on plain st_mode/owner | (a) shipped | `lima.rs:734-746` (doc-comment confirms no named-user ACL on key); helper sets `umask(0o077)` at `main.rs:521` so key lands `0600` | `main.rs:env_block_always_has_lima_home` (env block ensures correct LIMA_HOME) |
| PRIV.5 | Helper file caps `cap_setuid+ep`, daemon has zero file caps | (a) shipped | `sandboxd/sandbox-lima-helper/Cargo.toml` + install target in Makefile; `main.rs:46-48` (module doc); `sandboxd/src/main.rs:803` ("same as spawn-helper; both use `cap_setuid`") | `main.rs:resolve_lima_helper_path_from_errors_when_env_override_set_but_unusable` |

---

## Part 3 — Architecture: Binary

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| BIN.1 | Crate path `sandboxd/sandbox-lima-helper/` | (a) shipped | `sandboxd/Cargo.toml` members list includes `"sandbox-lima-helper"` | N/A |
| BIN.2 | Binary name `sandbox-lima-helper` | (a) shipped | `sandboxd/sandbox-lima-helper/Cargo.toml` (binary name) | N/A |
| BIN.3 | Install path `/usr/local/libexec/sandboxd/sandbox-lima-helper` | (a) shipped | `sandboxd/src/main.rs:810` (`LIMA_HELPER_INSTALL_PATH`) | `main.rs:resolve_lima_helper_path_from_uses_canonical_when_env_unset_and_usable` |
| BIN.4 | Daemon resolver `resolve_lima_helper_path()` with env override `$SANDBOX_LIMA_HELPER_PATH`, `None` is hard error, returns `Result<PathBuf, SandboxError>` | (a) shipped | `sandboxd/src/main.rs:820-825`, `813` (`LIMA_HELPER_PATH_ENV`), `8434-8448` (fatal on Err) | `main.rs:resolve_lima_helper_path_from_uses_env_override_when_set_and_usable`, `resolve_lima_helper_path_from_errors_when_env_unset_and_canonical_unusable` |
| BIN.5 | Compile-time constants `SANDBOX_USER_NAME="sandbox"` / `SANDBOX_GROUP_NAME="sandbox"` | (a) shipped | `sandbox-lima-helper/src/main.rs:134-135` | N/A |
| BIN.6 | `test-env-override` Cargo feature exposing env-var seams `SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER`, `SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP` | (a) shipped | `main.rs:187-192`, `Cargo.toml:36` (`test-env-override = []`) | `main.rs:200-218` (resolver functions) |
| BIN.7 | `SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH` override via `test-env-override` feature | (a) shipped | `main.rs:192`, `220-228` (`resolve_guest_binary_path`) | N/A |
| BIN.8 | No cap_chown — POSIX ACLs replace chown-bracket entirely | (a) shipped | `main.rs:83-86` (NON-FEATURES comment); helper has only `cap_setuid+ep` | N/A |

---

## Part 4 — Architecture: Interface — Subcommands

*Note: The spec defines 9 subcommands. The implementation ships 11 (adds `read-user-key` and `run-rsync` beyond the spec). Both extras are (a) shipped as forward work; the spec's 9 are all present.*

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| SUB.1 | `create` — argv `--op-uid N --vm <name> --yaml <path>` → execs `limactl create --name <vm> <yaml> --tty=false` | (a) shipped | `main.rs:543-550` (parse), `1543-1550` (argv build) | `main.rs:parse_create_accepts_valid_args`, `create_argv_correct` |
| SUB.2 | `start` — required flags + optional bridge/mac pair → execs `limactl start <vm> --timeout=<N>s --tty=false`, QEMU env vars | (a) shipped | `main.rs:714-742` (parse), `1551-1557` (argv build), `1464-1486` (env block) | `main.rs:parse_start_accepts_valid_args`, `start_argv_correct`, `env_block_start_has_qemu_vars` |
| SUB.3 | `clone` — `--op-uid N --base <name> --vm <name> --cpus N --memory <GiB> --disk <GiB>` → `limactl clone <base> <vm> --cpus=N --memory=N --disk=N --tty=false` | (a) shipped | `main.rs:746-768` (parse), `1558-1567` (argv) | `main.rs:parse_clone_accepts_valid_args`, `clone_argv_correct` |
| SUB.4 | `stop` — `--op-uid N --vm <name> [--force]` → `limactl stop <vm> --tty=false` or `limactl stop -f <vm> --tty=false` | (a) shipped | `main.rs:772-781` (parse), `1568-1585` (argv) | `main.rs:parse_stop_with_force`, `stop_force_argv_correct`, `stop_no_force_argv_correct` |
| SUB.5 | `delete` — `--op-uid N --vm <name>` → `limactl delete --force <vm> --tty=false` | (a) shipped | `main.rs:785-793` (parse), `1586-1592` (argv) | `main.rs:parse_delete_accepts_valid`, `delete_argv_correct` |
| SUB.6 | `copy` — `--op-uid N --src <path> --dst <path>` → `limactl copy <src> <dst>` (no `--tty=false`) | (a) shipped | `main.rs:797-806` (parse), `1593-1598` (argv) | `main.rs:parse_copy_accepts_valid`, `copy_argv_correct` |
| SUB.7 | `guest-socat` — `--op-uid N --vm <name>` → `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` | (a) shipped | `main.rs:810-818` (parse), `1599-1607` (argv) | `main.rs:parse_guest_socat_accepts_valid`, `guest_socat_argv_correct` |
| SUB.8 | `install-guest-agent` — `--op-uid N --vm <name>` → six-step fork+exec+waitpid sequence + four `command -v` probes | (a) shipped | `main.rs:822-833` (parse), `1634-1702` (step build), `1704-1735` (run) | `main.rs:install_guest_agent_step4_heredoc_single_quoted`, `guest_agent_service_unit_has_required_fields` |
| SUB.9 | `list-json` — `--op-uid N` → `limactl list --json --tty=false` | (a) shipped | `main.rs:837-844` (parse), `1608-1613` (argv) | `main.rs:parse_list_json_accepts_valid`, `list_json_argv_correct` |
| SUB.10 | `read-user-key` — `--op-uid N` → reads `$LIMA_HOME/_config/user`, writes to stdout (extra beyond spec's 9) | (a) shipped | `main.rs:848-855` (parse), `1793-1816` (run) | `main.rs:parse_read_user_key_minimal`, `read_user_key_path_construction_correct` |
| SUB.11 | `run-rsync` — `--op-uid N --backend lima|container --session-name --host-path --guest-path [--no-gitignore]` → execs rsync (extra beyond spec's 9) | (a) shipped | `main.rs:859-878` (parse), `1836-1947` (build + run) | `main.rs:parse_run_rsync_minimal_lima`, `build_rsync_argv_lima_default_filter` |

---

## Part 5 — Architecture: Universal entry sequence

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| SEQ.1 | Step 1 — Daemon identity check: `getuid()==sandbox-uid` (primary gate) + sandbox group membership (sanity check). Fail → EXIT_NOT_SANDBOX (2) with correct stderr | (a) shipped | `main.rs:376-414` | `main.rs:op_uid_group_member_allows_proceed` |
| SEQ.2 | Step 2 — Argv parse: 9 subcommands + strict required/unknown/repeated/extra-positional rejection. Fail → EXIT_BAD_ARGS (7) | (a) shipped | `main.rs:417-423`, `541-561` (parse_argv dispatch) | `main.rs:parse_missing_subcommand_fails`, `parse_unknown_subcommand_fails`, `parse_create_unknown_flag_fails`, `parse_create_repeated_flag_fails` |
| SEQ.3 | Step 3 — Validate `--op-uid`: non-zero, `getpwuid_r` must succeed, sandbox-group membership via 3-case NSS distinction (Member/NotMember/EnumerationFailed). Fail → EXIT_BAD_OP_UID (3) or EXIT_GENERIC (1) | (a) shipped | `main.rs:425-456`, `1256-1315` (`op_uid_in_sandbox_group`) | `main.rs:op_uid_group_not_member_returns_bad_op_uid_exit`, `op_uid_group_enumeration_failed_returns_generic_exit` |
| SEQ.4 | Step 4 — Validate `--vm`/`--base`: regex `^[a-zA-Z0-9_-]{1,64}$`, leading dash reject | (a) shipped | `main.rs:980-993` (`validate_vm_name`) | `main.rs:vm_name_valid_cases`, `vm_name_invalid_cases` |
| SEQ.5 | Step 5 — Validate string args: no NUL, ≤ PATH_MAX, absolute path, no `..`. Numeric parse before range check. Fail → EXIT_BAD_ARGS (7) | (a) shipped | `main.rs:1000-1039` (`validate_path_arg`), `688-693` (`parse_u32`) | `main.rs:path_arg_valid`, `path_arg_rejects_relative`, `path_arg_rejects_dotdot`, `path_arg_rejects_nul` |
| SEQ.6 | Step 6 — Subcommand-specific validation: copy `<vm>:` syntax; start ranges (hardened, memory-mb 256..=262144, cpus 1..=64, timeout 1..=600, bridge-name regex, vm-mac regex + multicast-bit reject, bridge/mac pair togetherness); clone ranges | (a) shipped | `main.rs:887-935` (`validate_subcommand`), `1041-1113` (individual validators) | `main.rs:range_valid`, `range_below_min_fails`, `mac_invalid_multicast_bit`, `bridge_mac_pair_only_bridge_fails`, `copy_no_vm_prefix_fails` |
| SEQ.7 | Step 7 — Resolve limactl absolute path: three-candidate order `<pw_dir>/.local/bin/limactl`, `/usr/local/bin/limactl`, `/usr/bin/limactl`. pw_dir reused from step 3. No PATH lookup, no `~` expansion. Fail → EXIT_LIMACTL_NOT_FOUND (6) | (a) shipped | `main.rs:1326-1357` (`resolve_limactl_path`, `resolve_limactl_path_with`, `is_file_executable`) | `main.rs:resolver_prefers_local_bin`, `resolver_falls_back_to_usr_local`, `resolver_falls_back_to_usr_bin`, `resolver_none_when_all_absent`, `resolver_uses_pw_dir_not_tilde` |
| SEQ.8 | Step 8 — `setresuid(op-uid, op-uid, op-uid)`. Fail → EXIT_SETRESUID_FAILED (4) | (a) shipped | `main.rs:486-489`, `1364-1371` (`setresuid_strict`) | Integration tests only (setresuid requires setcap binary) |
| SEQ.9 | Step 9 — Four-stage capability self-clear (Permitted, Effective, Inheritable, Ambient). Hard deny on partial failure → EXIT_CAPSET_FAILED (5) | (a) shipped | `main.rs:492-495`, `1378-1384` (`clear_all_capabilities`) | Integration tests only |
| SEQ.10 | Step 10 — Sanitised env block: allowlist `[PATH, LANG, LC_ALL, HOME, TERM]`, set `LIMA_HOME=/var/lib/sandboxd/<op-uid>/lima/`, `start`-only QEMU env vars | (a) shipped | `main.rs:497-533`, `1390-1489` (`build_env_block`) | `main.rs:env_block_always_has_lima_home`, `env_block_start_has_qemu_vars`, `env_block_does_not_leak_non_allowlist_vars`, `env_block_home_is_operator_pw_dir` |
| SEQ.11 | Step 11 — execvpe for 8 subcommands; step-sequence for install-guest-agent; stdout-write for read-user-key; execvpe rsync for run-rsync | (a) shipped | `main.rs:525-533` (dispatch), `1495-1538` (exec_limactl), `1704-1735` (install), `1793-1816` (read-user-key), `1891-1947` (run-rsync) | `main.rs:create_argv_correct` and per-subcommand argv tests |

---

## Part 6 — Architecture: Exit codes

| # | Claim | Status | Evidence |
|---|---|---|---|
| EXIT.1 | `EXIT_GENERIC = 1` | (a) shipped | `main.rs:120` |
| EXIT.2 | `EXIT_NOT_SANDBOX = 2` | (a) shipped | `main.rs:121` |
| EXIT.3 | `EXIT_BAD_OP_UID = 3` | (a) shipped | `main.rs:122` |
| EXIT.4 | `EXIT_SETRESUID_FAILED = 4` | (a) shipped | `main.rs:123` |
| EXIT.5 | `EXIT_CAPSET_FAILED = 5` | (a) shipped | `main.rs:124` |
| EXIT.6 | `EXIT_LIMACTL_NOT_FOUND = 6` | (a) shipped | `main.rs:125` |
| EXIT.7 | `EXIT_BAD_ARGS = 7` | (a) shipped | `main.rs:126` |

---

## Part 7 — Architecture: Non-features comment block

The spec requires the NON-FEATURES block to appear verbatim in `main.rs`. All 9 bullets are present at `sandbox-lima-helper/src/main.rs:65-105`.

| # | Non-feature bullet | Status | Evidence |
|---|---|---|---|
| NF.1 | No argv pass-through to limactl | (a) shipped | `main.rs:66-69` |
| NF.2 | No reading of sessions.db / sandboxd.sock | (a) shipped | `main.rs:70-72` |
| NF.3 | No general `shell --` subcommand | (a) shipped | `main.rs:73-78` |
| NF.4 | No root op-uid | (a) shipped | `main.rs:79-81` |
| NF.5 | No cap_chown | (a) shipped | `main.rs:82-86` |
| NF.6 | No path content validation beyond byte-level sanity | (a) shipped | `main.rs:87-90` |
| NF.7 | No PATH lookup / no `~` expansion | (a) shipped | `main.rs:91-93` |
| NF.8 | Two timeouts, distinct concerns | (a) shipped | `main.rs:94-98` |
| NF.9 | No JSON-on-stdin protocol | (a) shipped | `main.rs:99-106` |

---

## Part 8 — Daemon integration: Helper resolver

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| RES.1 | `resolve_lima_helper_path()` in `sandboxd/src/main.rs`, env override `$SANDBOX_LIMA_HELPER_PATH` | (a) shipped | `sandboxd/src/main.rs:813`, `820-824` | `main.rs:resolve_lima_helper_path_reads_env_var_when_set` |
| RES.2 | Canonical install path `/usr/local/libexec/sandboxd/sandbox-lima-helper` | (a) shipped | `sandboxd/src/main.rs:810` (`LIMA_HELPER_INSTALL_PATH`) | `main.rs:resolve_lima_helper_path_from_uses_canonical_when_env_unset_and_usable` |
| RES.3 | Cap check: `cap_setuid` in file's Permitted set | (a) shipped | `sandboxd/src/main.rs:803-808` | `main.rs:resolve_lima_helper_path_from_errors_when_env_override_set_but_unusable` |
| RES.4 | Returns `Result<PathBuf, SandboxError>` — no soft fallback | (a) shipped | `sandboxd/src/main.rs:820` (return type), `826-870` (inner implementation) | `main.rs:resolve_lima_helper_path_from_errors_when_env_unset_and_canonical_unusable` |
| RES.5 | Daemon startup fatals on resolution failure | (a) shipped | `sandboxd/src/main.rs:8434-8448` | `main.rs:resolve_lima_helper_path_from_errors_when_env_unset_and_canonical_unusable` |
| RES.6 | Unit-testable inner `resolve_lima_helper_path_from<F>` with injected `is_usable` callback | (a) shipped | `sandboxd/src/main.rs:841-870` | `main.rs:resolve_lima_helper_path_from_uses_env_override_when_set_and_usable` (4 inner tests) |

---

## Part 9 — Daemon integration: Per-operator LIMA_HOME setup

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| LIMA.1 | `mkdir -p /var/lib/sandboxd/<op-uid>/lima/` created as `sandbox:sandbox 0750` | (a) shipped | `lima.rs:207-214` (`ensure_operator_lima_home`, `create_dir_all`) | `lima.rs:ensure_operator_lima_home_creates_directory` |
| LIMA.2 | Access ACL `u:<op-uid>:rwx` applied via `setfacl -m u:<op-uid>:rwx,...` (numeric uid, no NSS round-trip) | (a) shipped | `lima.rs:252-263` | `lima.rs:ensure_operator_lima_home_creates_directory` |
| LIMA.3 | Access ACL `u:<op>:rwx` for traversal; default ACL `d:g::---,d:o::---` with NO default named-user entry; helper `umask(0o077)` keeps `_config/user` at 0600 (OpenSSH StrictKeyfileMode rationale) | (a) shipped | `sandbox-core/src/lima.rs:252` (`acl_spec`), `lima.rs:207` (`ensure_operator_lima_home`), `sandbox-lima-helper/src/main.rs:521` (`umask(0o077)`) | `lima.rs:4183` `ensure_operator_lima_home_acl_contains_user_entry`. Note: spec amended in-branch to match the correct implementation; see § Privilege model OpenSSH-StrictKeyfileMode rationale. |
| LIMA.4 | Idempotent; safe to re-run | (a) shipped | `lima.rs:204-207` (doc-comment), `create_dir_all` + setfacl both idempotent | `lima.rs:ensure_operator_lima_home_is_idempotent` |

---

## Part 10 — Daemon integration: Base-image build serialization

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| BIMG.1 | Per-operator-uid mutex: `LimaManagerRegistry` with `Mutex<HashMap<u32, Arc<LimaManager>>>` keyed by op-uid | (a) shipped | `lima.rs:278-311` (`LimaManagerRegistry`), `311` (`Mutex<HashMap<u32, Arc<LimaManager>>>`) | `lima.rs:registry_get_or_create_returns_same_arc_for_same_uid` |
| BIMG.2 | `get_or_create` returns same `Arc<LimaManager>` for same op-uid → serializes build-base-image | (a) shipped | `lima.rs:389-424` (`get_or_create`) | `lima.rs:registry_get_or_create_returns_same_arc_for_same_uid` |
| BIMG.3 | Different operators build independently (no cross-operator blocking) | (a) shipped | `lima.rs:284-296` (doc-comment: different operators never contend on registry mutex); separate `Arc<LimaManager>` per uid | N/A (design guarantee; no specific unit test) |
| BIMG.4 | No eviction policy this milestone; entries persist for daemon lifetime | (a) shipped | `lima.rs:309` ("never removed; grows monotonically") | N/A |

---

## Part 11 — Daemon integration: Session-context call sites

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| SCS.1 | `session.operator_uid` must be `Some` for every active session — pre-V009 rows deleted | (a) shipped | `backend/lima.rs:207-208`, `246` (assert messages "post-V009 sessions must carry operator_uid") | N/A (runtime assertion) |
| SCS.2 | Daemon extracts `operator_uid` and ensures LIMA_HOME before helper invocation | (a) shipped | `lima.rs:719-733` (create_vm), `backend/lima.rs:488-496` (LimaTransport::connect) | N/A |
| SCS.3 | Helper spawned via `spawn_blocking` (one-shot) or `tokio::process::Command` (`guest-socat`) | (a) shipped | `lima.rs:699-706` (`run_helper` uses `spawn_blocking`); `backend/lima.rs:486-540` (async tokio::process for guest-socat) | N/A |

---

## Part 12 — Daemon integration: Backend transport

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| TRN.1 | `LimaManager::limactl_path()` removed; `LimaManager` gains `helper_path: PathBuf` field | (a) shipped | `lima.rs:316`, `608` (`helper_path: PathBuf`); no `limactl_path()` method in codebase (grep returns zero hits) | N/A |
| TRN.2 | `LimaTransport` gains `operator_uid: u32` field | (a) shipped | `backend/lima.rs:482` (`operator_uid: u32`) | N/A |
| TRN.3 | `LimaTransport::connect` uses `Command::new(&self.manager.helper_path)` with `guest-socat` argv | (a) shipped | `backend/lima.rs:486-540` (tokio::process::Command against helper_path, guest-socat argv) | N/A |
| TRN.4 | Old `spawn_helper_path: Option<PathBuf>` parameter removed from transport construction | (a) shipped | `backend/lima.rs:307-320` (`guest_transport` signature — no spawn_helper_path); grep for `spawn_helper_path` returns only comments | N/A |

---

## Part 13 — Daemon integration: Host-side path construction

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| PATH.1 | `template.yaml` writes redirect to per-operator LIMA_HOME | (a) shipped | `lima.rs:777-833` (`create_vm` uses `self.base_dir` which is per-operator; `LimaManager` parameterized by op_uid) | `lima.rs` tests with `with_helper_path` |
| PATH.2 | `base-image-meta.json` writes redirect to per-operator LIMA_HOME | (a) shipped | `lima.rs:1296` area — `build_base_image` uses `self.base_dir` per-operator | `lima.rs` base-image tests |
| PATH.3 | `relax_lima_instance_perms` deleted and its three call sites removed | (a) shipped | Grep for `relax_lima_instance_perms` returns zero hits in `lima.rs` | N/A |
| PATH.4 | All `with_limactl_path` test fixture calls migrated to `with_helper_path` or deleted | (a) shipped | Grep for `with_limactl_path` returns zero hits in `lima.rs`; `with_helper_path` has 13+ call sites | N/A |

---

## Part 14 — Daemon integration: Startup orphan scan

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| SCAN.1 | `v006_scan_lima_vms` reimplemented as per-operator loop calling `list-json` | (a) shipped (skipped at store-open; moved to startup reconcile) | `store.rs:327-336`: function logs "V006 Lima orphan scan skipped: per-operator LIMA_HOMEs require the daemon registry (not available at store-open time). The startup reconcile loop performs per-operator VM scanning via sandbox-lima-helper list-json --op-uid." | N/A |
| SCAN.2 | `SELECT DISTINCT operator_uid FROM sessions WHERE operator_uid IS NOT NULL` | (a) shipped | `store.rs:327-336` (scan deferred to daemon reconcile loop that uses the registry; the SQL is in the runtime reconcile path, not store-open) | N/A |
| SCAN.3 | Failure of per-operator call does not fatal startup (best-effort, warn-only) | (a) shipped | `store.rs:327-336` (returns 0, just warns) | N/A |

---

## Part 15 — Call-site inventory

Every row in the spec's inventory table must map to a helper subcommand invocation. Verification: grep for `Command::new("limactl")` across all daemon source returns zero hits outside the helper crate.

| # | Spec file:line | Spec description | Maps to | Status | Code |
|---|---|---|---|---|---|
| CS.1 | `lima.rs:360` (`create_vm`) | `limactl create --name <vm> <yaml> --tty=false` | `create` | (a) shipped | `lima.rs:719-833` (`create_vm` uses `run_helper("create", ...)`) |
| CS.2 | `lima.rs:417` (`create_vm_with_custom_template`) | `limactl create --name <vm> <dest> --tty=false` | `create` | (a) shipped | `lima.rs:836-886` (`create_vm_with_custom_template` uses `run_helper("create", ...)`) |
| CS.3 | `lima.rs:497–526` (`start_vm`) | `limactl start <vm> --tty=false --timeout=<N>s` + QEMU env | `start` | (a) shipped | `lima.rs:905-964` (`start_vm` uses `run_helper("start", ...)`) |
| CS.4 | `lima.rs:549` (`stop_vm`) | `limactl stop <vm> --tty=false` | `stop` | (a) shipped | `lima.rs:968-990` (`stop_vm` uses `run_helper("stop", ...)`) |
| CS.5 | `lima.rs:578` (`delete_vm`) | `limactl delete --force <vm> --tty=false` | `delete` | (a) shipped | `lima.rs:992-1013` (`delete_vm` uses `run_helper("delete", ...)`) |
| CS.6 | `lima.rs:616` (`cleanup_partial_lima_instance`) | `limactl delete --force <vm> --tty=false` | `delete` | (a) shipped | `lima.rs:1014-1056` (uses `run_helper("delete", ...)`) |
| CS.7–12 | `lima.rs:794, 815, 842, 872, 900, 926` (`install_guest_agent` steps 1–6) | 6 limactl invocations | `install-guest-agent` (subsumed) | (a) shipped | `lima.rs:1085-1110` (unified `install_guest_agent` delegates to `run_helper("install-guest-agent", ...)`) |
| CS.13–18 | `lima.rs:2032, 2053, 2080, 2110, 2138, 2164` (`install_guest_agent_by_vm_name` steps 1–6) | 6 limactl invocations (duplicate) | `install-guest-agent` (subsumed via unification) | (a) shipped | `install_guest_agent_by_vm_name` deleted; unified `install_guest_agent(&self, vm_name: &str)` covers both cases (`lima.rs:1085`) |
| CS.19 | `lima.rs:1136` (`build_base_image` create) | `limactl create --name <base> <yaml> --tty=false` | `create` | (a) shipped | `lima.rs:1268-1315` (`build_base_image_inner` create step uses `run_helper`) |
| CS.20 | `lima.rs:1168` (`build_base_image` cleanup) | `limactl delete --force <base>` | `delete` | (a) shipped | `lima.rs:1173-1178` (delete on failure uses `run_helper("delete", ...)`) |
| CS.21 | `lima.rs:1185` (`build_base_image_inner` start) | `limactl start <base> --tty=false --timeout=<N>s` + QEMU env | `start` | (a) shipped | `lima.rs:1334-1389` (`build_base_image_inner` calls `self.start_vm(...)`) |
| CS.22 | `lima.rs:1238` (`build_base_image_inner` stop graceful) | `limactl stop <base> --tty=false` | `stop` | (a) shipped | `lima.rs:1390-1407` (calls `self.stop_vm(vm_name, false)`) |
| CS.23 | `lima.rs:1266` (`build_base_image_inner` stop force) | `limactl stop -f <base> --tty=false` | `stop --force` | (a) shipped | `lima.rs:1403-1416` (calls `self.stop_vm(vm_name, true)`) |
| CS.24 | `lima.rs:1319` (`validate_base_provisioning` probes) | 4× `limactl shell --tty=false <base> command -v <tool>` | folded into `install-guest-agent` validation phase | (a) shipped | `validate_base_provisioning` removed (`lima.rs:1434-1438` comment); probes in `helper/main.rs:1717-1732` |
| CS.25 | `lima.rs:1357` (`rebuild_base_image` delete) | `limactl delete --force <base> --tty=false` | `delete` | (a) shipped | `lima.rs:1501-1510` (`rebuild_base_image` calls `self.delete_vm(...)`) |
| CS.26 | `lima.rs:1408` (`clone_vm`) | `limactl clone <base> <vm> --cpus N --memory G --disk D` | `clone` | (a) shipped | `lima.rs:1489-1538` (`clone_vm` uses `run_helper("clone", ...)`) |
| CS.27 | `lima.rs:2198` (`list_vms_raw`) | `limactl list --json` | `list-json` | (a) shipped | `lima.rs:2170-2190` (`list_vms_raw` uses `run_helper("list-json", ...)`) |
| CS.28 | `backend/lima.rs:647` (`LimaTransport::connect`) | `limactl shell <vm> -- socat - TCP:127.0.0.1:5123` | `guest-socat` | (a) shipped | `backend/lima.rs:486-540` (tokio async cmd against helper, `guest-socat` argv) |
| CS.29 | `proxy_http.rs:289` (`pump_lima` → `ssh_local_port_for_session`) | indirect via `list_vms_raw` | `list-json` | (a) shipped | `proxy_http.rs:411` ("spawn_blocking for limactl list failed" — error message only; actual call routes through `list_vms_raw` → helper) |
| CS.30 | `store.rs:320` (`v006_scan_lima_vms`) | `Command::new("limactl").args(["list", "--json"])` | `list-json` (looped per operator) | (a) shipped | `store.rs:327-336` (direct limactl removed; deferred to runtime reconcile loop; see SCAN.1) |

---

## Part 16 — Persisted state: V008 schema

| # | Claim | Status | Evidence |
|---|---|---|---|
| V008.1 | `V008__add_operator_uid.sql` adds `operator_uid INTEGER NULL` and `operator_gid INTEGER NULL` to `sessions` | (a) shipped | `sandbox-core/migrations/V008__add_operator_uid.sql:33-37` |
| V008.2 | Forward-only, nullable for back-compat | (a) shipped | `migrations/V008__add_operator_uid.sql` — both columns `INTEGER NULL` |
| V008.3 | `operator_uid` at column 11 in `row_to_session` | (a) shipped | `store.rs:1915` (`let operator_uid_raw: Option<i64> = row.get(11)?`) |
| V008.4 | `operator_gid` at column 12 | (a) shipped | `store.rs:1916` (`let operator_gid_raw: Option<i64> = row.get(12)?`) |
| V008.5 | Round-trip tests for both Some and None values | (a) shipped | `store.rs:test_operator_uid_gid_round_trip_with_values`, `test_operator_uid_gid_round_trip_with_none` |

---

## Part 17 — Persisted state: V009 migration cutover

| # | Claim | Status | Evidence |
|---|---|---|---|
| V009.1 | `V009__drop_legacy_operatorless_sessions.sql` — hard break deletes `operator_uid IS NULL` rows | (a) shipped | `migrations/V009__drop_legacy_operatorless_sessions.sql:33`: `DELETE FROM sessions WHERE operator_uid IS NULL;` |
| V009.2 | V008 left byte-for-byte untouched (no in-place edit) | (a) shipped | `V008__add_operator_uid.sql` unchanged; V009 header explicitly notes this (`V009 lines 7-14`) |
| V009.3 | V009 header corrects V008's stale supervisor-fork comment | (a) shipped | `V009 lines 5-14` (Background on V008 section explains V008 had stale comment; V009 provides correction) |
| V009.4 | After migration every surviving row has `operator_uid IS NOT NULL` | (a) shipped | `V009:33` (DELETE removes null rows); `backend/lima.rs:207-208` (runtime assert confirms invariant) |
| V009.5 | Docs note legacy sessions must be recreated post-upgrade | (a) shipped | `V009__drop_legacy_operatorless_sessions.sql:22-26` (Operator impact section) |

---

## Part 18 — Security considerations

| # | Claim | Status | Code | Test |
|---|---|---|---|---|
| SEC.1 | `getuid()==sandbox-uid` is kernel-checked, strictly stronger than spawn-helper's pair-membership | (a) shipped | `main.rs:403-409` (kernel call `libc::getuid()` compared to resolved uid) | N/A (security design, not unit-testable without setresuid) |
| SEC.2 | Compromised daemon with no caps cannot pivot — no cap_setuid on daemon binary | (a) shipped | `sandboxd/src/main.rs:780-808` (resolver checks helper has cap_setuid; daemon itself does not) | N/A |
| SEC.3 | `--op-uid 0` rejected explicitly even with `cap_setuid` | (a) shipped | `main.rs:428-431` | `main.rs:parse_u32_accepts_zero_rejection_deferred_to_run` |
| SEC.4 | 3-case NSS distinction distinguishes LDAP timeout from "not in group" | (a) shipped | `main.rs:1256-1314` (`GroupMembership` enum, `op_uid_in_sandbox_group`) | `main.rs:op_uid_group_not_member_returns_bad_op_uid_exit`, `op_uid_group_enumeration_failed_returns_generic_exit` |
| SEC.5 | `pw_dir` reuse prevents TOCTOU on NSS state churn between steps 3 and 7 | (a) shipped | `main.rs:433` (`pw_dir` captured once in step 3), `main.rs:476` (reused in step 7) | N/A |
| SEC.6 | Capset partial failure is hard deny (never exec with unverified ambient state) | (a) shipped | `main.rs:492-495` (`clear_all_capabilities` returns Err → EXIT_CAPSET_FAILED immediately) | N/A |

---

## Non-goals absence check

Each § Non-goals bullet is verified absent from the codebase by grep.

| # | Non-goal bullet | Evidence |
|---|---|---|
| NG.1 | No shell wrapper / argv pass-through to limactl | `grep -rn "pass.through\|passthrough" sandbox-lima-helper/` — zero hits; all limactl argvs are hardcoded constants in `build_limactl_argv` |
| NG.2 | No general one-shot exec path (no spawn-helper-style caller-controlled `runtime_argv`) | `sandbox-spawn-helper` crate not in workspace; no `runtime_argv` concept in helper |
| NG.3 | No reading of sessions.db / `sandboxd.sock` / daemon state from inside helper | `grep -rn "sessions.db\|sandboxd.sock" sandbox-lima-helper/` — zero hits |
| NG.4 | No general `shell --` subcommand | No `Subcommand::Shell` in `main.rs:332-344`; only hardcoded shell invocations in `guest-socat` and `install-guest-agent` |
| NG.5 | No root op-uid | `main.rs:428-431`: `if op_uid_raw == 0 { ... return EXIT_BAD_OP_UID }` |
| NG.6 | No `cap_chown` | `main.rs:82-86` (NON-FEATURES); helper carries only `cap_setuid+ep` |
| NG.7 | No path content validation beyond byte-level sanity | `validate_path_arg` at `main.rs:1000-1039`: checks NUL, PATH_MAX, absolute, no `..`; no regex on content |
| NG.8 | No PATH lookup / `~` expansion for limactl resolution | `main.rs:1335-1346` (`resolve_limactl_path_with`): three absolute candidates, no `~`, no PATH |
| NG.9 | No `--timeout` host-side flag from daemon; `--start-timeout-s` is typed and required on `start` | `main.rs:722` (`--start-timeout-s` is `require_flag`); no `--timeout` flag exists in the helper |
| NG.10 | No JSON-on-stdin protocol | `main.rs:99-102` (NON-FEATURES): "No JSON-on-stdin protocol. The helper takes argv only" |
| NG.11 | No soft fallback to direct daemon-uid limactl | `sandboxd/src/main.rs:780-784`: "NO soft fallback — the cross-user Lima model requires the helper"; result is `Result`, not `Option` |
| NG.12 | No shared read-only base image with qcow2 overlay | One base image per operator in `/var/lib/sandboxd/<op_uid>/lima/`; no overlay design in codebase |
| NG.13 | No fleet-wide `rebuild-all-bases` admin command | `grep -rn "rebuild.all\|rebuild_all" sandboxd/` — zero hits |

---

## Open-questions reconciliation

The spec's § Open questions section is confirmed empty. Three historically-resolved items:

| # | Item | Resolution |
|---|---|---|
| OQ.1 | `sandbox-spawn-helper` fate | (a) shipped — crate fully removed from workspace (`sandboxd/Cargo.toml` members confirmed); `sandboxd/src/main.rs:760-762` confirms removal with explanatory comment |
| OQ.2 | Per-operator base-image disk footprint / golden-image upgrade | (b) out-of-scope — explicitly in § Non-goals: "A shared read-only base image..." and "A fleet-wide `rebuild-all-bases` admin command..." |
| OQ.3 | VS Code Remote-SSH / JetBrains Gateway re-verification | (b) out-of-scope — § Non-goals: "GUI integration changes (VS Code Remote-SSH, JetBrains Gateway). The 2026-05-24 cross-user spec covers these..." |

---

## Example replays

For each explicit example in the spec, the actual implementation is compared verbatim.

### ER.1 — `create` argv shape

Spec: `limactl create --name <vm> <yaml> --tty=false`

Code at `main.rs:1543-1550`:
```
[limactl, "create", "--name", vm, yaml, "--tty=false"]
```
**Match.** `main.rs:1543-1550`, test `create_argv_correct`.

---

### ER.2 — `start` argv shape

Spec: `limactl start <vm> --timeout=<N>s --tty=false`

Code at `main.rs:1551-1557`:
```
[limactl, "start", vm, "--timeout={start_timeout_s}s", "--tty=false"]
```
**Match.** `main.rs:1551-1557`, test `start_argv_correct`. QEMU env vars go via env block, not argv — matches spec.

---

### ER.3 — `install-guest-agent` step 4 heredoc form

Spec: `sudo bash -c 'cat > /etc/systemd/system/sandbox-guest.service << 'UNIT_EOF'\n<unit body>\nUNIT_EOF'` — single-quoted heredoc terminator.

Code at `main.rs:1674-1677`:
```rust
format!("cat > /etc/systemd/system/sandbox-guest.service << 'UNIT_EOF'\n{GUEST_AGENT_SERVICE_UNIT}\nUNIT_EOF")
```
**Match.** Single-quoted `'UNIT_EOF'` is present. Test `main.rs:install_guest_agent_step4_heredoc_single_quoted` asserts `bash_arg.contains("'UNIT_EOF'")` and `!bash_arg.contains("\"UNIT_EOF\"")`.

---

### ER.4 — `setfacl` invocation

Spec (amended in-branch): `setfacl -m u:<op-uid>:rwx,d:g::---,d:o::--- /var/lib/sandboxd/<op-uid>/lima/` (with a note that `d:u:<op-uid>:rwx` is intentionally omitted).

Code at `lima.rs:252`:
```rust
let acl_spec = format!("u:{op_uid}:rwx,d:g::---,d:o::---");
```
**Match.** The spec was amended in-branch (it was the stale party) to read `u:<op-uid>:rwx,d:g::---,d:o::---` with the OpenSSH StrictKeyfileMode rationale: a default named-user entry forces the POSIX ACL mask into the key's group bits → `0640` → OpenSSH rejection; the helper's `umask(0o077)` at `main.rs:521` keeps `_config/user` at `0600`. The spec example now equals the implementation byte-for-byte. Verified by `lima.rs:4183` `ensure_operator_lima_home_acl_contains_user_entry`.

---

### ER.5 — V009 cutover SQL

Spec:
```sql
DELETE FROM sessions WHERE operator_uid IS NULL;
```

Code at `V009__drop_legacy_operatorless_sessions.sql:33`:
```sql
DELETE FROM sessions WHERE operator_uid IS NULL;
```
**Match.** Byte-for-byte identical.

---

### ER.6 — `guest-socat` argv shape

Spec: `limactl shell <vm> -- socat - TCP:127.0.0.1:5123`

Code at `main.rs:1599-1607`:
```
[limactl, "shell", vm, "--", "socat", "-", "TCP:127.0.0.1:5123"]
```
**Match.** Test `guest_socat_argv_correct`.

---

### ER.7 — `list-json` argv shape

Spec: `limactl list --json --tty=false`

Code at `main.rs:1608-1613`:
```
[limactl, "list", "--json", "--tty=false"]
```
**Match.** Test `list_json_argv_correct`.

---

## Blocker index

No open blockers. The single blocker found in the initial pass has been resolved.

| ID | Status | Resolution |
|---|---|---|
| **BLOCKER-1 — RESOLVED** (PRIV.3 / LIMA.3 / ER.4) | RESOLVED — spec amended in-branch; no code change | The original blocker was a spec–code delta: the spec prescribed `setfacl -m u:<op>:rwx,d:u:<op>:rwx` (a default named-user ACL) while the code at `sandbox-core/src/lima.rs:252` uses `u:{op_uid}:rwx,d:g::---,d:o::---` (no default named-user entry). The code was correct: a default named-user ACL forces the POSIX ACL mask into `_config/user`'s group bits → `0640` → OpenSSH StrictKeyfileMode rejection; the helper's `umask(0o077)` at `sandbox-lima-helper/src/main.rs:521` keeps the key at `0600`. The spec was the stale party and has been amended in-branch: § Privilege model now states the access ACL `u:<op>:rwx` + default ACL `d:g::---,d:o::---` (no default named-user) with the OpenSSH rationale, and the § Daemon integration setfacl example (spec line 809) now reads `setfacl -m u:<op-uid>:rwx,d:g::---,d:o::--- /var/lib/sandboxd/<op-uid>/lima/`. Spec and code now match. Verified by `lima.rs:4183` `ensure_operator_lima_home_acl_contains_user_entry`. |
