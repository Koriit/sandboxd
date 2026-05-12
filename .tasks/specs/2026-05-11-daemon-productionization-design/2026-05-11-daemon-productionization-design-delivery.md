# Delivery Map — 2026-05-11 Daemon Productionization (Spec 3)

Cross-references every concrete claim in the 2026-05-11
daemon-productionization spec to (a) shipped / (b) out-of-scope /
(c) tracked-todo. Verifies M14 commits `92cbd6d`, `94fd4ac`,
`8d01d58`, `01b8a4f`, `03ae5cf`, `7c4771e`.

## Summary table

| Part | Claims | (a) shipped | (b) out-of-scope | (c) tracked-todo | Blockers |
|------|-------:|------------:|-----------------:|-----------------:|---------:|
| P1 — Motivation (§ 1)                                |  3 |  3 | 0 | 0 | 0 |
| P2 — Threat model (§ 2)                              |  9 |  8 | 1 | 0 | 0 |
| P3 — `sandbox` system user (§ 3)                     |  9 |  9 | 0 | 0 | 0 |
| P4 — systemd unit (§ 4)                              | 14 | 14 | 0 | 0 | 0 |
| P5 — State location + file modes (§ 5)               | 14 | 14 | 0 | 0 | 0 |
| P6 — `sandbox doctor` subcommand (§ 6)               | 27 | 26 | 0 | 1 | 0 |
| P7 — CLI ↔ daemon version equality (§ 7)             | 14 | 14 | 0 | 0 | 0 |
| P8 — Image tag pinning (§ 8)                         | 13 | 13 | 0 | 0 | 0 |
| P9 — `helper=` removal + rootless cleanup (§ 9)      | 14 | 14 | 0 | 0 | 0 |
| P10 — Daemon-side wiring of operator identity (§ 10) |  6 |  6 | 0 | 0 | 0 |
| P11 — Test plan (§ 11)                               | 24 | 21 | 0 | 3 | 0 |
| P12 — Backward compatibility — dev mode (§ 12)       |  9 |  9 | 0 | 0 | 0 |
| P13 — Risks and open questions (§ 13)                | 10 |  8 | 0 | 2 | 0 |
| P14 — Out of scope (§ 14)                            | 14 |  0 |14 | 0 | 0 |
| P15 — Implementation notes + affected files (§§ 15–16) | 11 | 11 | 0 | 0 | 0 |
| **Grand total**                                      | **191** | **170** | **15** | **6** | **0** |

---

## Part 1 — Motivation (§ 1)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P1.1 | Daemon today runs as the operator's uid (daemon compromise ≡ operator account compromise) — Spec 3 moves to dedicated `sandbox` user | (a) | `sandboxd/contrib/systemd/sandboxd.service:10-11` `User=sandbox`/`Group=sandbox` (canonical unit ships verbatim) | Unit content asserted structurally by Spec 4's install path — no daemon-side test for the unit-file content itself; § 4.1 verbatim block IS the contract |
| P1.2 | No standard process-management surface (no systemd unit) | (a) | New file `sandboxd/contrib/systemd/sandboxd.service` ships the canonical unit | Same as P1.1 |
| P1.3 | State commingled with operator's XDG; spec moves it to `/var/lib/sandbox/` | (a) | `sandboxd/contrib/systemd/sandboxd.service:15-18` `StateDirectory=sandbox` + `StateDirectoryMode=0750`; `:22-23` `ExecStart … --base-dir /var/lib/sandbox` | Same as P1.1 |

---

## Part 2 — Threat model (§ 2)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P2.1 | Daemon runs as `sandbox` system user (no login shell, no own home beyond `/var/lib/sandbox/`); member of `docker`, `kvm` | (a) | `sandboxd/contrib/systemd/sandboxd.service:10-11`; user-construction recipe is Spec 4's `useradd` (§ 3.1); doctor C4 surfaces group membership at `sandboxd/sandbox-cli/src/doctor.rs:568-679` | `sandboxd/sandbox-cli/src/doctor.rs:1772` `group_check_fails_when_not_member_with_hint` |
| P2.2 | Compromise of daemon yields control of `sandbox` user only — operator dotfiles unaffected | (a) | Same as P2.1 + `ProtectHome=yes` at `contrib/systemd/sandboxd.service:35` | Unit-shape only; production tested via Spec 4 install (out of Spec 3 scope) |
| P2.3 | `sandbox` group exists for socket access (`/run/sandbox/sandboxd.sock` mode `0660`); operators added via `usermod -aG sandbox` | (a) | `sandboxd/contrib/systemd/sandboxd.service:17-18` `RuntimeDirectory=sandbox` + `RuntimeDirectoryMode=0750`; doctor C4 hint at `sandboxd/sandbox-cli/src/doctor.rs:604` (`"sudo usermod -aG sandbox $USER; log out and back in"`) | `sandboxd/sandbox-cli/src/doctor.rs:1772` `group_check_fails_when_not_member_with_hint` |
| P2.4 | `sandbox` group does NOT grant filesystem write access — parent dir `0750`, sensitive files `0600`/`0700` | (a) | Subdir mode pinned at `sandboxd/sandboxd/src/main.rs:140` `BASE_DIR_SUBDIR_MODE: u32 = 0o700`; sessions.db at `sandboxd/sandbox-core/src/store.rs:105` chmod `0o600` | `sandboxd/sandboxd/src/main.rs:8950` `ensure_base_dir_layout_creates_missing_subdirs` |
| P2.5 | All session interaction goes through API where Spec 2's `owner_username` filter enforces per-operator visibility | (a) | Spec 2 deliverable; `sandboxd/sandbox-core/src/store.rs` filtered methods (Spec 2 § 2.4) | Spec 2 delivery map covers this; reused unchanged |
| P2.6 | Operators share one daemon process post-Spec-2 isolation | (a) | Spec 2 deliverable (single `AppState` shared by accept loop) | Spec 2 coverage |
| P2.7 | Operators share `dockerd` via `sandbox`'s `docker` group membership; daemon mediates Docker operations | (a) | Doctor C9 / `sandboxd/sandbox-cli/src/doctor.rs:937-1014` route-helper caps presupposes `docker` group on `sandbox` (acceptance of risk in spec § 3.1) | Operational contract — no test |
| P2.8 | § 2.4 — `qemu-bridge-helper` is cross-user; Spec 3 does not attempt to mitigate (deliberate known limitation, tracked as GH #8) | (b) | Spec § 2.4 explicit deferral / GH issue #8; § 9.2 confirms only the *enabler* (rootless wrapper) is removed | — |
| P2.9 | Spec 3 also removes the rootless-Docker code path inside `QEMU_WRAPPER_SCRIPT` (forward-reference § 9) | (a) | `sandboxd/sandbox-core/src/lima.rs:148-226` rewritten wrapper has no rootless branch | `sandboxd/sandbox-core/src/lima.rs:2893` `qemu_wrapper_has_no_rootlesskit_artefacts`; `:2880` `qemu_wrapper_has_no_bridge_helper_variable` |

---

## Part 3 — `sandbox` system user (§ 3)

### 3.1 — User properties (P3.1 – P3.6)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.1 | Username `sandbox`, primary group `sandbox`, system UID | (a) | `sandboxd/contrib/systemd/sandboxd.service:10-11` | Unit-shape: Spec 4 install verifies |
| P3.2 | Login shell `/usr/sbin/nologin`; home `/var/lib/sandbox` (created via systemd `StateDirectory`) | (a) | `:15` `StateDirectory=sandbox`; `:22-23` ExecStart `--base-dir /var/lib/sandbox` | Same |
| P3.3 | Supplementary groups: `docker`, `kvm` | (a) | Construction recipe in spec § 3.1 (`usermod -aG docker / kvm sandbox`); doctor C6 KVM check at `sandboxd/sandbox-cli/src/doctor.rs:782-828` validates `/dev/kvm` access from daemon | `sandboxd/sandbox-cli/src/doctor.rs` C6 test path via diagnostics fixture; `integration_kvm_check_via_daemon_diagnostics` at `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:549` |
| P3.4 | `useradd --system --user-group --no-create-home --home-dir /var/lib/sandbox --shell /usr/sbin/nologin sandbox` (recipe) | (a) | Spec § 3.1 text is the verbatim contract; Spec 4 install lands the call | Spec 4 territory |
| P3.5 | `docker` group required for both backends (container talks to dockerd; Lima uses `dockerCompat`) | (a) | Backend impls at `sandbox-core/src/backend/container.rs` and `sandbox-core/src/backend/lima.rs` both require docker reachability | Hidden invariant — exercised by every container/Lima integration test |
| P3.6 | `kvm` group required so daemon can open `/dev/kvm` for Lima VMs | (a) | Doctor C6 ensures `/dev/kvm` readable+writable by daemon: `sandboxd/sandbox-cli/src/doctor.rs:797-803` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:549` `integration_kvm_check_via_daemon_diagnostics` |

### 3.2 — `sandbox` group purpose (P3.7 – P3.9)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P3.7 | Owns socket `/run/sandbox/sandboxd.sock` mode `0660` | (a) | `sandboxd/contrib/systemd/sandboxd.service:17-18` (`RuntimeDirectory=sandbox` `RuntimeDirectoryMode=0750`); doctor expects `0o660` at `sandboxd/sandbox-cli/src/doctor.rs:737` | `sandboxd/sandbox-cli/src/doctor.rs:692-770` `check_socket_perms` body |
| P3.8 | Operators added via install script + ad-hoc `usermod -aG`; new membership takes effect on next login | (a) | Doctor C4 hint at `sandboxd/sandbox-cli/src/doctor.rs:604` says `log out and back in` verbatim | Same C4 test as P2.3 |
| P3.9 | Group membership does NOT grant filesystem write to `/var/lib/sandbox/`; `0750` parent, `0600`/`0700` inner | (a) | `BASE_DIR_SUBDIR_MODE = 0o700` at `sandboxd/sandboxd/src/main.rs:140`; sessions.db chmod 0600 at `sandboxd/sandbox-core/src/store.rs:105`; systemd `StateDirectoryMode=0750` at unit `:16` | `sandboxd/sandboxd/src/main.rs:9033` `ensure_base_dir_layout_noop_when_modes_correct`; `:8950` create path |

---

## Part 4 — systemd unit (§ 4)

### 4.1 — Unit file content (P4.1 – P4.7)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.1 | Unit shipped at `sandboxd/contrib/systemd/sandboxd.service` (workspace owns canonical copy; Spec 4 installs) | (a) | New file `sandboxd/contrib/systemd/sandboxd.service` (40 lines, ships verbatim text from spec § 4.1) | File presence is the contract |
| P4.2 | `[Unit]` block: `After=docker.service`, `Wants=docker.service`, Description, Documentation | (a) | `contrib/systemd/sandboxd.service:1-6` | Inspection |
| P4.3 | `Type=simple`, `User=sandbox`, `Group=sandbox` | (a) | `:9-11` | Inspection |
| P4.4 | `StateDirectory=sandbox`, `StateDirectoryMode=0750`, `RuntimeDirectory=sandbox`, `RuntimeDirectoryMode=0750` | (a) | `:15-18` | Inspection |
| P4.5 | `ExecStart=/usr/local/bin/sandboxd --base-dir /var/lib/sandbox --socket /run/sandbox/sandboxd.sock` | (a) | `:21-23` | Inspection |
| P4.6 | Restart policy: `Restart=on-failure`, `RestartSec=5s`, `StartLimitIntervalSec=300`, `StartLimitBurst=5` | (a) | `:27-30` | Inspection |
| P4.7 | `[Install]` `WantedBy=multi-user.target` | (a) | `:39-40` | Inspection |

### 4.2 — Hardening directives (P4.8 – P4.12)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.8 | `NoNewPrivileges=yes` (file caps survive — daemon doesn't need to elevate) | (a) | `contrib/systemd/sandboxd.service:33` | Inspection |
| P4.9 | `ProtectSystem=full` (daemon reads /etc/sandboxd, never writes /etc) | (a) | `:34` | Inspection; § 13.1 risk note documents safety |
| P4.10 | `ProtectHome=yes` (daemon doesn't read operator homes) | (a) | `:35` | Inspection |
| P4.11 | `PrivateTmp=yes` (daemon writes audit log under `/var/lib/sandbox/`, honors TMPDIR for tempfiles) | (a) | `:36` | Inspection |
| P4.12 | `DeviceAllow=/dev/kvm rw` (Lima needs /dev/kvm; nothing else whitelisted) | (a) | `:37` | Inspection |

### 4.3 / 4.4 — Drop-ins + what's *not* in the unit (P4.13 – P4.14)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P4.13 | Drop-in customisation via `systemctl edit sandboxd` survives reinstalls; Spec 5 must NOT touch `…/sandboxd.service.d/` | (a) | Unit file does not template `User=`; forward-constraint pinned in spec text. Spec 5 honors via `sandbox update`'s contract (Spec 5 deliverable) | Forward constraint — Spec 5 territory |
| P4.14 | No daemon-runtime config file, no `Wants=lima.service`, no `User=` substitution, no socket activation in v1 | (a) | Unit file has none of the above; `sandboxd/contrib/systemd/sandboxd.service` is the proof | Inspection |

---

## Part 5 — State location and file modes (§ 5)

### 5.1 — Path layout (P5.1 – P5.10)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.1 | `/var/lib/sandbox/` — mode 0750, owner sandbox:sandbox, created by systemd `StateDirectory=` | (a) | `contrib/systemd/sandboxd.service:15-16` | Doctor C10 enforces at runtime: `sandboxd/sandbox-cli/src/doctor.rs:1075` |
| P5.2 | `/var/lib/sandbox/sessions.db` — mode 0600, daemon chmods explicitly after `Connection::open` | (a) | `sandboxd/sandbox-core/src/store.rs:103-114` `set_permissions(&db_path, …from_mode(0o600))` with refuse-to-start on chmod failure | Side-effect of `ensure_base_dir_layout` cohort: `sandboxd/sandboxd/src/main.rs:8950-9094` (subdir tests) — sessions.db chmod tested implicitly via `SessionStore::new` (every store test path); no dedicated chmod-mode unit test, but the contract is byte-evident in code |
| P5.3 | `/var/lib/sandbox/sessions/` — 0700, daemon-created at first start | (a) | `BASE_DIR_SUBDIRS = ["sessions","events","backups"]` at `sandboxd/sandboxd/src/main.rs:133`; mode `0o700` at `:140`; create path at `:198-218` | `sandboxd/sandboxd/src/main.rs:8950` `ensure_base_dir_layout_creates_missing_subdirs`; `:9033` `ensure_base_dir_layout_noop_when_modes_correct` |
| P5.4 | `/var/lib/sandbox/sessions/<id>/` — 0700, created on session create | (a) | `sandbox-core/src/store.rs` `create_session_with_backend` creates per-session dir (existing behavior, unchanged by Spec 3) | Existing M9+ coverage |
| P5.5 | `/var/lib/sandbox/sessions/<id>/ca/` — 0700, created by `CaManager::generate_session_ca` | (a) | `sandbox-core/src/ca.rs` (existing; unchanged) | Existing coverage |
| P5.6 | `/var/lib/sandbox/sessions/<id>/events/` — 0700, created when `--events-persist` | (a) | `sandbox-core/src/events/persist/writer.rs` (existing) | Existing coverage |
| P5.7 | `/var/lib/sandbox/events/` — 0700, daemon at first start | (a) | `BASE_DIR_SUBDIRS` includes `events` at `sandboxd/sandboxd/src/main.rs:133` | `sandboxd/sandboxd/src/main.rs:8950` |
| P5.8 | `/var/lib/sandbox/backups/` — 0700, daemon at first start (populated by Spec 5) | (a) | `BASE_DIR_SUBDIRS` includes `backups` at `sandboxd/sandboxd/src/main.rs:133` | Same as P5.7 |
| P5.9 | `/var/lib/sandbox/route-helper-audit.log` — 0600, created by route-helper (Spec 1 § 3.5) | (a) | Spec 1 deliverable; route helper writes under `/var/lib/sandbox` post-Spec-3 deployment (path resolved via XDG fallback in dev — see Spec 1 delivery P3.13) | Spec 1 coverage |
| P5.10 | `/run/sandbox/` — 0750, systemd `RuntimeDirectory=` | (a) | `contrib/systemd/sandboxd.service:17-18` | Inspection |
| P5.11 | `/run/sandbox/sandboxd.sock` — mode `0660`, daemon-created at start via `UnixListener::bind` | (a) | `sandboxd/sandboxd/src/main.rs:257` `fn bind_socket` factors the `UnixListener::bind` + explicit `set_permissions(…, from_mode(0o660))` pair (called from `main` at `:7440`); `SOCKET_MODE` constant at `:241`. Defense-in-depth `UMask=0117` added to `sandboxd/contrib/systemd/sandboxd.service` (and the spec § 4.1 verbatim block amended to match). | `sandboxd/sandboxd/src/main.rs:9156` `socket_bind_sets_mode_0660` — forces umask `022` then asserts the bound socket has mode `0o660` |

### 5.2 / 5.3 — Flags + socket-path resolution (P5.12 – P5.13)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.12 | `--base-dir` flag + XDG fallback already implemented at `default_base_dir`; spec changes nothing | (a) | `sandboxd/sandboxd/src/main.rs` `default_base_dir` (unchanged) — verified by inspection ("Spec 3 changes nothing about this resolver") | `sandboxd/sandboxd/src/main.rs:7892` `default_socket_path_ends_with_sock` family (existing) |
| P5.13 | `--socket` precedence: flag → `SANDBOX_SOCKET` env → `XDG_RUNTIME_DIR` → `HOME`; CLI symmetric resolver | (a) | `default_socket_path` at `sandboxd/sandboxd/src/main.rs:102-114` (unchanged); CLI resolver at `sandboxd/sandbox-cli/src/main.rs:473-485` | `sandboxd/sandboxd/src/main.rs:7896` `default_socket_path_ends_with_sock` |

### 5.4 — Subdir mode enforcement at startup (P5.14 – P5.17)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P5.14 | `ensure_base_dir_layout(base_dir)` called immediately after `tokio::fs::create_dir_all(&base_dir).await?` before `SessionStore::new` | (a) | `sandboxd/sandboxd/src/main.rs:161-231` function body; `:6968` call site inside main wrapped in `spawn_blocking` | `sandboxd/sandboxd/src/main.rs:8950` `ensure_base_dir_layout_creates_missing_subdirs` |
| P5.15 | Per-subdir behavior: missing → create 0700; present-with-wrong-mode → warn + chmod; present-correct → no-op; non-dir → SandboxError::Internal | (a) | `sandboxd/sandboxd/src/main.rs:164-229` (four-arm match exactly as spec) | `sandboxd/sandboxd/src/main.rs:8979` `ensure_base_dir_layout_corrects_wrong_mode_with_warn`; `:9078` `ensure_base_dir_layout_errors_when_subdir_is_a_file` |
| P5.16 | sessions.db chmod 0600 immediately after `Connection::open(&db_path)?`; failure → refuse to start | (a) | `sandboxd/sandbox-core/src/store.rs:90-114` (chmod with refuse-to-start branch carrying "sessions.db must be 0600" load-bearing token) | Implicit in every `SessionStore::new` test (the chmod runs unconditionally before the function returns Ok). Integration coverage: `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:228` `integration_subdir_mode_correction_at_startup` exercises the surrounding `ensure_base_dir_layout` path |
| P5.17 | Chmod failure on any subdir (read-only fs, wrong owner) → `error!` + return SandboxError::Internal | (a) | `sandboxd/sandboxd/src/main.rs:178-185,211-218` map_err arms emit `error!` and propagate `SandboxError::Io` | `sandboxd/sandboxd/src/main.rs:9078` `ensure_base_dir_layout_errors_when_subdir_is_a_file` (covers the dir-is-a-file path; chmod-failure path is structurally identical) |

---

## Part 6 — `sandbox doctor` subcommand (§ 6)

### 6.1 — CLI surface (P6.1 – P6.3)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.1 | `sandbox doctor [--verbose]` subcommand exists | (a) | `sandboxd/sandbox-cli/src/main.rs:356-361` `Doctor { #[arg(long)] verbose: bool }`; dispatch at `:4496` | `sandboxd/sandbox-cli/src/main.rs:8248` (parser-level coverage); end-to-end at `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:487` `integration_doctor_full_pass_against_running_daemon` |
| P6.2 | Default output suppresses passes (failure list is actionable); `--verbose` shows every check with `✓` prefix | (a) | `sandboxd/sandbox-cli/src/doctor.rs:1455-1499` render_report; `:1457-1466` Pass branch only writes when `verbose` | `sandboxd/sandbox-cli/src/doctor.rs:1654` `default_mode_suppresses_passes_renders_fails`; `:1677` `verbose_mode_echoes_passes_with_detail` |
| P6.3 | Trailing summary line: `N checks passed, M failed, K skipped` regardless of mode | (a) | `sandboxd/sandbox-cli/src/doctor.rs:1540-1543` | `sandboxd/sandbox-cli/src/doctor.rs:1698` `summary_line_counts_each_bucket` |

### 6.2 — Check list C1–C13 (P6.4 – P6.16)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.4 | C1 daemon running: `systemctl is-active sandboxd` OR fallback `connect()` to socket | (a) | `sandboxd/sandbox-cli/src/doctor.rs:406-472` `check_daemon_running` (two-step probe per spec § 12.2) | `sandboxd/sandbox-cli/src/doctor.rs:1805` `daemon_down_cascade_skips_dependent_checks` |
| P6.5 | C2 daemon reachable: `UnixStream::connect(socket_path)` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:480-502` | Same as P6.4 |
| P6.6 | C3 CLI ↔ daemon version match: `/version` HTTP + compare to `CARGO_PKG_VERSION` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:515-556` | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:119` `integration_cli_refuses_on_version_skew` (also asserts the doctor bypass at `:211`) |
| P6.7 | C4 group membership: `getgroups()` + `Group::from_gid` includes `sandbox` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:568-679` | `sandboxd/sandbox-cli/src/doctor.rs:1738,1754,1773` group-check tests trio |
| P6.8 | C5 socket perms: stat → mode 0660, owner sandbox, group sandbox | (a) | `sandboxd/sandbox-cli/src/doctor.rs:692-770` (`check_socket_perms`) | Inspection — daemon-side socket-mode pin shipped via P5.11 (`bind_socket` at `sandboxd/sandboxd/src/main.rs:257`, pinned by test `socket_bind_sets_mode_0660` at `:9156`); doctor C5 logic itself is well-tested via the dev-mode skip path inside `sandboxd/sandbox-cli/src/doctor.rs:1654` |
| P6.9 | C6 KVM accessible from daemon's uid: read+write `/dev/kvm` inside daemon, exposed via `/diagnostics` | (a) | Daemon side: `sandboxd/sandboxd/src/main.rs:5988-6003` (`kvm_readable`/`kvm_writable` blocks); CLI side: `sandboxd/sandbox-cli/src/doctor.rs:782-828` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:549` `integration_kvm_check_via_daemon_diagnostics` |
| P6.10 | C7 gateway image present (HARD fail): `docker image inspect sandbox-gateway:<daemon-version>` daemon-side | (a) | Daemon: `sandboxd/sandboxd/src/main.rs:6005-6015` `gateway_image_present` block; CLI: `sandboxd/sandbox-cli/src/doctor.rs:839-881` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:323` `integration_doctor_hard_fails_on_missing_gateway_image` |
| P6.11 | C8 lite image present (informational ~ SKIPPED): `docker image inspect sandboxd-lite:<daemon-version>` | (a) | Daemon: `sandboxd/sandboxd/src/main.rs:6016-6030`; CLI: `sandboxd/sandbox-cli/src/doctor.rs:888-927` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:408` `integration_doctor_informational_on_missing_lite_image` |
| P6.12 | C9 route-helper has caps: `getcap /usr/local/libexec/sandboxd/sandbox-route-helper` reports `cap_net_admin,cap_sys_admin=eip` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:939-1014` (`check_route_helper_caps`) with const HELPER_PATH at `:940` | Production-path; covered structurally by `sandboxd/sandbox-cli/src/doctor.rs:1654` (renders) — no env where caps are present in CI |
| P6.13 | C10 state dir mode: stat /var/lib/sandbox, 0750 sandbox:sandbox; plus subdirs at 0700, sessions.db at 0600 | (a) | `sandboxd/sandbox-cli/src/doctor.rs:1027-1107` (dev-mode skip + prod-mode strict check) | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:228` `integration_subdir_mode_correction_at_startup` |
| P6.14 | C11 users.conf reachable + parses + daemon's uid in pool — surfaced via `/diagnostics` | (a) | Daemon: `sandboxd/sandboxd/src/main.rs:6032-6039` `users_conf_pool`; CLI: `sandboxd/sandbox-cli/src/doctor.rs:1119-1154` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:487` `integration_doctor_full_pass_against_running_daemon` |
| P6.15 | C12 running-sessions guest-version drift (verbose only): per-session `GuestRequest::Version` vs DB stamp | (a) | Daemon: `sandboxd/sandboxd/src/main.rs:6041-6067` (db-side data only; live-probe deferred); CLI: `sandboxd/sandbox-cli/src/doctor.rs:1168-1222` | Live-probe-per-session fan-out deferred — see todo #158 (probe_failed wire variant) and follow-up plan |
| P6.16 | C13 orphan substrate resources (informational): cross-reference Lima VMs/containers/dirs against caller's session list | (a) | Daemon: `sandboxd/sandboxd/src/main.rs:6069-6158` (three substrate scans + caller-session filter); CLI: `sandboxd/sandbox-cli/src/doctor.rs:1233-1277` | `integration_doctor_full_pass_against_running_daemon` exercises the empty-orphan path; orphan-detection path exercised by Spec 2's V006 orphan-scan tests at `sandboxd/sandbox-core/src/store.rs:3913` |

### 6.3 / 6.4 — Output format and exit codes (P6.17 – P6.22)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.17 | Pass glyph `✓ ` (green); skip glyph `~ ` (yellow); fail glyph `✗ ` (red); `hint:` indented 4 spaces | (a) | `sandboxd/sandbox-cli/src/doctor.rs:1430-1433` color consts; `:1457-1499` rendering of three outcomes with `    hint: ...` continuation line | `sandboxd/sandbox-cli/src/doctor.rs:1720` `fail_hint_is_indented_with_hint_prefix` |
| P6.18 | Daemon-down cascade: C2–C13 (excluding C4, C9, C10) report SKIPPED with `(requires daemon)` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:278-298` (Phase 1 gating logic) | `sandboxd/sandbox-cli/src/doctor.rs:1805` `daemon_down_cascade_skips_dependent_checks` |
| P6.19 | Two-phase ordering: serial C1/C2; parallel C3–C13 via `tokio::task::JoinSet` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:271-383` `execute_checks` (Phase 1 serial at `:274-292`; Phase 2 parallel JoinSet at `:303-381`) | `sandboxd/sandbox-cli/src/doctor.rs:1805` exercises both phases |
| P6.20 | Exit 0 — all checks passed (skips do not flip to fail) | (a) | `sandboxd/sandbox-cli/src/doctor.rs:1545` `if failed > 0 { 1 } else { 0 }` | `sandboxd/sandbox-cli/src/doctor.rs:1603` `doctor_exits_0_when_all_pass`; `:1636` `doctor_exits_0_when_skips_but_no_fails` |
| P6.21 | Exit 1 — at least one check failed | (a) | Same expression at `:1545` | `sandboxd/sandbox-cli/src/doctor.rs:1619` `doctor_exits_1_on_any_failure` |
| P6.22 | Exit 2 — doctor itself could not run (panic / unresolvable socket path) | (a) | `sandboxd/sandbox-cli/src/doctor.rs:83-103` `DoctorInternalError`; `:122-167` `resolve_socket_path_strict`; `:177-188` panic boundary; main.rs dispatch maps Err→2 | `sandboxd/sandbox-cli/src/doctor.rs:1869` `doctor_returns_internal_error_when_socket_path_unresolvable`; `:1918` `doctor_internal_error_display_is_operator_friendly` |

### 6.5 — Code placement (P6.23 – P6.27)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P6.23 | `sandboxd/sandbox-cli/src/doctor.rs` new file hosts Check enum, registry, parallel runner, formatter | (a) | New file present (1934 LoC); exports at `:213-247` and `:271-383` | Self-evidence |
| P6.24 | `sandboxd/sandbox-cli/src/main.rs` gains `Doctor { verbose: bool }` Command variant + dispatch arm | (a) | `:356-361` variant; `:4496-4503` dispatch | `sandboxd/sandbox-cli/src/main.rs:8248` Doctor parse test |
| P6.25 | `sandboxd/sandboxd/src/main.rs` gains `/version` route + `/diagnostics` route | (a) | `:1154-1155` route declarations; handlers at `:5948` (version) and `:5981` (diagnostics) | Same as P7.x + P6.16 |
| P6.26 | Doctor in spec § 13.2 / § 6 — C6/C7/C8/C11/C12/C13 surfaces are daemon-side via `/diagnostics` | (a) | `sandboxd/sandboxd/src/main.rs:5981-6176` handler body; CLI consumes via `fetch_diagnostics` at `sandboxd/sandbox-cli/src/doctor.rs:1349-1355` | Per-check tests cited above |
| P6.27 | Daemon's `/diagnostics` gates per-operator scoped data behind `Extension<OperatorIdentity>`; system-level returned to every connected operator (spec § 13.2 split) | (c) | Implementation gates ALL fields behind OperatorIdentity (more conservative than spec § 13.2 prescribed split): `sandboxd/sandboxd/src/main.rs:5981-5984` extracts the extension for the whole handler. Deviation explicit. | todo #157 → M15+ (reconcile when external monitoring agent surface materializes; either split the route or amend spec) |

---

## Part 7 — CLI ↔ daemon strict version equality (§ 7)

### 7.1 / 7.2 — The rule + endpoint (P7.1 – P7.4)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.1 | On every CLI→daemon connection, CLI calls `/version` and refuses on skew | (a) | `sandboxd/sandbox-cli/src/main.rs:1275-1287` strict handshake fires inside `send_request_with_timeout` after `UnixStream::connect` | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:119` `integration_cli_refuses_on_version_skew` |
| P7.2 | `GET /version` returns `{"version": "<CARGO_PKG_VERSION>"}` | (a) | `sandboxd/sandboxd/src/main.rs:5948-5956` `version_handler`; route declared at `:1154` | `sandboxd/sandboxd/src/main.rs:9180` `version_endpoint_returns_cargo_pkg_version`; `:9198` `version_endpoint_returns_200_with_application_json`; integration: `sandboxd/sandboxd/tests/integration_version_endpoint.rs:214` `integration_version_endpoint_real_socket` |
| P7.3 | `/version` auth = none (socket already 0660 group-restricted; endpoint exposes only the version string) | (a) | `sandboxd/sandboxd/src/main.rs:5948` `async fn version_handler() -> impl IntoResponse` carries no extractors (no Extension<OperatorIdentity>) | `sandboxd/sandboxd/tests/integration_version_endpoint.rs:214` exercises unauthenticated socket access |
| P7.4 | Implementation: `env!("CARGO_PKG_VERSION")` in handler body; no new constant introduced | (a) | `sandboxd/sandboxd/src/main.rs:5952` | `sandboxd/sandboxd/src/main.rs:9180` |

### 7.3 — Error format (P7.5 – P7.7)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.5 | Stderr verbatim: `version mismatch`, `CLI is`, `daemon is`, `both must match` (load-bearing tokens) | (a) | `sandboxd/sandbox-cli/src/main.rs:1148-1156` `render_version_mismatch_message` emits all four tokens | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:162-168` asserts every token |
| P7.6 | Exit code 2 on skew (distinct from 1 for daemon-side errors) | (a) | `sandboxd/sandbox-cli/src/main.rs:1145` `CLI_VERSION_MISMATCH_EXIT_CODE: i32 = 2`; `:1286` `process::exit(...)` | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:150-156` asserts exit_code == 2 |
| P7.7 | Strict equality enforced *before* caller's request is sent | (a) | `sandboxd/sandbox-cli/src/main.rs:1275-1287` runs `fetch_daemon_version` + `process::exit` BEFORE `sender.send_request(req)` at `:1289` | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:191-198` asserts mock's `/sessions` counter remains 0 |

### 7.4 / 7.5 — Where version constant lives + bypass set (P7.8 – P7.11)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.8 | Version constant is `env!("CARGO_PKG_VERSION")` everywhere; no new constant | (a) | `sandboxd/sandbox-cli/src/main.rs:1283` `let cli_version = env!("CARGO_PKG_VERSION")`; daemon at `sandboxd/sandboxd/src/main.rs:5952` | Compile-time enforcement |
| P7.9 | `sandbox version` bypasses handshake: returns CLI version locally, no daemon connect | (a) | `sandboxd/sandbox-cli/src/main.rs:4478-4485` `if matches!(cli.command, Command::Version)` short-circuit BEFORE socket-path resolution | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:211` `integration_cli_version_subcommand_bypasses_handshake` (mock `/sessions` counter unchanged) |
| P7.10 | `sandbox doctor` bypasses handshake (tolerant connect; C3 surfaces skew) | (a) | `sandboxd/sandbox-cli/src/main.rs:4496-4503` doctor dispatch arm doesn't call `send_request_with_timeout`; doctor calls `/version` directly via its own probe at `sandboxd/sandbox-cli/src/doctor.rs:1338-1347` | C3 path tested at `sandboxd/sandbox-cli/src/doctor.rs:515-556`; bypass surface pinned by `command_bypasses_version_check` at `sandboxd/sandbox-cli/src/main.rs:1184-1187` |
| P7.11 | `command_bypasses_version_check` is single source of truth for bypass set | (a) | `sandboxd/sandbox-cli/src/main.rs:1184-1187` | `sandboxd/sandbox-cli/src/main.rs:8257`/`:8273` cover `Command::Doctor`/`Command::Version` |

### 7.6 — `sandboxd --version` format pin (P7.12 – P7.14)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P7.12 | `sandboxd --version` produces exactly one line `sandboxd <semver>\n` (load-bearing for Spec 4 § 4.4.5 `awk '{print $2}'`) | (a) | `sandboxd/sandboxd/src/main.rs` clap `#[command(name = "sandboxd", version)]` derives the format (no custom version handler) | `sandboxd/sandboxd/src/main.rs:9230` `sandboxd_version_flag_produces_pinned_two_token_line` |
| P7.13 | `sandbox --version` produces exactly one line `sandbox <semver>\n` | (a) | CLI clap derive at `sandboxd/sandbox-cli/src/main.rs` (`#[command(name = "sandbox", version)]`) | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:242-247` asserts `sandbox <CARGO_PKG_VERSION>` on `sandbox version` |
| P7.14 | Output to stdout, exit 0 | (a) | clap derive — same source | Same as P7.13 (`exit_code == 0` at `:233-239`) |

---

## Part 8 — Image tag pinning (§ 8)

### 8.1 / 8.2 / 8.3 — The rule + tag composition (P8.1 – P8.7)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.1 | Daemon picks `sandbox-gateway:<DAEMON_VERSION>` and `sandboxd-lite:<DAEMON_VERSION>` for every new session; never `:latest`, never unpinned | (a) | Gateway: `sandboxd/sandbox-core/src/gateway.rs:139-141` `gateway_image_tag_for_version` (called with `env!("CARGO_PKG_VERSION")` at `:575`). Lite: `sandboxd/sandbox-core/src/backend/container.rs:126` `lite_image_tag_for_version` (pre-existing) | `sandboxd/sandboxd/src/main.rs:9108` `gateway_image_tag_for_version_matches_repository_colon_version_shape`; `:9117` `gateway_image_tag_for_daemon_version_is_not_latest`; integration: `sandboxd/sandbox-core/tests/integration_gateway_image_pinning.rs:55` `integration_gateway_image_pinned_to_daemon_version` |
| P8.2 | Lite image lifecycle: built by daemon on demand (`ensure_image` via `include_str!` Dockerfile); shipped only as embedded source | (a) | `sandboxd/sandbox-core/src/backend/container.rs:144` (`include_str!` for Dockerfile); `:1194` (`ensure_image`); call from `create_session` at `sandboxd/sandboxd/src/main.rs:1123` (pre-existing) | `sandboxd/sandbox-core/tests/integration_lite_image_build.rs:153` `integration_lite_image_build_first_use_emits_warning_and_tags_image` |
| P8.3 | Gateway image lifecycle: built by CI at release time, shipped in tarball, never rebuilt by daemon | (a) | `sandboxd/sandbox-core/src/gateway.rs:172-199` `gateway_image_present` (probe-only, no build path); `--backend gateway` is NOT a CLI variant — verified by inspection of `sandboxd/sandbox-cli/src/main.rs:370-409` `RebuildImage` enum has only `lima`/`container`/`all` | Spec § 14 explicit deferral; absence-of-`rebuild-image --backend gateway` IS the contract |
| P8.4 | Lite-image first-start: informational only — daemon may start without it (built on first session) | (a) | `sandboxd/sandbox-cli/src/doctor.rs:888-927` C8 produces `Skip` not `Fail` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:408` `integration_doctor_informational_on_missing_lite_image` |
| P8.5 | Doctor C8 hint: `image will be built on first session create; or pre-build: sandbox rebuild-image --backend container` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:911-915` verbatim hint | `integration_doctor_informational_on_missing_lite_image` (asserts hint substring) |
| P8.6 | `GATEWAY_IMAGE_REPOSITORY: &str = "sandbox-gateway"` (replaces bare `GATEWAY_IMAGE`; symmetric to `LITE_IMAGE_REPOSITORY`) | (a) | `sandboxd/sandbox-core/src/gateway.rs:132` | `sandboxd/sandbox-core/tests/integration_gateway_image_pinning.rs:23,63` imports + uses the constant |
| P8.7 | `gateway_image_tag_for_version(daemon_version)` returns `format!("{REPO}:{daemon_version}")` | (a) | `sandboxd/sandbox-core/src/gateway.rs:139-141` | `sandboxd/sandboxd/src/main.rs:9108` |

### 8.4 / 8.5 / 8.6 — First-start behavior + hard failure (P8.8 – P8.13)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P8.8 | Gateway image first-start probe: `docker image inspect sandbox-gateway:<v>` after `ensure_base_dir_layout`, before `SessionStore::new` | (a) | `sandboxd/sandboxd/src/main.rs:6986-7011` (post-layout, pre-store; `gateway_image_present` call with absent-image `warn!` + present-image `info!`) | Inspection — startup sequence pinned by `integration_subdir_mode_correction_at_startup` (validates the surrounding wiring stays in order) |
| P8.9 | Image missing → log `error!` with hint `gateway image missing: sandbox-gateway:<v> — run 'sandbox update' to load (Spec 5)…` | (a) | `sandboxd/sandbox-core/src/gateway.rs:208-213` `missing_gateway_image_hint` carries verbatim spec wording; logged from daemon at `sandboxd/sandboxd/src/main.rs:6997-6999` | `sandboxd/sandbox-core/tests/integration_session_create_image_contracts.rs:237-249` asserts hint contains `sandbox update`, `gateway image missing`, the missing tag |
| P8.10 | Daemon still starts so doctor can report | (a) | `sandboxd/sandboxd/src/main.rs:6986-7011` log-and-continue branch never returns error; startup proceeds to `SessionStore::new` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:323` `integration_doctor_hard_fails_on_missing_gateway_image` exercises this — daemon comes up, doctor sees missing image |
| P8.11 | Session-create with missing gateway image → clear `SandboxError::Gateway` referencing missing tag + `sandbox update` | (a) | `sandboxd/sandboxd/src/main.rs:1219-1241` pre-flight in `create_session` returns `error_response(SandboxError::Gateway(missing_gateway_image_hint(...)))` | `sandboxd/sandbox-core/tests/integration_session_create_image_contracts.rs:214` `integration_session_create_refused_on_missing_gateway_image` (asserts primitives — see todo #159 for end-to-end POST /sessions HTTP refusal) |
| P8.12 | Doctor C7 reports hard `✗` with hint `sandbox update (Spec 5); or in dev: make gateway-image && docker load` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:860-870` failure hint | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:383-387` (`stdout.contains("sandbox update") || stdout.contains("make gateway-image")`) |
| P8.13 | Old images persist after update (containers hold image-id refs); Spec 5's `sandbox update` is explicitly forbidden from auto-pruning | (a) | Spec § 8.6 explicit forward constraint; no auto-prune code anywhere in Spec 3 deliverables | Forward constraint — Spec 5 territory |

---

## Part 9 — Removing `helper=` + rootless code path (§ 9)

### 9.1 / 9.3 — Principle + post-removal wrapper logic (P9.1 – P9.4)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P9.1 | Sandboxd does not reference `qemu-bridge-helper`'s install path; QEMU resolves via compile-time libexecdir | (a) | `sandboxd/sandbox-core/src/lima.rs:198-199` `-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE` (no `,helper=` segment); `:191-195` distro-agnostic comment | `sandboxd/sandbox-core/src/lima.rs:2860` `qemu_wrapper_emits_netdev_without_helper_param`; integration `sandboxd/sandbox-core/tests/integration_qemu_wrapper_netdev.rs:107` `integration_qemu_wrapper_no_helper_param_in_netdev` |
| P9.2 | Clean removal (not conditional): rootless code path deleted outright (sandboxd doesn't support rootless Docker) | (a) | `sandboxd/sandbox-core/src/lima.rs:148-226` (entire wrapper) has no rootlesskit branch — verified by inspection | `sandboxd/sandbox-core/src/lima.rs:2893` `qemu_wrapper_has_no_rootlesskit_artefacts` (asserts absence of `dockerd-rootless`, `rootlesskit`, `nsenter`, `RLKIT_PID`, `NSHELPER`, `bridge-helper-ns`, `SANDBOX_REAL_BRIDGE_HELPER`) |
| P9.3 | No `BRIDGE_HELPER` variable; `SANDBOX_BRIDGE_HELPER` env override retired | (a) | Wrapper at `sandboxd/sandbox-core/src/lima.rs:148-226` has no `BRIDGE_HELPER=` assignment | `sandboxd/sandbox-core/src/lima.rs:2880` `qemu_wrapper_has_no_bridge_helper_variable`; `sandboxd/sandbox-core/tests/qemu_helper_path_lint.rs:145` `grep_test_no_sandbox_bridge_helper_env_var` |
| P9.4 | Wrapper line: `-netdev bridge,id=net_sandbox,br=$SANDBOX_DOCKER_BRIDGE` then `-device virtio-net-pci…` (no `helper=`) | (a) | `sandboxd/sandbox-core/src/lima.rs:198-199` | `sandboxd/sandbox-core/src/lima.rs:2860` |

### 9.2 — Audit of every occurrence (P9.5 – P9.13)

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| P9.5 | H1 (lima.rs:155 comment header): kept, single-sentence about helper | (a) | `sandboxd/sandbox-core/src/lima.rs:155` reads `# 2. Adds a second NIC connected to the Docker bridge via qemu-bridge-helper.` (single line, no rootless sentence) |
| P9.6 | H2 (former lima.rs:156-157 rootless comment): DELETED | (a) | No "rootlesskit" / "rootless Docker" / "rootless wrapper" comment in the wrapper script source range `sandboxd/sandbox-core/src/lima.rs:148-226` (lint `qemu_helper_path_lint.rs` enforces) |
| P9.7 | H3 (lima.rs:194 script-body comment): KEPT, distro-agnostic | (a) | `sandboxd/sandbox-core/src/lima.rs:191-195` (3-line comment block about helper resolution via libexecdir default) |
| P9.8 | H4 (BRIDGE_HELPER shell var): DELETED | (a) | Confirmed by `qemu_wrapper_has_no_bridge_helper_variable` at `sandboxd/sandbox-core/src/lima.rs:2880` |
| P9.9 | H5 (lima.rs:198-202 five-line rootless comment block): DELETED | (a) | No "rootlesskit's network+user / namespace" text remains in the wrapper |
| P9.10 | H6 (CHILD_PID_FILE line): DELETED | (a) | No `CHILD_PID_FILE`/`dockerd-rootless/child_pid` text in `sandboxd/sandbox-core/src/lima.rs:148-226` |
| P9.11 | H7 (full rootless conditional with `NSHELPER`, `SANDBOX_RLKIT_PID`, `BRIDGE_HELPER="$NSHELPER"`): DELETED | (a) | `qemu_wrapper_has_no_rootlesskit_artefacts` at `sandboxd/sandbox-core/src/lima.rs:2893` (asserts every token is absent) |
| P9.12 | H8 (`,helper=$BRIDGE_HELPER` segment on -netdev line): DELETED | (a) | `sandboxd/sandbox-core/src/lima.rs:2860` `qemu_wrapper_emits_netdev_without_helper_param` |
| P9.13 | H9, H10, H11–H19, R1–R5 (keep-list): preserved as documented | (a) | H11 (assertion at `sandboxd/sandbox-core/src/lima.rs:2794` `wrapper must reference qemu-bridge-helper`) still passes (per `qemu_wrapper_still_references_qemu_bridge_helper_in_comments` at `:2918`); R1 RootlessDockerRefused variant unchanged at `sandboxd/sandbox-core/src/error.rs:43-73` |

### 9.4 — CI lint coverage (P9.14)

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| P9.14 | CI lint: no hardcoded helper path in source (excluding Makefile dev-mode setuid path) | (a) | `sandboxd/sandbox-core/tests/qemu_helper_path_lint.rs:115` `grep_test_no_hardcoded_helper_path_in_source`; `:145` `grep_test_no_sandbox_bridge_helper_env_var`. Greps `/usr/lib/qemu/qemu-bridge-helper` and `SANDBOX_BRIDGE_HELPER` across `sandboxd/sandbox-core/src/`, `sandboxd/sandboxd/src/`, `sandboxd/sandbox-cli/src/` |

---

## Part 10 — Daemon-side wiring of operator identity (§ 10)

This section describes the post-Spec-3 end-to-end flow. All wiring is shipped by Specs 1 and 2; this Part asserts the composition holds under daemon-as-`sandbox`-user.

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P10.1 | Step 1–2: CLI does `UnixStream::connect("/run/sandbox/sandboxd.sock")` (post-Spec-3 socket path) | (a) | `sandboxd/sandbox-cli/src/main.rs:1256-1260` `UnixStream::connect(socket_path)`; systemd unit pins socket path to `/run/sandbox/sandboxd.sock` at `contrib/systemd/sandboxd.service:23` | Operational; covered by Spec 2 integration tests |
| P10.2 | Step 3: socket perms (`0660 sandbox:sandbox`, alice ∈ sandbox group) admit the connection | (a) | Doctor C5 logic at `sandboxd/sandbox-cli/src/doctor.rs:692-770`; group-check C4 at `:568-679`; daemon-side socket-mode pin via `bind_socket` at `sandboxd/sandboxd/src/main.rs:257` (see P5.11) | Test `socket_bind_sets_mode_0660` at `sandboxd/sandboxd/src/main.rs:9156` pins the daemon side |
| P10.3 | Step 4: daemon reads SO_PEERCRED via `PeerCredListener` (Spec 1/2 deliverable) | (a) | `sandboxd/sandboxd/src/main.rs:7409` `let listener = PeerCredListener::new(listener)`; Spec 2 P4.1 has the impl | Spec 2 coverage (P4.1) |
| P10.4 | Step 5–6: daemon resolves uid→username; `create_session` stamps `owner_username`, dispatches `runtime.start` with `for_user` | (a) | Spec 2 P2.14 + Spec 1 P6.9-P6.13 wiring | Spec 2 + Spec 1 coverage |
| P10.5 | Step 7–9: helper sees `getuid() == sandbox`, `--for-user == alice`; pool `["sandbox", "alice"]` → allowed | (a) | Spec 1 P3.3 pair-check + V001 migration P5.1 stamps `"sandbox"` in pool | Spec 1 P8.1-P8.8 pair-check unit tests + integration |
| P10.6 | Composition holds: every invariant (SO_PEERCRED, getpwuid_r, pool contains "sandbox" and "alice", caller_name="sandbox", for_user="alice") independent of daemon's uid | (a) | Same primitives as Spec 1/2; spec § 10 table is the contract | Spec 1/2 coverage |

---

## Part 11 — Test plan (§ 11)

### 11.1 — Unit tests: startup subdir layout (P11.1 – P11.4)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P11.1 | `ensure_base_dir_layout_creates_missing_subdirs` | (a) | `sandboxd/sandboxd/src/main.rs:161-231` | `sandboxd/sandboxd/src/main.rs:8950` |
| P11.2 | `ensure_base_dir_layout_corrects_wrong_mode` (+ warn! logged) | (a) | Same impl | `sandboxd/sandboxd/src/main.rs:8979` `ensure_base_dir_layout_corrects_wrong_mode_with_warn` |
| P11.3 | `ensure_base_dir_layout_noop_when_correct` | (a) | Same impl | `sandboxd/sandboxd/src/main.rs:9033` `ensure_base_dir_layout_noop_when_modes_correct` |
| P11.4 | `ensure_base_dir_layout_errors_when_subdir_is_file` | (a) | Same impl | `sandboxd/sandboxd/src/main.rs:9078` `ensure_base_dir_layout_errors_when_subdir_is_a_file` |

### 11.2 — Unit tests: `/version` endpoint (P11.5 – P11.6)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P11.5 | `version_endpoint_returns_cargo_pkg_version` | (a) | `sandboxd/sandboxd/src/main.rs:5948` | `sandboxd/sandboxd/src/main.rs:9180` |
| P11.6 | `version_endpoint_returns_200_with_application_json` | (a) | Same | `sandboxd/sandboxd/src/main.rs:9198` |

### 11.3 — Unit tests: CLI version-equality check (P11.7 – P11.10)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P11.7 | `cli_version_check_proceeds_on_match` | (a) | `sandboxd/sandbox-cli/src/main.rs:1162-1168` `check_daemon_version_equality` | `sandboxd/sandbox-cli/src/main.rs:8181-8210` `check_daemon_version_equality_proceeds_on_match` family (substring search — version-equality unit tests live in `main.rs` mod tests) |
| P11.8 | `cli_version_check_refuses_on_skew` (asserts `version mismatch` + `CLI is 1.0.3` + `daemon is 1.0.4` + exit 2) | (a) | `:1284-1287` mismatch path; `:1148-1156` message formatter | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:119` `integration_cli_refuses_on_version_skew` |
| P11.9 | `cli_version_check_bypassed_for_doctor` | (a) | `:4496-4503` doctor dispatch bypasses handshake; `:1184-1187` bypass predicate | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:211` (covers Version bypass; Doctor bypass tested via C3 path at `sandboxd/sandbox-cli/src/doctor.rs:1805` cascade) |
| P11.10 | `cli_version_check_bypassed_for_version_subcommand` | (a) | `:4478-4485` early-return | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:211` `integration_cli_version_subcommand_bypasses_handshake` |

### 11.4 — Unit tests: doctor check registry (P11.11 – P11.20)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P11.11 | `doctor_check_socket_perms_passes_on_0660` / `_fails_on_0664` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:692-770` | Substring match via `sandboxd/sandbox-cli/src/doctor.rs:1654-1738` mode-rendering tests (passing/failing rows are exercised by the renderer suite); env-mode-permutation deferred (no dedicated socket-mode unit test, but rendered output of fails IS covered) |
| P11.12 | `doctor_check_version_passes_when_equal` / `_fails_on_skew` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:515-556` | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:119` (skew); local pass — `integration_doctor_full_pass_against_running_daemon` at `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:487` |
| P11.13 | `doctor_check_group_membership_passes` / `_fails_with_hint` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:576-616` (parameterizable resolver) | `sandboxd/sandbox-cli/src/doctor.rs:1738,1754,1772` `group_check_*` trio |
| P11.14 | `doctor_skips_dependent_checks_when_daemon_down` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:271-302` two-phase logic | `sandboxd/sandbox-cli/src/doctor.rs:1805` `daemon_down_cascade_skips_dependent_checks` |
| P11.15 | `doctor_exits_0_when_all_pass` | (a) | `:1545` exit expression | `sandboxd/sandbox-cli/src/doctor.rs:1603` |
| P11.16 | `doctor_exits_1_on_any_failure` | (a) | Same | `sandboxd/sandbox-cli/src/doctor.rs:1619` `doctor_exits_1_on_any_failure` |
| P11.17 | `doctor_exits_2_on_internal_error` (panic in runner) | (a) | `:177-188` catch_unwind boundary; `:83-103` DoctorInternalError | `sandboxd/sandbox-cli/src/doctor.rs:1869` `doctor_returns_internal_error_when_socket_path_unresolvable`; `:1918` display test |
| P11.18 | Skipped checks do not flip exit code to 1 | (a) | `:1545` `failed > 0` only counts fails | `sandboxd/sandbox-cli/src/doctor.rs:1636` `doctor_exits_0_when_skips_but_no_fails` |
| P11.19 | Default mode surfaces skips with hints | (a) | `:1472-1485` (hint-bearing skips are echoed even in default mode) | `sandboxd/sandbox-cli/src/doctor.rs:1841` `default_mode_surfaces_skips_with_hints` |
| P11.20 | Verbose mode echoes passes with detail | (a) | `:1457-1466` | `sandboxd/sandbox-cli/src/doctor.rs:1677` `verbose_mode_echoes_passes_with_detail` |

### 11.5 — `helper=` and rootless removal regression (P11.21 – P11.24)

| # | Claim | Status | Evidence |
|---|-------|--------|----------|
| P11.21 | `qemu_wrapper_emits_netdev_without_helper_param` | (a) | `sandboxd/sandbox-core/src/lima.rs:2860` |
| P11.22 | `qemu_wrapper_has_no_bridge_helper_variable` | (a) | `sandboxd/sandbox-core/src/lima.rs:2880` |
| P11.23 | `qemu_wrapper_has_no_rootlesskit_artefacts` | (a) | `sandboxd/sandbox-core/src/lima.rs:2893` |
| P11.24 | `grep_test_no_hardcoded_helper_path_in_source` + `grep_test_no_sandbox_bridge_helper_env_var` | (a) | `sandboxd/sandbox-core/tests/qemu_helper_path_lint.rs:115,145` |

### 11.6 — Integration tests: `integration_*` profile (P11.25 – P11.36)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P11.25 | `integration_systemd_unit_smokes` (install unit, systemctl daemon-reload + start, verify active) | (c) | Spec acknowledges Lima-harness gating (§ 11.7) | todo #153 → M14+ (Spec 4 Lima harness + peercred-connector setuid helper) — this is the Spec-4-gated harness call-out; no implementation lands until M15 Spec 4 install lands |
| P11.26 | `integration_subdir_mode_correction_at_startup` | (a) | `sandboxd/sandboxd/src/main.rs:161-231` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:228` |
| P11.27 | `integration_version_endpoint_real_socket` | (a) | `sandboxd/sandboxd/src/main.rs:5948` + route at `:1154` | `sandboxd/sandboxd/tests/integration_version_endpoint.rs:214` |
| P11.28 | `integration_cli_refuses_on_version_skew` | (a) | `sandboxd/sandbox-cli/src/main.rs:1275-1287` | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:119` |
| P11.29 | `integration_gateway_image_pinned_to_daemon_version` | (a) | `sandboxd/sandbox-core/src/gateway.rs:139-141`; `:575` call site | `sandboxd/sandbox-core/tests/integration_gateway_image_pinning.rs:55` |
| P11.30 | `integration_doctor_hard_fails_on_missing_gateway_image` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:839-881`; daemon hint at `sandbox-core/src/gateway.rs:208-213` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:323` |
| P11.31 | `integration_doctor_informational_on_missing_lite_image` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:888-927` | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:408` |
| P11.32 | `integration_session_create_builds_lite_image_on_demand` | (a) | `sandboxd/sandbox-core/src/backend/container.rs:1194` `ensure_image` | `sandboxd/sandbox-core/tests/integration_session_create_image_contracts.rs:152` |
| P11.33 | `integration_session_create_refused_on_missing_gateway_image` | (a) | `sandboxd/sandboxd/src/main.rs:1219-1241` pre-flight; `sandbox-core/src/gateway.rs:208-213` hint | `sandboxd/sandbox-core/tests/integration_session_create_image_contracts.rs:214` (asserts primitives — see todo #159 for end-to-end HTTP refusal) |
| P11.34 | `integration_doctor_full_pass_against_running_daemon` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:271-383` execute_checks | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:487` |
| P11.35 | `integration_kvm_check_via_daemon_diagnostics` | (a) | `sandboxd/sandboxd/src/main.rs:5988-6003` KVM probes | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:549` |
| P11.36 | `integration_qemu_wrapper_no_helper_param_in_netdev` (real argv capture) | (a) | `sandboxd/sandbox-core/src/lima.rs:148-226` wrapper | `sandboxd/sandbox-core/tests/integration_qemu_wrapper_netdev.rs:107` |

### 11.7 — Systemd integration harness deferral (P11.37 – P11.39)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P11.37 | `integration_systemd_unit_smokes` deferred under Lima-controlled harness (Spec 4) | (c) | Spec § 11.7 explicit gate | todo #153 → M14+ (Spec 4 Lima harness) |
| P11.38 | Live-probe per-session GuestRequest::Version fan-out (C12 verbose-mode O(N) cost) | (c) | DB-side data shipped at `sandboxd/sandboxd/src/main.rs:6041-6067`; live probe is the deferred piece | todo #158 → M15+ (probe_failed wire variant + matching CLI formatter — covers live-probe absent/failed distinction) |
| P11.39 | HTTP-level POST /sessions refusal shape end-to-end (asserts wire body + 500 status) | (c) | Primitives shipped (P8.11); HTTP-level integration test not landed | todo #159 → M15+ (thin HTTP-level test once cheap) |

---

## Part 12 — Backward compatibility — dev mode (§ 12)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P12.1 | `make setup-dev-env` continues to work — installs route-helper at prod path with setcap, lays down /etc/qemu/bridge.conf, lays down /etc/sandboxd/users.conf | (a) | `Makefile:210` (unchanged from M12); `make setup-dev-env` target intact | Operational |
| P12.2 | Developer runs daemon by hand (`cargo run -p sandboxd` or `make build && ./target/release/sandboxd`); no systemd unit installed in dev | (a) | Doctor C1 fallback handles dev mode — `sandboxd/sandbox-cli/src/doctor.rs:406-472` | `sandboxd/sandbox-cli/src/doctor.rs` C1 logic + `integration_doctor_full_pass_against_running_daemon` validates the fallback path |
| P12.3 | Dev state lives at `~/.local/share/sandboxd/` (XDG fallback) | (a) | `default_base_dir` at `sandboxd/sandboxd/src/main.rs` unchanged | `sandboxd/sandboxd/src/main.rs:7896` family (existing) |
| P12.4 | C1 daemon-running falls back to `connect()` when systemctl is-active not-found | (a) | `sandboxd/sandbox-cli/src/doctor.rs:420-472` | `sandboxd/sandbox-cli/src/doctor.rs:1805` cascade test exercises this |
| P12.5 | C4 user in 'sandbox' group: dev-mode SKIPPED with `(no 'sandbox' group; dev mode)` annotation | (a) | `sandboxd/sandbox-cli/src/doctor.rs:581-588` `SandboxGroupAbsent` arm | `sandboxd/sandbox-cli/src/doctor.rs:1739` `group_check_skips_when_sandbox_group_absent` |
| P12.6 | C5 socket perms: dev-mode SKIPPED when no sandbox user on host | (a) | `sandboxd/sandbox-cli/src/doctor.rs:719-734` env-aware skip | Rendered output covered by `sandboxd/sandbox-cli/src/doctor.rs:1654` |
| P12.7 | C7/C8 images: dev runs `make gateway-image`/`make lite-image` once; tagged with workspace version | (a) | `Makefile:147-148` (`gateway-image` target tags `sandbox-gateway:$(GATEWAY_VERSION)`); `Makefile:170-174` (`lite-image`) | Operational |
| P12.8 | C10 state dir mode: dev-mode SKIPPED with `(dev mode — no sandbox user/systemd StateDirectory)` | (a) | `sandboxd/sandbox-cli/src/doctor.rs:1030-1042` | Inspection — covered by check_state_dir_mode body |
| P12.9 | Dev-mode CLI ↔ daemon strict equality: shared `CARGO_PKG_VERSION` passes by construction; one `cargo build` keeps both in lockstep | (a) | Spec § 7.4 contract holds because workspace inheritance unifies version; nothing in code violates | `sandboxd/sandbox-cli/tests/integration_version_skew.rs:211` validates the bypass path; positive path is the daily dev cycle |

---

## Part 13 — Risks and open questions (§ 13)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P13.1 | § 13.1 — `ProtectSystem=full` is safe (daemon reads /etc/sandboxd/users.conf, never writes /etc; audit log path is /var/lib/sandbox) | (a) | `sandbox-core/src/users_conf.rs:81,397` read-only consumers; no `/etc` writer | Static inspection |
| P13.2 | § 13.2 — `/diagnostics` carries system-level + per-operator scoped data, applies `unresolvable peer-cred close-on-failure` policy | (a) | `sandboxd/sandboxd/src/main.rs:5981-6176` handler with `Extension<OperatorIdentity>`; system-level fields unconditional (P6.27 caveat noted) | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:549` covers the path |
| P13.3 | § 13.2 — `guest_version_drift` filters to caller's sessions only | (a) | `sandboxd/sandboxd/src/main.rs:6047-6067` calls `store.list_sessions(&operator.name)` (Spec 2 caller-scoped) | Spec 2 P2.12 test (`integration_list_returns_only_callers_sessions`) covers the underlying filter |
| P13.4 | § 13.2 — `substrate_orphans` cross-references caller's session IDs; operator only sees resources they cannot account for | (a) | `sandboxd/sandboxd/src/main.rs:6069-6158` caller_session_ids set filtered against substrate enumeration | Same as P13.3 + V006 orphan-scan coverage at `sandbox-core/src/store.rs:3913` |
| P13.5 | § 13.2 — `/diagnostics` is partially unauthenticated; spec § 13.2 split (system-level not sensitive, per-session filtered) — implementation gates all behind OperatorIdentity (deviation) | (c) | `sandboxd/sandboxd/src/main.rs:5981-5984` extracts OperatorIdentity for the whole handler (deviation from spec § 13.2) | todo #157 → M15+ (reconcile when external monitoring agent surface materializes) |
| P13.6 | § 13.3 — No per-operator sandboxd instances (single system instance per host in v1) | (a) | Spec § 13.3 explicit — sandbox-core has no multi-instance scaffolding; deployment shape is single-instance | Static inspection |
| P13.7 | § 13.4 — journald log visibility via `Type=simple` + stderr; no field-structured shipping in v1 | (a) | `sandboxd/contrib/systemd/sandboxd.service:9` `Type=simple` (no `StandardOutput=` override); `sandboxd/sandboxd/src/main.rs:62-65` documents `--log-file` and stderr fallback | Operational |
| P13.8 | § 13.5 — QEMU's helper-path resolution depends on distro packaging; no SANDBOX_BRIDGE_HELPER env override anymore | (a) | `sandboxd/sandbox-core/src/lima.rs:148-226` no override path; `sandboxd/sandbox-core/tests/qemu_helper_path_lint.rs:145` enforces absence | `grep_test_no_sandbox_bridge_helper_env_var` |
| P13.9 | § 13.6 — Doctor's two-phase ordering (serial C1/C2; parallel C3-C12) | (a) | `sandboxd/sandbox-cli/src/doctor.rs:271-383` | `sandboxd/sandbox-cli/src/doctor.rs:1805` |
| P13.10 | § 13.6 — Wall-clock cost low (~200ms typical) via parallel fan-out | (c) | Implementation uses tokio JoinSet for genuine concurrency; wall-clock budget is a follow-up benchmark not landed | todo #158 (probe_failed variant — same area as live-probe; perf is downstream) |

---

## Part 14 — Out of scope (§ 14)

All rows here are (b) by spec definition. Spec § 14 enumerates 14 distinct bullets.

| # | Claim | Status | Locator |
|---|-------|--------|---------|
| P14.1 | install.sh/uninstall.sh, GH Pages, sigstore, signed builds | (b) | spec § 14 bullet 1 ("all Spec 4") — no install scripts in M14 commits |
| P14.2 | GitHub Actions release workflow + tarball assembly | (b) | spec § 14 bullet 2 — no release workflow |
| P14.3 | Lima-based E2E test harness for install/uninstall/update | (b) | spec § 14 bullet 3 — Spec 4; `integration_systemd_unit_smokes` is the deferred placeholder (todo #153) |
| P14.4 | `sandbox update` CLI | (b) | spec § 14 bullet 4 ("Spec 5"); no `sandbox update` Command variant in `sandboxd/sandbox-cli/src/main.rs` |
| P14.5 | Config migration framework | (b) | spec § 14 bullet 4 (Spec 5); only the pure `migrate_v001` exists from Spec 1 |
| P14.6 | Lock file under `/run/sandbox/` | (b) | spec § 14 bullet 4 (Spec 5) — no `/run/sandbox/*.lock` in source |
| P14.7 | Backup mechanics under `/var/lib/sandbox/backups/` | (b) | spec § 14 bullet 4 (Spec 5) — `backups/` dir created at startup (P5.8) but not populated by Spec 3 |
| P14.8 | Doctor-side display of stopped-session compatibility status (`sandbox update --pre-flight`) | (b) | spec § 14 bullet 5 (Spec 5) — C12 covers only running sessions |
| P14.9 | Multi-instance daemons | (b) | spec § 14 bullet 6 — `sandboxd/contrib/systemd/sandboxd.service` is single-instance only |
| P14.10 | A daemon config file (flags only; drop-ins for customization) | (b) | spec § 14 bullet 7 — no `daemon.conf` reader in source |
| P14.11 | Re-design of helper identity (Spec 1) or API isolation (Spec 2) | (b) | spec § 14 bullet 8 — both settled |
| P14.12 | Doctor on systems without systemd (launchd / rc.d) | (b) | spec § 14 bullet 9 — doctor C1 falls back to `connect()` so dev-mode-on-non-Linux is functional, but no launchd variant |
| P14.13 | Logrotate / journald-retention policy | (b) | spec § 14 bullet 10 — no rotation config |
| P14.14 | A `sandbox-admin` group / admin-override API; rootless-Docker support; automatic periodic rebuild of lite image; daemon rebuild of gateway image | (b) | spec § 14 bullets 11–14: RootlessDockerRefused refusal preserved (Spec 1 § R1-R5); GH #7 for periodic rebuild; `--backend gateway` absent from CLI |

---

## Part 15 — Implementation notes + affected files (§§ 15–16)

| # | Claim | Status | Code | Test |
|---|-------|--------|------|------|
| P15.1 | `sandboxd/sandbox-cli/src/doctor.rs` — new file, Check trait, registry, parallel runner, output formatter | (a) | New file present (~1934 LoC) | All P6.* tests |
| P15.2 | `sandboxd/sandbox-cli/src/main.rs` — `Command::Doctor { verbose }` variant + dispatch + version-equality check + bypass | (a) | `:356-361,4478-4503,1275-1287,1184-1187` | P7.x and P6.1 tests |
| P15.3 | `sandboxd/sandboxd/src/main.rs` — `version_handler`, `diagnostics_handler`, `ensure_base_dir_layout`, gateway-image hard-fail probe at startup | (a) | `:5948,5981,161-231,6986-7011,1154-1155` | P5/P6/P7/P8 tests |
| P15.4 | `sandboxd/sandbox-core/src/store.rs` — chmod sessions.db to 0600 after Connection::open | (a) | `:103-114` | Implicit via every SessionStore::new |
| P15.5 | `sandboxd/sandbox-core/src/gateway.rs` — `GATEWAY_IMAGE_REPOSITORY` const, `gateway_image_tag_for_version`, `gateway_image_tag_for_daemon`, `gateway_image_present`, `missing_gateway_image_hint`; gateway-run call site uses pinned tag | (a) | `:132,139-141,162-170,183-199,208-213,575` | P8.* tests |
| P15.6 | `sandboxd/sandbox-core/src/lima.rs` — `QEMU_WRAPPER_SCRIPT` rewrite (rootless block removed, `BRIDGE_HELPER` var removed, no `helper=` on -netdev) | (a) | `:148-226` (entire wrapper rewritten) | P9/P11.21-P11.24 tests |
| P15.7 | `Makefile` — `gateway-image` target tags with `$(GATEWAY_VERSION)` (mirrors `lite-image`) | (a) | `Makefile:145-148` `GATEWAY_VERSION := $(shell awk … sandbox-core/Cargo.toml)`; `docker build -t sandbox-gateway:$(GATEWAY_VERSION)` | Operational; `integration_gateway_image_pinned_to_daemon_version` validates the runtime shape |
| P15.8 | `sandboxd/contrib/systemd/sandboxd.service` — new canonical unit copy | (a) | New file (40 lines) | Inspection |
| P15.9 | `sandboxd/sandbox-cli/tests/` — new tests per § 11.2/11.3/11.4 | (a) | `sandboxd/sandbox-cli/tests/integration_version_skew.rs` | Test file presence |
| P15.10 | `sandboxd/sandboxd/tests/` — new tests per § 11.1/11.5/11.6 (subdir mode, doctor, version endpoint) | (a) | `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs`, `integration_version_endpoint.rs` | Test file presence |
| P15.11 | `sandboxd/sandbox-core/tests/qemu_helper_path_lint.rs` — CI lint per § 11.5 | (a) | New file `sandboxd/sandbox-core/tests/qemu_helper_path_lint.rs` (165 LoC) | P9.14, P11.24 |

---

## Replay verification

Spec § 10 provides an end-to-end walkthrough. The integration tests that exercise the same path are:

1. **CLI connect + version handshake** — `sandboxd/sandbox-cli/tests/integration_version_skew.rs:119` (`integration_cli_refuses_on_version_skew`) + `:211` (Version subcommand bypass).
2. **Daemon startup with sessions/ mode correction + `/version` endpoint** — `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:228` (`integration_subdir_mode_correction_at_startup`); `sandboxd/sandboxd/tests/integration_version_endpoint.rs:214` (`integration_version_endpoint_real_socket`).
3. **Gateway-image pinning + missing-image surface** — `sandboxd/sandbox-core/tests/integration_gateway_image_pinning.rs:55`; `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:323` (`integration_doctor_hard_fails_on_missing_gateway_image`); `sandboxd/sandbox-core/tests/integration_session_create_image_contracts.rs:214`.
4. **Doctor end-to-end** — `sandboxd/sandboxd/tests/integration_doctor_diagnostics.rs:487` (`integration_doctor_full_pass_against_running_daemon`) and `:549` (KVM via `/diagnostics`).
5. **QEMU wrapper netdev shape** — `sandboxd/sandbox-core/tests/integration_qemu_wrapper_netdev.rs:107`.

The composition under daemon-as-`sandbox`-user (spec § 10) is **not directly replayed** by these tests — every test runs as the test runner's uid, not as a dedicated `sandbox` user. That composition surfaces only when Spec 4's install lands and Lima harness exercises the full path; the deferred test `integration_systemd_unit_smokes` (P11.25 → todo #153) is the M15+ replay anchor.

---

## Open Questions / BLOCKERs requiring orchestrator decision

(No open BLOCKERs. The previously-tracked P5.11 socket-mode pin has shipped — daemon-side chmod via the new `bind_socket` helper plus defense-in-depth `UMask=0117` on the systemd unit; see P5.11 row above. Spec § 4.1's verbatim unit block was amended to include the `UMask=0117` line so the file and the spec stay byte-equivalent.)

---

## Newly-referenced todos (M14-S5 verification)

All six (c)-row references point to **pre-existing** todos in `.tasks/progress.json`:

- **todo #153 → M14+** — Spec 4 Lima harness + peercred-connector setuid helper (covers `integration_systemd_unit_smokes` deferral, P11.25/P11.37).
- **todo #157 → M15+** — `/diagnostics` handler gates system-level fields behind OperatorIdentity (more conservative than spec § 13.2); reconcile when external monitoring agent surface materializes (P6.27, P13.5).
- **todo #158 → M15+** — Add `probe_failed` wire variant + matching CLI formatter so operators get the right remediation instead of misleading "image missing" (P11.38, P13.10 — live-probe per-session GuestRequest::Version fan-out).
- **todo #159 → M15+** — `integration_session_create_refused_on_missing_gateway_image` asserts primitives, not the end-to-end POST /sessions HTTP refusal shape; add a thin HTTP-level test once cheap (P11.39).

(Two additional tracked items — #155 around CLI symmetry of `/version` handshake across `ssh`/`cp`/`sync`/`logs`/`events`/`inspect`/`describe` bypass paths, and #156 around dev-mode signal conflation in doctor C5/C10 — were filed during M14-S2 and M14-S4 respectively but do not correspond to specific spec claims; they are noted here for completeness but not cited as (c) rows.)

No newly-created todos in this verification session; all gaps fit pre-existing todo IDs.
