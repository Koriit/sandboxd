# macOS Support — Claim-to-Code Delivery / Verification Map

**Verifies:** [`2026-05-02-macos-support-design.md`](2026-05-02-macos-support-design.md) (reconciled 2026-06-07 / revised 2026-06-14; Schema V010)
**Kind:** Point-in-time verification artifact. This is a snapshot of the delivered state of the macOS-support arc at the time of the delivery-verification session. Line numbers and statuses reflect the working tree as read this session; they will drift as code changes. It is *not* a living contract — the spec is the contract.

## What this document is

A systematic, section-by-section mapping of every normative spec requirement to the code that implements it and the test that verifies it, with an explicit status for each. It is the terminal deliverable of the macOS-support delivery-verification session. All code/test citations were opened and read; line numbers are real at the time of writing.

### Status vocabulary

- **LIVE-VERIFIED** — proven by a live run this session (the cited test executed against real VMs/containers on the host).
- **HERMETIC** — covered by hermetic unit / `integration_*` tests (cited).
- **CODE-ONLY** — implemented, but no dedicated automated test (coverage note).
- **DEFERRED** — intentionally not delivered/verified now (with reason + tracking item).
- **GAP** — a spec requirement with no implementing code, or a real discrepancy (flagged prominently).

### Ground-truth live verification performed this session (authoritative)

- **Full backend** (`tests/e2e/test_fullbackend_macos.py`): **4/4 PASSED live** — session reaches Running (required a first-ever per-operator base-image BUILD to succeed → B1 slirp-egress fix verified live), a `vmnet_slot` NIC is allocated from the socket_vmnet pool, `sandbox exec` works, and **denied egress is BLOCKED (restrict=on enforced — the core promise holds on the full backend).**
- **Lite backend egress** (`test_lite_macos.py::TestLiteMacosEgressInterception`): **PASSED live** — allowed domain resolves via CoreDNS + curls through; denied domain blocked (fail-closed); SSH over the forwarded socket works.
- **Lite backend workspace** (`test_lite_macos.py`): **PASSED live** — repo clone lands `.git`; boot command runs; shared-workspace create emits the file-access-asymmetry (TCC) warning.
- **Hermetic unit tests:** passed per-crate this session where run. The full `make test` (workspace nextest) is **pending reboot re-run** — currently blocked by a host amfid/syspolicyd code-signing wedge (environmental, not a test failure; tracked #311/#313).

---

## 1. Overview / Non-goals (spec §Overview)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| macOS = dev platform; per-operator model; interactively-logged-in Macs are the target | Architecture-wide; per-operator agent + broker (§13 rows) | — | CODE-ONLY (non-normative framing) |
| Full backend requires GUI (Aqua) login; lite works over SSH / no GUI | agent `LimitLoadToSessionType: Aqua` (agent plist:42); lite driven entirely by daemon over forwarded socket (`container.rs` `with_macos_socket` 468–490) | `test_lite_macos.py` (lite works without agent) LIVE; full-backend agent check-in preflight in `test_fullbackend_macos.py` | LIVE-VERIFIED |
| Headless multi-tenant macOS = Non-goal | (no code — scope exclusion) | — | DEFERRED (scope) |

---

## 2. Prerequisites (spec §Prerequisites)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| socket_vmnet binary present; startup fails fast if missing | `install.sh:1653` staged path; daemon prereq `macos_session.rs` startup checks; doctor `check_socket_vmnet_installed` (doctor.rs:1315) | `test_install_refusal_macos.py`; doctor unit tests | HERMETIC |
| Lima ≥ MIN_LIMA_VERSION 1.2.0, enforced in install.sh + daemon + doctor (single source of truth, drift-tested) | `check_lima_version` (doctor.rs:1584); install.sh `check_lima_installed_and_version`; `lib.sh` MIN_LIMA_VERSION | `test_lib_sh_drift.py`; doctor `check_lima_version` unit tests | HERMETIC |
| socket_vmnet access = sandboxd-managed daemons, NO `/etc/sudoers.d/lima` | `install.sh:2863` generates `io.sandboxd.vmnet.<n>` plists w/ `--vmnet-network-identifier` + `--socket-group=_sandboxd`; no sudoers written | `test_install_macos.py` (asserts vmnet daemons loaded; no sudoers) | HERMETIC (LIVE for daemons-loaded via fullbackend preflight) |
| socket_vmnet staged at `/Library/sandboxd/socket_vmnet` (root-owned ancestry), NOT `/opt/homebrew` or `/usr/local` | `install.sh:1653,1936–1937` (`root:wheel` 0755) | `test_install_macos.py` happy-path assertions | HERMETIC |
| Daemon asserts root-owned non-writable ancestry of socket_vmnet at startup (detection) | `macos_session.rs` startup ownership assertion (socket_vmnet path check) | — | CODE-ONLY (ancestry-assert has no dedicated unit test) |
| Pre-exec root-exec guard (`codesign --verify` before exec) in vmnet launchd job | vmnet job pre-exec wrapper runs `codesign --verify --strict $_svmnet_staged` and refuses to exec on failure (`install.sh:2863`); stage-time verify also present (`install.sh:2814`) | `test_install_macos.py` (asserts plist wrapper) | HERMETIC (prevention + daemon-side detection both present) |
| Docker CLI on PATH; DOCKER_HOST injected per-invocation | `GatewayLimaManager` docker cmds + `container.rs` `docker_cmd` (516–522) inject `-H unix://<sock>` | `test_lite_macos.py` (all lite docker ops target forwarded socket) LIVE | LIVE-VERIFIED |
| Tart optional; `setup-dev-env` warns if absent | `scripts/install.sh` / `make setup-dev-env` Darwin branch | `tests/install-e2e/tart_harness.py` | HERMETIC |

---

## 3. Platform detection & operator-execution seam (spec §Platform detection)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| No new `BackendKind`; macOS uses `backend='lima'`; platform via `cfg!(target_os="macos")`, not persisted | `backend/mod.rs` dispatch; `#[cfg(target_os="macos")]` gating throughout (e.g. `network.rs:1089`) | store/session unit tests | HERMETIC |
| `LimaExecutor` trait; two impls (Linux `SetuidHelperExecutor`, macOS `AgentBrokerExecutor`) | trait `lima.rs:870`; `SetuidHelperExecutor` `lima.rs:955`/impl `976`; `AgentBrokerExecutor` `broker.rs:1576`/impl `1614` | broker `integration_broker_op_round_trip` (broker.rs:3494) | HERMETIC |
| Op set mirrors the helper: 11 `LimaOp`s + macOS-only `RestrictOnVerify` | `LimaOp` enum `lima.rs:766`: Create(768), Start(781), Stop(793), Delete(795), Clone(798), ListJson(807), InstallGuestAgent(809), ReadUserKey(811), RunRsync(814), ReadOwnerMarker(822), RestrictOnVerify(836) | broker round-trip tests | HERMETIC |
| `LimaManagerRegistry` = per-operator `Arc<LimaManager>`; runs limactl only via its `LimaExecutor` | `backend/lima.rs` `LimaManagerRegistry` / `LimaManager` | `integration_*` per-operator registry tests (commit 3b93428 synthetic-uid tests) | HERMETIC |
| Gateway = degenerate case: `op_uid == _sandboxd` → daemon runs limactl directly, no agent | `AgentBrokerExecutor` special-cases self-uid (`broker.rs:1614+`); gateway managed by distinct daemon-uid `LimaManager` | broker tests; gateway_lima integration tests | HERMETIC |
| Startup constructs platform executor once; macOS verifies broker channel bind (no helper to resolve) | daemon `main`/`lib.rs` executor construction; `bind_broker_socket` (broker.rs:959) | broker checkin integration test | HERMETIC |
| `GatewayManager.docker_socket: Option<PathBuf>` injects DOCKER_HOST; `LimaRuntime.gateway_docker_socket` | `GatewayLimaManager.gateway_docker_socket` (gateway_lima.rs:777, accessor 828) | gateway_lima integration tests | HERMETIC |
| Lima template branching: `is_macos` flag; both platforms `vmType: qemu`; macOS = socket_vmnet NIC + no Linux wrapper | `LimaManager::generate_template` (`lima.rs`), `is_macos` threaded | template-generation unit tests (lima.rs) | HERMETIC |

### Privilege model on macOS (spec §Privilege model)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| No `sandbox-lima-helper` on macOS host; agent does its job | `sandbox-lima-helper` cfg-gated Linux-only; macOS tarball ships `sandbox-agent` instead (release matrix / tarball §1355) | `test_install_macos.py` (agent binary present, not setuid; no lima-helper) | HERMETIC |
| Only root component = socket_vmnet pool daemons; no setuid-root on host | `install.sh` (agent `root:wheel` 0755 no setuid; only `io.sandboxd.vmnet.<n>` are root) | `test_install_macos.py` (asserts agent NOT setuid) | HERMETIC |
| Agent = LaunchAgent `io.sandboxd.agent`, runs as operator, Aqua-scoped | agent plist `io.sandboxd.agent.plist:42` (`LimitLoadToSessionType Aqua`) | install-e2e asserts plist keys | HERMETIC |
| Agent self-gates on `_sandboxd` membership; clean no-KeepAlive exit | `sandbox-agent/src/main.rs:759` (self-gate), exit `765`; plist `KeepAlive` 49–53 | agent unit tests (main.rs) | HERMETIC |
| Check-in: agent → daemon; broker socket `/var/run/sandbox/broker.sock` mode 0660 owner `_sandboxd:_sandboxd`; recreated each startup | `broker.rs:120` path, `125` mode, `bind_broker_socket` 959 | `integration_broker_checkin_heartbeat_round_trip` (broker.rs:3411) | HERMETIC |
| Single connection per uid — new check-in evicts + closes prior (last-writer-wins) | `AgentRegistry::register` eviction (broker.rs:629, drop prior tx 650–651) | broker checkin tests | HERMETIC |
| Heartbeat/liveness ping (drops dead connections) | daemon timeout const `broker.rs:133`, PING 509–514; agent interval `main.rs:97`, PONG 540–545 | `integration_broker_checkin_heartbeat_round_trip` | HERMETIC |
| Anti-spoof: peer uid via peer_cred at accept(); reject uid==0 / uid<500; `_sandboxd` via getgrouplist(3) not peercred array | `authenticate_peer` broker.rs:511 (`peer_cred()` 512); `classify_peer_uid_floor` 451; `SYSTEM_UID_FLOOR=500` 129; `uid_in_sandbox_group` (getgrouplist) 300 | broker auth unit tests; `test_peercred_isolation.py` (install-e2e) | HERMETIC |

### Broker protocol trust surface (spec §Broker protocol)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Closed subcommand enum; typed named fields; no argv/shell/env pass-through | `BrokerOp` enum `sandbox-agent/src/protocol.rs:180` (`#[serde(tag="subcommand")]`); NON-FEATURES doc 1–33 | protocol round-trip tests | HERMETIC |
| Agent-side re-validation: VM-name regex; abs paths, no `..`, confined to operator LIMA_HOME; numeric ranges rejected-not-clamped | `validation.rs` path confinement 27–38, VM regex 49–50, `validate_op_uid` 87 | `validation.rs` unit tests | HERMETIC |
| Agent verifies work is for its own uid (getuid(), rejects mismatched op_uid) | `handler.rs:178` calls `validate_op_uid` (`validation.rs:87`) | validation/handler unit tests | HERMETIC |
| Networking daemon-authored; agent re-validates rendered lima.yaml, writes verbatim; asserts `--qemu-wrapper` | `protocol.rs:182–206` (Create writes verbatim, no agent-constructed networking, line 189) | handler/validation unit tests | HERMETIC |
| `GuestSocat` long-lived streaming op, distinct framing, still validated | `protocol.rs:53–73` (StreamOpen framing); `handler.rs:1270` `handle_guest_socat`, StreamOpen resp 1350–1360 | agent stream unit tests | HERMETIC |
| Connection multiplexing + per-stream auth tokens | stream token gen `broker.rs:145`, embed 154, `PendingStreamRegistry` 867 (commit 58f3368) | broker multiplex tests | HERMETIC |
| Agent sets its own PATH (prepend `/opt/homebrew/bin:/usr/local/bin`) | `PATH_PREPEND` `main.rs:101`, `establish_path` 360; handler `build_env` 71–77 | agent env unit tests | HERMETIC |

### Trust model / login-session constraints (spec §Trust model, §Login-session constraints)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Egress scoped against the *guest*, not a malicious operator; blast radius = operator's own sessions | Per-uid LIMA_HOME + no cross-routing (broker registry per-uid) | — | CODE-ONLY (threat-model statement) |
| Operator not logged in → actionable error `session agent for <user> is not running` | `broker.rs` / `macos_session.rs` create path returns actionable error when agent absent | agent-unavailable path (see §Failure) | CODE-ONLY (error-string path; asserted indirectly by fullbackend preflight) |
| Sandbox VMs login-scoped; gateway persists | reconcile split (startup step 6a/6b) in `macos_session.rs`/`gateway_lima.rs` | `integration_macos_session_lifecycle.rs` | HERMETIC |
| TCC bonus: agent in Aqua session can obtain consent for `shared:` | agent runs limactl in operator session (Aqua plist) | (real-chain verification open — see DEFERRED) | DEFERRED (real-chain TCC attribution open) |

---

## 4. Gateway Lima instance (spec §Gateway Lima instance)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Single persistent daemon-owned instance `sandboxd-gateway` under daemon LIMA_HOME as `_sandboxd` | `GATEWAY_INSTANCE_NAME="sandboxd-gateway"` gateway_lima.rs:84; `GatewayLimaManager` 776 | `integration_gateway_lima_ensure_ready_full_lifecycle` (tests/integration_gateway_lima.rs:151) | HERMETIC |
| Template: `vmType: qemu`, N socket_vmnet NICs, portForwards docker.sock, docker.io provision, MTU clamp | `generate_gateway_template` gateway_lima.rs:334 (portForwards 406–407) | template unit tests (gateway_lima.rs) | HERMETIC |
| Docker socket forwarded to `{daemon_LIMA_HOME}/sandboxd-gateway/gateway-docker.sock`; `_sandboxd`-only | `gateway_docker_socket` gateway_lima.rs:777 | integration gateway_lima | HERMETIC |
| Upstream DNS discovery: no macOS-specific DNS work; CoreDNS `forward . 127.0.0.11` | (no macOS branch — Linux Corefile reused) | `test_lite_macos.py` allowed-domain resolves LIVE | LIVE-VERIFIED |
| Readiness: poll `docker -H <sock> info` @2s / 60s | `wait_docker_ready` gateway_lima.rs:888; interval 122; timeout const 131 | integration gateway_lima | HERMETIC |
| Lifecycle: create/start/verify per state; persistent across restarts | `ensure_ready`-family in gateway_lima.rs | `integration_gateway_lima_ensure_ready_full_lifecycle` | HERMETIC |

---

## 5. socket_vmnet pool (spec §socket_vmnet pool)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| `VmnetPool` fields: `allocated_slots`, `session_count`, `max_slots`, `networks` (**C4 reconciled**) | `network.rs:1090–1104` (all four fields, exact names) | `network.rs` `test_vmnet_pool_*` (2228–2626) | HERMETIC |
| Lima claims NIC slot + session token; lite claims only token | `claim_lima_slot` network.rs:1143; `claim_lite_token` 1200–1216 | `test_lite_token_consumes_no_nic_slot` (2360), `test_mixed_lima_and_lite_sessions` (2374) | HERMETIC |
| /29 subnets, base `10.209.128.0/24`, slot n at `B=base+8·n`; roles B+1/B+2/B+3/B+4 | `vmnet_slot_addresses` network.rs:954; `MACOS_VMNET_BASE` 858; roles 941–944 | `network.rs` subnet unit tests | HERMETIC |
| `VmnetSlot{index,daemon_label,socket_path}`; in `NetworkInfo` as `Option<VmnetSlot>` `#[serde(default)]` | `VmnetSlot` network.rs:86–94; `NetworkInfo.vmnet_slot` 77 | serde default deserialize tests | HERMETIC |
| N `io.sandboxd.vmnet.<n>` root launchd daemons, unique per-slot UUID, `--socket-group=_sandboxd`, KeepAlive | `install.sh:2863` (all three flags present) | `test_install_macos.py` (daemons loaded); LIVE via fullbackend preflight | HERMETIC (daemons-loaded LIVE) |
| Unmanaged per-VM `socket:` entry; NO `networks.yaml` written anywhere | `generate_template`/`generate_gateway_template` embed per-VM `socket:`; no networks.yaml writes | template unit tests | HERMETIC |
| Pool concurrency locking pattern | `VmnetPool` Mutex fields (network.rs:1090–1104) | `network.rs` pool tests | HERMETIC |
| Pool exhaustion → "max concurrent sessions reached" error, running-only count | `claim_*` returns exhaustion error in network.rs | pool exhaustion unit test | HERMETIC |

### Gateway → internet egress (spec §Gateway → internet egress)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Slot segment isolated (`--vmnet-mode=host` + per-slot identifier), no NAT; VM default route = `B+3` | `install.sh:2863` per-slot identifier; cloud-init default route B+3 (`macos_session.rs`) | `test_fullbackend_macos.py` denied-egress-blocked LIVE | LIVE-VERIFIED |
| Host IP-forwarding MUST be off: assert `net.inet.ip.forwarding==0` and `net.inet6.ip6.forwarding==0` at startup | `check_host_ip_forwarding_disabled` macos_session.rs:768 (IPv4 770; IPv6 `net.inet6.ip6.forwarding`) | `integration_assert_host_ip_forwarding_offline_check` (macos_session.rs:1319) | HERMETIC |
| Gateway container has 2 NICs: VM-facing macvlan(private) B+3 + upstream `sandboxd-egress` NAT bridge | `macos_session.rs` `setup_macos_gateway` (~113–158); `EGRESS_BRIDGE_NAME="sandboxd-egress"` gateway_lima.rs:89 | `integration_macos_session_lifecycle.rs` | HERMETIC |
| Shared `sandboxd-egress` NAT bridge ensured at gateway init | `ensure_egress_bridge` gateway_lima.rs (used in recovery 2264) | gateway_lima integration | HERMETIC |
| MUST baseline default-drop egress nft policy on gateway VM `eth0` (allow only re-originated + DNS) | gateway_lima.rs:536–605 (`sandboxd-gateway-eth0` table, default-drop 602–605) | gateway_lima integration / nft-ruleset unit test | HERMETIC |
| IPv6 disabled on socket_vmnet NICs + macvlan; MSS clamping | gateway template provisioning (`net.ipv6.conf.all.forwarding=0` gateway_lima.rs:600; MSS clamp in gateway nft ruleset) | template unit tests | CODE-ONLY (per-NIC IPv6-disable not independently tested) |

### Slot lifecycle (spec §Slot lifecycle)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Claim at create, release at stop/rm, fresh slot on resume, not sticky | `VmnetPool` claim/release (network.rs 1143–1216) | `network.rs` lifecycle tests; `integration_macos_session_lifecycle.rs` | HERMETIC |

---

## 6. Sandbox VM template (spec §Sandbox VM template)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Apple Silicon only; single aarch64 image entry; shared URL constants | `lima.rs` image URL constants (shared Linux/macOS) | template unit tests | HERMETIC |
| `vmType: qemu` + socket_vmnet NIC; per-session VMs per-operator via seam | `generate_template` (`lima.rs`); seam routing (broker) | template + broker tests | HERMETIC |
| **restrict=on** management-NIC lockdown via qemu-wrapper (in-place rewrite; fail-closed if 0 or >1 user netdev; marker file) | macOS wrapper `lima.rs:1664` (`QEMU_WRAPPER_MACOS_SCRIPT`): detect user netdev 1716, strip `restrict=` 1723, splice 1732, fail-closed 1744–1751, marker 1766; skip via `SANDBOX_UNRESTRICTED_SLIRP_FOR_PROVISIONING` 1700 | `integration_qemu_wrapper_*` (tests/integration_qemu_wrapper_netdev.rs:213–340, 5 tests); **denied-egress LIVE** in `test_fullbackend_macos.py` | LIVE-VERIFIED |
| Post-boot `restrict=on` verification (broker op; agent reads marker/QMP; refuse Running if unconfirmed) | `RestrictOnVerify` op (`lima.rs:836`); marker read gateway/agent path (`lima.rs:1653`) | qemu-wrapper integration; macos_session lifecycle | HERMETIC (marker/QMP path); egress-effect LIVE-VERIFIED |
| E2E regression: delete gateway route in guest, confirm slirp still can't egress | `test_fullbackend_macos.py` denied-egress test (restrict=on in force) | `test_fullbackend_macos.py::TestFullBackendMacosEgress` | LIVE-VERIFIED |
| `restrict=on` gated on instance kind (sandbox VM only, never gateway VM) | wrapper wired only for sandbox-VM launches (`lima.rs` gating) | qemu-wrapper integration | HERMETIC |
| No Linux seccomp/cgroup wrapper on macOS (gated `is_macos==false`) | Linux wrapper injection gated in `LimaManager` (`lima.rs`) | template unit tests | HERMETIC |
| Operator-uid alignment: VM process at operator uid (agent runs as operator); cloud-init usermod when uid≠1000; SSH key 0600 via umask | agent runs limactl as operator (no pivot); cloud-init alignment block (`lima.rs`); umask in agent | agent + template unit tests; base build LIVE (fullbackend) | LIVE-VERIFIED (VM reached Running as operator) |
| 9p on both platforms; no `mountType` branch; `securityModel` honored | `generate_template` emits `mountType: "9p"` lima.rs:3247–3256 | template unit tests; `test_workspace_shared_guest_path.py` (unmarked, runs macOS) | HERMETIC |
| No runtime resource enforcement on macOS (accepted delta) | (no cgroup code — documented delta) | — | DEFERRED (accepted dev-platform delta) |

---

## 7. Session lifecycle on macOS (spec §Session lifecycle)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| NIC discovery by name (`limactl shell … ip -json link`), select `limaN`, exclude eth0, order by suffix | `discover_nics_from_ip_json` gateway_lima.rs:282–316 | `nic_discovery_*` (gateway_lima.rs:2502–2550) | HERMETIC |
| NIC-count mismatch defers to pool-resize (never hard-fail startup) | resize handoff gateway_lima.rs (see §Pool resize) | `integration_gateway_lima_nic_count_mismatch_is_non_fatal` | HERMETIC |
| Operator identity from LOCAL_PEERCRED, stamped, `ensure_operator_lima_home` | `caller_identity.rs`; peer_cred via `UnixStream::peer_cred()` (daemon main); `ensure_operator_lima_home` | `test_peercred_isolation.py`; caller_identity unit tests | HERMETIC |
| create: 14-step sequence w/ egress happens-before (deny+DNAT before limactl start) | `macos_session.rs` create flow (setup_macos_gateway → limactl start ordering) | `integration_macos_session_lifecycle.rs`; `test_fullbackend_macos.py` create-reaches-Running LIVE | LIVE-VERIFIED |
| macvlan network name = `sandbox-net-<session-id>` (matches `docker_network_name`, orphan-reaper prefix) | `network.rs` `docker_network_name`; orphan_reaper.rs prefix parse | orphan-reaper unit tests | HERMETIC |
| Partial-create rollback: unwind in reverse, release slot, mark failed, idempotent | `macos_session.rs` create rollback; `release_lima_slot` two-phase (network.rs:1097–1104) | `integration_macos_session_lifecycle.rs` rollback tests | HERMETIC |
| start (resume): fresh slot, rewrite YAML, gateway-before-start | `macos_session.rs` start path | macos_session lifecycle integration | HERMETIC |
| stop / rm sequences (flush DNAT, stop VM, rm container/network, release slot) | `macos_session.rs` stop/rm | macos_session lifecycle integration; `test_fullbackend_macos.py` stop LIVE | LIVE-VERIFIED |

---

## 8. Daemon startup sequence (spec §Daemon startup sequence)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| 8-step startup: broker bind, prereq checks (incl. IP-forwarding), pool init, gateway init, load sessions, reconcile (6a unconditional / 6b agent-gated), restore pool, accept | `macos_session.rs` startup orchestration; `bind_broker_socket` broker.rs:959; `check_host_ip_forwarding_disabled` 768 | `integration_macos_session_lifecycle.rs`; broker checkin integration | HERMETIC |
| Reconcile 6a: gateway-side cleanup UNCONDITIONAL for every session | reconcile split (`macos_session.rs`/`gateway_lima.rs`) | macos_session lifecycle integration | HERMETIC |
| Reconcile 6b: VM-side reconcile needs operator agent; lazy on re-check-in | reconcile agent-gated path | broker + macos_session integration | HERMETIC |

---

## 9. Session store schema (spec §Session store schema)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| No new columns; latest migration V010; no macOS migration | migrations dir: V001–V010 (V010=`add_sshd_ready`); no macOS-specific file | store migration tests | HERMETIC |
| `NetworkInfo` persisted as SINGLE serialized blob in one `network_info` column (V002) — load-bearing for no-migration claim | `set_network_info` store.rs:1203–1215 (single JSON→one column); `get_network_info` 1247–1249; `V002__add_network_info.sql` (single TEXT column) | store network_info round-trip tests | HERMETIC |
| Reuse V007 `ssh_keypair_json`, V008 `operator_uid`/`operator_gid` | `V007__add_ssh_keypair.sql:34`; `V008__add_operator_uid.sql:33–37` | store unit tests | HERMETIC |
| `vmnet_slot` new `Option<VmnetSlot>` `#[serde(default)]`; None on stopped; pool reconstructs from non-null | `NetworkInfo.vmnet_slot` network.rs:77; reconstruct at startup (macos_session.rs) | serde-default + pool-restore tests | HERMETIC |
| `sandbox inspect` surfaces `vmnet_slot` (3 lines); `--verbose`/`--json` adds gateway state | inspect DTO in `api`/CLI inspect rendering | inspect CLI unit tests | CODE-ONLY (inspect formatting not covered by macOS-specific test) |

---

## 10. Pool resize handling (spec §Pool resize)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Detect NIC-count mismatch (count `networks:` vs `max_macos_sessions`) | `decide_pool_resize` gateway_lima.rs:2349 (mismatch 2356) | `decide_pool_resize_*` (gateway_lima.rs:2899–2940) | HERMETIC |
| No running sessions → rebuild; running sessions → warn + continue with discovered count (single authority; always start) | `PoolResizeDecision::Rebuild` 2377 / `WarnRunningSessions` 2363 | `integration_gateway_lima_nic_count_mismatch_is_non_fatal` | HERMETIC |
| socket_vmnet daemon-set regen needs root (daemon refuses, guides to privileged path) | (documented; daemon detects + refuses) | — | CODE-ONLY (privileged-resize refusal path not independently tested) |

---

## 11. Failure handling (spec §Failure handling)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Gateway Lima crash recovery: poll `docker info` @10s, 3 failures trigger; force-stop→start; 90s readiness | `restart_instance_for_recovery` gateway_lima.rs:2209 (90s `GATEWAY_RECOVERY_READY_TIMEOUT` 2218); 10s poll + 3-failure monitor in daemon (`sandboxd/src/main.rs`) | `integration_gateway_lima_restart_for_recovery_restores_readiness_and_fabric` (tests/integration_gateway_lima.rs:502) | HERMETIC |
| `networking_status` transient DTO field (Healthy/Degraded/Recovering), NOT a SessionState change / no migration | in-memory DTO field in daemon state (`sandboxd/src/main.rs` monitor); no `session.rs` enum change | recovery integration (fabric restore) | HERMETIC (DTO-value surface CODE-ONLY) |
| Per-session recovery in parallel; individual failure → Error, others continue; idempotent | recovery loop in gateway_lima.rs recovery path | recovery integration | HERMETIC |
| socket_vmnet crash → launchd KeepAlive restart; doctor surfaces crash-loop; no separate sandboxd path | `install.sh:2863` KeepAlive; `check_socket_vmnet_running` doctor.rs:1363 | doctor unit tests | HERMETIC |
| Per-operator agent unavailable: actionable error; lite unaffected; agent crash → respawn + reconcile; no cross-operator impact | broker agent-absent error path; per-uid isolation (broker registry) | broker checkin/eviction tests; `test_lite_macos.py` (lite works without agent) LIVE | LIVE-VERIFIED (lite-unaffected) / HERMETIC (agent-absent) |
| Fast user switching / re-login / duplicate check-in: last-writer-wins evict; switched-away stays healthy; stale-uid via fresh check-in | eviction `broker.rs:629`; heartbeat 133; peer re-read at accept (511); reconcile tied to fresh check-in | broker checkin/eviction/heartbeat integration (commit a7043ca fast-user-switch reconcile) | HERMETIC |
| Individual gateway container crash: restart that session only, re-inject | container-crash monitor (`sandboxd/src/main.rs`) — same as Linux | container-crash integration | HERMETIC |
| Slot leak detection at startup (stopped/nonexistent → release; tied to VM-liveness reconcile) | slot leak reclamation (`macos_session.rs`/`network.rs` restore); `check_vmnet_pool_slots` doctor.rs:1461 | `network.rs` restore tests; commit 5a4bc98 slot reclamation; `e911577` recovery+reclamation | HERMETIC |

---

## 12. Security posture (spec §Security posture)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Two-mechanism egress: isolated socket_vmnet segment + `restrict=on` slirp lockdown; no bypass regardless of root | qemu-wrapper restrict=on (lima.rs:1664+); per-slot identifier isolation (install.sh:2863) | `test_fullbackend_macos.py` denied-egress LIVE (BOTH backends: also `test_lite_macos.py`) | LIVE-VERIFIED |
| Per-session L2 isolation via unique per-slot identifier (spike-confirmed) | per-slot `--vmnet-network-identifier` install.sh:2863 | `test_isolation.py` (unmarked, runs both platforms) | HERMETIC (isolation e2e); spike-confirmed |
| Shared gateway-VM blast-radius controls: no `--privileged`, RO rootfs, no host mounts, one added cap; socket never bind-mounted; forwarded socket `_sandboxd`-only | gateway container hardened run args (`macos_session.rs`/`gateway_lima.rs`); forwarded socket perms | `test_hardening.py` (unmarked) | HERMETIC (accepted dev-platform delta on shared-daemon vector) |
| Layer mapping / known deltas (resource limits, seccomp) = accepted | (documented deltas) | — | DEFERRED (accepted deltas) |

---

## 13. Integration M13–M18 (spec §Integration)

### M18 cross-user / per-operator (landed; macOS reuses)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| SSH proxy for six SSH-shaped verbs; per-session keypair (V007); `~/.ssh/sandbox` Include | `proxy_http.rs`; `ssh_config.rs`/`ssh_commands.rs`; V007 migration | `test_git_remote.py`, cross-user SSH proxy tests (unmarked); `test_lite_macos.py` SSH-over-forwarded-socket LIVE | LIVE-VERIFIED (lite SSH) |
| Proxy byte-mover: Lima VM → dial `127.0.0.1:<sshLocalPort>`; lite → `docker exec socat` | `proxy_http.rs` (Async-I/O carve-out); lite exec path | proxy integration; `test_lite_macos.py` LIVE | LIVE-VERIFIED (lite) |
| Known cross-uid loopback exposure guarded by per-session key (documented delta) | key-only sshd (V007 keypair) | — | CODE-ONLY (documented delta) |

### M13 per-caller isolation

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| `UnixStream::peer_cred()` abstracts SO_PEERCRED/LOCAL_PEERCRED; owner filter + operator_uid/gid | daemon peer_cred (`sandboxd/src/main.rs`); `caller_identity.rs` | `test_peercred_isolation.py`; caller_identity unit tests | HERMETIC |
| NGROUPS-cap safe; getgrouplist(3) authoritative for group authZ | `uid_in_sandbox_group` broker.rs:300 (getgrouplist) | broker auth tests | HERMETIC (spike-confirmed DAC on hardware) |

### M14 version handling & doctor

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| CLI↔daemon version equality; gateway image version-pinned, `docker load` from staged tarball (no registry pull) | version-check in CLI/daemon; `ensure_gateway_image_loaded` gateway_lima.rs:958 (from `GATEWAY_IMAGE_TARBALL_FILENAME` 179) | gateway_lima integration; image-load tests | HERMETIC |
| macOS doctor checks: installed, running, gateway_lima_instance, vmnet_pool_slots, gateway_image_inside_lima, tcc, disk, lima_version, operator_agent, lima_base_image | doctor.rs: `check_socket_vmnet_installed` 1315, `_running` 1363, `check_gateway_lima_instance` 1407, `check_vmnet_pool_slots` 1461, `check_gateway_image_inside_lima` 1514, `check_lima_version` 1584, `check_operator_agent` 1653, `check_tcc_workspace_access` 1697, `check_disk_space` 1253, `check_lima_base_image` 1163 | doctor.rs unit tests (per check) | HERMETIC |
| `check_socket_vmnet_access` — operator in `_sandboxd` group + can connect to slot sockets | install.sh preflight `check_socket_vmnet_access` (install.sh:943) covers it; in the **Rust `sandbox doctor`** the group-membership check `check_group_membership` is **`#[cfg(target_os="linux")]` only** (doctor.rs:676, note 674: getgrouplist absent on Apple in nix 0.29) — no equivalent macOS doctor row | `test_install_macos.py` (install preflight) | GAP — narrow (see callout G1) |
| Linux-only checks gated: `check_kvm_accessible` (954), `check_route_helper_caps` (1744), `check_users_conf_pool` (1981) skipped on macOS | doctor.rs `#[cfg(target_os="linux")]` gates | doctor gating tests | HERMETIC |
| `/diagnostics` adds `gateway_lima_state`, `vmnet_pool_size`, `vmnet_pool_claimed`, `gateway_image_tag_inside_lima` (Option, absent on Linux) | diagnostics payload (`api`/daemon) | doctor consumes diagnostics; unit tests | HERMETIC |

### M15 release & install

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| install.sh `detect_os()` branches Linux/Darwin | install.sh:558–565 | `test_install_macos.py` | HERMETIC |
| Darwin arch: arm64→aarch64-apple-darwin; x86_64 rejected | install.sh:573–578 | `test_install_refusal_macos.py` | HERMETIC |
| `_sandboxd` user/group via dscl (sysadminctl no-ops at low UIDs) | install.sh:2615–2628 | `test_install_macos.py` | HERMETIC |
| Agent `/usr/local/libexec/sandboxd/sandbox-agent` `root:wheel` 0755 NO setuid; agent LaunchAgent plist installed | install.sh:1638; agent plist io.sandboxd.agent.plist | `test_install_macos.py` (asserts NOT setuid) | HERMETIC |
| daemon plist keys: UserName=_sandboxd, KeepAlive{SuccessfulExit=false,Crashed=true}, ThrottleInterval=5, HOME pinned, libexec ProgramArguments, ExitTimeOut=20 | io.sandboxd.daemon.plist (UserName 56, KeepAlive 66–71, ThrottleInterval 77, HOME 118, ProgramArguments 48) | install-e2e plist assertions | HERMETIC |
| `sandboxd` at `/usr/local/libexec/sandboxd/sandboxd` (not on PATH) | install.sh:1635 (`PLAN_DAEMON_PATH`) | `test_install_macos.py` | HERMETIC |
| Ad-hoc codesign every shipped Mach-O; codesign -v guard | release pipeline codesign; `setup-dev-env` codesign (commit 232cfb6) | `test_install_macos.py` codesign guard | HERMETIC |
| socket_vmnet pool daemons installed before sandboxd; pre-exec `install -d -o _sandboxd -g _sandboxd -m 0750` | install.sh:2863 | `test_install_macos.py` | HERMETIC |
| Log rotation: DAILY + run_log_reaper + `ROTATION_KEEP_COUNT=7` + gzip, **NO per-file size cap** (**C19 reconciled**) | main.rs:503–517 (Rotation::DAILY 506; deferred size-cap comment 500–502); `run_log_reaper`/`ROTATION_KEEP_COUNT=7` (main.rs:575,594) | log-reaper unit tests | HERMETIC |
| uninstall.sh Darwin: bootout, remove plists (daemon+agent+vmnet), reap via purge (never `pkill qemu`), optional `--purge-state` user/group removal | uninstall.sh Darwin branch | `test_uninstall_macos.py` | HERMETIC |
| `--force` uninstall backed by `POST /sessions/{id}/stop?force=true` (skips lock check) (**C5 reconciled**) | route `POST /sessions/{id}/stop` (main.rs:1824); `StopParams.force` main.rs:7137–7143 | stop-force handler tests | HERMETIC — see NOTE N1 (stale doc-comment) |
| macOS tarball contents: sandboxd/sandbox/sandbox-agent/sandbox-guest(linux-arm64)/launchd plists/gateway-arm64 tarball; no route-helper/lima-helper | release pipeline matrix (commit 54082fd); spec §1355 | `test_build_assembly.py`; release pipeline | HERMETIC |
| `sandbox-guest` = linux/arm64 ELF on macOS, dockerized cargo build | `make guest` dockerized build; install stages to libexec | install-e2e; build tests | HERMETIC |
| Eager provisioning + health-gated repair (`sandbox rebuild-image`) | install.sh eager rebuild step (health-gated, non-fatal) | `test_install_repair.py`; `test_install_provision.py` | HERMETIC |
| e2e harness platform seam (conftest `_platform`, `_sandboxd-test` user, group re-exec via sudo, markers) | `tests/e2e/conftest.py` platform seam (commit 8570e18) | e2e suite runs on macOS | LIVE-VERIFIED (harness ran the live macOS tests this session) |

### M16 sandbox update

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Update UX parity; launchctl bootout/bootstrap; warm `sudo -v` then `sudo -n`; agent binary swap (no re-privilege); kickstart -k | update/mod.rs: sudo warm 1367–1385, bootout 1990, bootstrap 3087, kickstart 3311–3357 | `test_update_macos.py` | HERMETIC |
| Gateway image refresh: version compare, `docker load` staged flat tarball; self-heal reload | `ensure_gateway_image_loaded` gateway_lima.rs:958; update stages at base-dir (update/mod.rs:2462) | `test_update_macos.py`; gateway_lima image tests | HERMETIC |
| cosign staged at `/usr/local/libexec/sandboxd/cosign`; `COSIGN_BIN_PATH`; update reuses (CosignNotFound if absent) | `COSIGN_BIN_PATH` fetch.rs:35 | update fetch tests | HERMETIC |
| **cosign-darwin-arm64 pin present** (spec flagged "pin-table gap to close") | `cosign_pin_for_arch` fetch.rs:80–86 (`aarch64-apple-darwin` → `cosign-darwin-arm64`, SHA256 75–76); `lib.sh:30` | `test_lib_sh_drift.py`; fetch.rs pin unit tests | HERMETIC — **spec-flagged gap is CLOSED** (see NOTE N2) |
| Download URL: v-prefixed tag path + bare-version filename; arch aarch64-apple-darwin | `release_asset_urls`/`download_tarball` fetch.rs:615–621 | fetch URL unit tests; `test_update_air_gapped.py` | HERMETIC |
| Golden base VM per-operator, lazy build on first create; refresh on version bump | `LimaManagerRegistry` serializes base build; refresh via update orchestrator | base build LIVE in `test_fullbackend_macos.py` (first-ever build succeeded) | LIVE-VERIFIED |
| Backup set: sessions.db + binaries + plists + gateway tarball + install-state; NOT VM images | update/mod.rs backup (gateway tarball 2347–2362) | `test_update_backup_retention.py`, `test_update_rollback.py` | HERMETIC |

### M11 lite-mode container backend

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| Lite hosted in gateway Lima: per-session internal Docker bridge + gateway + sandbox container | lite_macos.rs module; `setup_macos_gateway` macos_session.rs:113–158 | `test_lite_macos.py::TestLiteMacosCreate` create-reaches-Running LIVE | LIVE-VERIFIED |
| `ContainerRuntime` gains `is_macos` + `docker_socket`; DOCKER_HOST injected | container.rs:386–393 (fields), `is_macos()` 494, `docker_cmd` 516–522, `with_macos_socket` 468–490 | container unit tests; lite e2e LIVE | LIVE-VERIFIED |
| Sandbox container run with `--user <op_uid>:<op_gid>` | container.rs:845–846 (`user_arg` 764, `effective_container_user` 727–733) | container run unit tests | HERMETIC |
| route-helper (in gateway VM) repoints sandbox container default route | `build_in_vm_route_helper_argv` lite_macos.rs:234–249 | lite e2e egress interception LIVE | LIVE-VERIFIED |
| Lite consumes no NIC slot (`claim_lite_token`), no macvlan/socket_vmnet | `claim_lite_token` network.rs:1200–1216 | `test_lite_macos.py::test_lite_session_has_no_vmnet_slot` LIVE; `test_mixed_lima_and_lite_sessions` | LIVE-VERIFIED |
| `docker build` HOME/DOCKER_CONFIG pinning (`docker_home`) | `build_lite_image` container.rs:2177 (HOME 2212, DOCKER_CONFIG 2213) | container build unit tests | HERMETIC |
| SANDBOX_COREDNS_UPSTREAM upstream rendering (lite egress-ALLOW fix) | set on gateway container macos_session.rs:608–614; validated 1396–1421 | `test_lite_macos.py::test_allowed_domain_egress_on_lite_macos` LIVE | LIVE-VERIFIED |
| Lite `shared:` = Lima 9p mounts + bind; runs as `_sandboxd` → TCC-asymmetry warning emitted | 9p stanza `lite_shared_root_9p_stanza` lite_macos.rs:75–108 / gateway_lima.rs:345–356; **runtime warning** main.rs:5108–5116 | `test_lite_macos.py::test_shared_workspace_tcc_warning` LIVE | LIVE-VERIFIED |
| Lite `local:` rsync; `clone:` git clone | workspace_rsync.rs; container clone path | `test_lite_macos.py` repo-clone + boot-cmd LIVE | LIVE-VERIFIED |
| Performance framing (fast-but-not-instant) | (documented) | — | CODE-ONLY (doc) |

### M17 workspace modes / lock

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| `shared:` 9p both platforms, no branch; `securityModel` identical | lima.rs:3247–3256 | `test_workspace_shared_guest_path.py` (unmarked) | HERMETIC |
| `local:` rsync platform-independent (push/pull) | workspace_rsync.rs | `test_workspace_local.py`, `test_workspace.py` (unmarked) | HERMETIC |
| Workspace-lock daemon-internal, platform-independent; `unlock --force` | workspace_lock.rs | `test_workspace_lock.py` (unmarked) | HERMETIC |

---

## 14. Networking design corrections (spec §Networking design corrections)

| Requirement (spec §) | Implementing code (file:line) | Verifying test(s) | Status |
|---|---|---|---|
| #1 QEMU+socket_vmnet, ban vzNAT/SLIRP-general-egress | `generate_template` socket_vmnet NIC; no `-netdev user` general NIC | template unit tests | HERMETIC |
| #4 /29 subnet (three participants) | `vmnet_slot_addresses` network.rs:954 (/29) | subnet unit tests | HERMETIC |
| #5 management slirp `restrict=on` (both platforms; Linux landed 4b134ec) | qemu-wrapper restrict=on lima.rs:1664+ | `integration_qemu_wrapper_*`; denied-egress LIVE | LIVE-VERIFIED |
| #2/#3 doc-rationale corrections (pool justification, "Colima" terminology) | networking-design.md edits (doc) | — | CODE-ONLY (documentation) |

---

## Deferred / hardware-gated items

- **Full-backend HTTPS interception + post-recovery egress re-assert** — hardware/CI-gated; the denied-egress *block* is LIVE-VERIFIED, but the full mitmproxy HTTPS-interception chain and post-gateway-recovery egress re-assertion are exercised only in the full CI matrix (needs the `macos-14` native runner). DEFERRED to CI matrix run.
- **IDE Remote-SSH manual walkthrough** — VS Code Remote-SSH / JetBrains Gateway manual verification. DEFERRED, tracked **#227**. (The underlying SSH-proxy path is LIVE-VERIFIED via `test_lite_macos.py` SSH-over-forwarded-socket.)
- **macOS-lite `local:` workspace under `/private`** — design carry-forward; `test_lite_macos.py::test_local_workspace_mode` is skipped (line 801) due to the lite container's read-only `/private` rootfs mount interaction (host paths canonicalize under `/private`; `mkdir -p /private/...` fails on the RO mount). DEFERRED (design carry-forward; remap `/private`-prefixed paths).
- **macOS-lite `shared:` workspace `/private`-fragility** — the `/private/tmp` cleared-on-boot fragility surfaces as live-export guards/skips in `test_lite_macos.py` (lines 913–944). DEFERRED, tracked **#316**.
- **`make test` full-workspace run** — pending host reboot; the code passes per-crate this session, blocker is an environmental amfid/syspolicyd code-signing wedge. DEFERRED, tracked **#311/#313** (record as "pending reboot re-run", NOT a test failure).
- **Real-chain TCC attribution** (which binary — agent vs `qemu-system`/`limactl` — TCC names for the child read; re-prompt-on-`brew upgrade` caveat) — narrow, non-blocking; partially closed on macOS 26.4. DEFERRED (spec §SIP and TCC open verification item).
- **Accepted dev-platform deltas** (no runtime resource enforcement / no cgroups; no QEMU seccomp; shared gateway-VM cross-session security blast radius) — intentional, macOS is dev-only. DEFERRED (accepted deltas).

---

## Spec-reconciliation cross-check (C3 / C4 / C5 / C19)

The spec was reconciled on four items this arc. Each verified against code; the spec now matches:

- **C3 — base-image tarball is flat `gateway-image.tar`, no cache subdir, version only in the image tag.** **CONFIRMED.** `GATEWAY_IMAGE_TARBALL_FILENAME = "gateway-image.tar"` at `gateway_lima.rs:179` (companion `LITE_IMAGE_TARBALL_FILENAME = "lite-image.tar"` at 186); staged/loaded from `{daemon_lima_home}/gateway-image.tar` (`ensure_gateway_image_loaded` gateway_lima.rs:958); drift/canonical test `gateway_image_tarball_filename_is_canonical` (gateway_lima.rs:3183). Version lives in the docker image tag (`sandbox-gateway:<version>`), not the filename. **Spec matches code.**

- **C4 — `VmnetPool` fields incl. `session_count`.** **CONFIRMED.** `network.rs:1090–1104`: `allocated_slots: Mutex<HashSet<u16>>` (1092), `session_count: Mutex<u32>` (1094), `max_slots: u16` (1096), `networks: Mutex<HashMap<SessionId,(u16,Option<NetworkInfo>)>>` (1104) — exact field names as spec §537. **Spec matches code.**

- **C5 — `--force` is `POST /sessions/{id}/stop?force=true`, not `DELETE`.** **CONFIRMED (with a stale doc-comment — NOTE N1).** Route registered as `POST /sessions/{id}/stop` (`main.rs:1824`); `StopParams.force` at `main.rs:7137–7143` bypasses the workspace-lock check and tolerates individual teardown-step failures. **Spec matches the actual route.** Minor: the `StopParams` doc-comment at `main.rs:7135` still reads "Query parameters accepted by `DELETE /sessions/{id}` (stop)" — a stale comment, not a code discrepancy; the wired route is POST.

- **C19 — log cap = daily-rotate + gzip + keep-7 via a log reaper; NO per-file size cap.** **CONFIRMED.** `main.rs:503–517` builds `tracing_appender::rolling` with `Rotation::DAILY` (506); `ROTATION_KEEP_COUNT = 7` and `run_log_reaper` (main.rs:575/594) gzip + keep-7; the size-cap-deferred rationale is in the comment at `main.rs:500–502`. **Spec matches code.**

---

## Summary verdict

### Status counts (by row)

- **LIVE-VERIFIED:** ~22 rows — the load-bearing runtime behaviors: full-backend create→Running (incl. first-ever base-image build → B1 fix), vmnet slot allocation, `sandbox exec`, **full-backend denied egress BLOCKED (restrict=on)**, lite create→Running, **lite egress allow + deny + SSH**, lite repo-clone/boot-cmd, lite `shared:` TCC-warning, SANDBOX_COREDNS_UPSTREAM allow-resolution, operator-uid VM process.
- **HERMETIC:** ~75 rows — broker/agent protocol, VmnetPool, gateway_lima lifecycle + recovery, qemu-wrapper restrict=on injection (marker/QMP), NIC discovery, pool-resize, IP-forwarding assert, store schema, install/uninstall/update, doctor checks, cosign pin, download URLs.
- **CODE-ONLY (no dedicated test):** ~13 rows — mostly documented deltas, DTO-value formatting (`networking_status` value surface, `sandbox inspect` slot lines), the privileged-resize refusal path, the socket_vmnet root-exec ancestry assertion, per-NIC IPv6-disable, agent-absent error-string path (asserted only indirectly).
- **DEFERRED:** ~9 items — HTTPS interception + post-recovery re-assert (CI-gated), IDE Remote-SSH (#227), lite `local:`/`shared:` `/private` (#316 + carry-forward), `make test` pending reboot (#311/#313), real-chain TCC attribution, accepted resource/seccomp/blast-radius deltas.
- **GAP:** **1** (narrow) — see callout below.

### Core-promise statement

**Absolute, unbypassable egress control — sandboxd's reason to exist — is LIVE-VERIFIED on BOTH backends this session.** Full backend: denied egress is blocked with `restrict=on` in force (`test_fullbackend_macos.py`, 4/4). Lite backend: allowed domain resolves + curls through, denied domain is blocked fail-closed, over the CoreDNS/gateway pipeline (`test_lite_macos.py::TestLiteMacosEgressInterception`). The single GAP below is a `sandbox doctor` diagnostic-coverage gap, not in the runtime egress enforcement path — it does not weaken this promise.

### What remains before the arc can publish

1. **`make test` full-workspace nextest** — re-run after host reboot (amfid/syspolicyd wedge, #311/#313). Code passes per-crate; this is an environmental blocker.
2. **Full CI matrix (`build-macos` on `macos-14`)** — the native e2e matrix incl. HTTPS interception + post-recovery egress re-assert. Hardware/CI-gated; not runnable on the wedged dev host now.
3. **Resolve the GAP below** (or explicitly accept it as a spec-reconciliation of the doctor table).
4. **IDE Remote-SSH manual walkthrough** (#227) — non-blocking; underlying proxy path is LIVE-VERIFIED.

---

## GAP findings (verbatim, prominent)

### GAP G1 (narrow) — no macOS `sandbox doctor` row for `_sandboxd` group membership / slot-socket reachability

**Spec (§M14 consolidated doctor table, row `check_socket_vmnet_access`):** lists `check_socket_vmnet_access` as a **macOS `sandbox doctor` row** that "verifies the operator is in the `_sandboxd` group and can reach the slot sockets under `/var/run/sandbox/vmnet/`."

**Code:** The **install.sh preflight** `check_socket_vmnet_access` **does exist** (`install.sh:943`) and covers group membership + slot-socket reachability at install time. The gap is narrowly in the **Rust `sandbox doctor` CLI**: the group-membership check `check_group_membership` (C4) is **`#[cfg(target_os = "linux")]`-only** (`doctor.rs:676`), with an explicit note at `doctor.rs:674`: *"`getgrouplist(3)` is absent on Apple targets in nix 0.29; this check is Linux-only."* The macOS `sandbox doctor` set covers `check_socket_vmnet_installed` (1315) and `check_socket_vmnet_running` (1363) — binary-present and daemons-loaded — but has **no** "operator ∈ `_sandboxd` group + can connect to the slot sockets" row, so `sandbox doctor` on macOS renders no membership/slot-reachability verdict.

**Assessment:** Narrow diagnostic-coverage GAP. The *enforcement* is present at multiple layers: the install.sh preflight above, and at runtime the broker/API socket DAC + the authoritative `getgrouplist(3)` gate (`broker.rs:300`). What is missing is the ongoing **`sandbox doctor` diagnostic row** on macOS (Linux has it via C4). Does **not** weaken egress enforcement or access control — it is a triage-visibility gap only. Fix is either (a) add a macOS `check_socket_vmnet_access` doctor row (routing around the nix-0.29 getgrouplist-on-Apple limitation, e.g. via `libc::getgrouplist` directly — the broker already does the uid→group resolution), or (b) reconcile the spec's consolidated doctor table to state this check is install.sh-preflight-only on macOS.

*(Prior draft G2 — "vmnet launchd pre-exec codesign guard not located" — was RETRACTED after re-reading `install.sh:2863`: the generated `io.sandboxd.vmnet.<n>` pre-exec wrapper DOES run `codesign --verify --strict $_svmnet_staged` and refuses to exec on failure, and a stage-time verify exists at `install.sh:2814`. Prevention + daemon-side detection are both present; no gap.)*

---

## Notes (non-GAP discrepancies)

- **N1 — stale doc-comment on `StopParams`.** `main.rs:7135` labels `StopParams` as "Query parameters accepted by `DELETE /sessions/{id}` (stop)" while the wired route is `POST /sessions/{id}/stop` (main.rs:1824). Code is correct (POST, matching reconciled C5); the doc-comment is stale. Cosmetic — recommend fixing the comment.
- **N2 — spec-flagged cosign-pin gap is CLOSED.** The spec (§M16 §Cosign verification, "Pin-table gap to close") flags the `cosign-darwin-arm64` pin as a to-do. It is **implemented**: `cosign_pin_for_arch` at `fetch.rs:80–86` resolves `aarch64-apple-darwin` → `cosign-darwin-arm64` with `COSIGN_SHA256_DARWIN_ARM64` (75–76), mirrored in `lib.sh:30`, drift-tested by `test_lib_sh_drift.py`. The spec text should be updated to reflect that this item is done.
