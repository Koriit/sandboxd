/// Integration tests for the macOS gateway Lima instance.
///
/// These tests require a real Lima VM (`sandboxd-gateway`) and are therefore
/// prefixed with `integration_` so the nextest `integration` profile picks
/// them up (and the default profile filters them out).
///
/// ```bash
/// # From sandboxd/:
/// cargo nextest run --profile integration -E 'test(integration_gateway_lima)'
/// ```
///
/// ## Prerequisites
///
/// - macOS host with Lima ≥ 1.2.0 and QEMU on PATH
/// - N socket_vmnet pool daemons running (`make setup-dev-env`)
/// - `sandboxd-gateway` Lima instance not yet created (or already deleted)
/// - The daemon uid must have write access to its LIMA_HOME
///   (`/var/lib/sandboxd/<daemon_uid>/<daemon_uid>/lima/`)
// These tests are macOS-only; the module is macOS-only to keep the Linux
// build clean.
#[cfg(target_os = "macos")]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use nix::unistd::Uid;
    use sandbox_core::backend::AsyncReadWrite;
    use sandbox_core::error::SandboxError;
    use sandbox_core::gateway_lima::{
        EGRESS_BRIDGE_NAME, GATEWAY_INSTANCE_NAME, GatewayLimaManager,
    };
    use sandbox_core::lima::{LimaExecutor, LimaOp, operator_lima_home};
    use sandbox_core::process::run_with_timeout;

    // ------------------------------------------------------------------
    // Test executor: direct limactl invocation (daemon-uid degenerate path)
    // ------------------------------------------------------------------

    /// An integration-test executor that invokes `limactl` directly.
    ///
    /// Mirrors the daemon's direct-path for the gateway instance: sets `LIMA_HOME`
    /// to the daemon-uid LIMA_HOME and calls `limactl` with a clean environment.
    struct DirectLimaExecutor {
        daemon_uid: u32,
    }

    #[async_trait]
    impl LimaExecutor for DirectLimaExecutor {
        fn run(
            &self,
            _op_uid: u32,
            op: LimaOp<'_>,
            timeout: Duration,
            label: &str,
        ) -> Result<std::process::Output, SandboxError> {
            let lima_home = operator_lima_home(self.daemon_uid);
            let lima_home_str = lima_home.to_string_lossy().into_owned();
            let current_path = std::env::var("PATH").unwrap_or_default();
            let path_value = format!("/opt/homebrew/bin:/usr/local/bin:{current_path}");

            let mut cmd = std::process::Command::new("limactl");
            cmd.env_clear()
                .env("LIMA_HOME", &lima_home_str)
                .env("PATH", &path_value)
                .env("HOME", std::env::var("HOME").unwrap_or_default())
                .env("TERM", "dumb");

            match op {
                LimaOp::Create { vm, yaml_path, .. } => {
                    cmd.args([
                        "create",
                        "--name",
                        vm,
                        &yaml_path.to_string_lossy(),
                        "--tty=false",
                    ]);
                }
                LimaOp::Start {
                    vm,
                    start_timeout_s,
                    ..
                } => {
                    let timeout_flag = format!("--timeout={start_timeout_s}s");
                    cmd.args(["start", vm, &timeout_flag, "--tty=false"]);
                }
                LimaOp::Stop { vm, force } => {
                    if force {
                        cmd.args(["stop", "--force", vm, "--tty=false"]);
                    } else {
                        cmd.args(["stop", vm, "--tty=false"]);
                    }
                }
                LimaOp::Delete { vm } => {
                    cmd.args(["delete", "--force", vm, "--tty=false"]);
                }
                LimaOp::ListJson => {
                    cmd.args(["list", "--json", "--tty=false"]);
                }
                _ => {
                    return Err(SandboxError::Lima(format!(
                        "{label}: unsupported op in integration test executor"
                    )));
                }
            }

            run_with_timeout(&mut cmd, timeout, label)
        }

        async fn guest_socat(
            &self,
            _op_uid: u32,
            _vm: &str,
        ) -> Result<Box<dyn AsyncReadWrite + Send + Unpin>, SandboxError> {
            Err(SandboxError::Lima(
                "guest_socat not supported in integration test executor".to_string(),
            ))
        }
    }

    /// Construct a `GatewayLimaManager` backed by the direct limactl executor.
    ///
    /// The manager carries no slot set — every call that needs one takes it as
    /// an argument, so each test states the slots it is exercising at the call
    /// site rather than inheriting them from construction.
    fn build_test_manager() -> GatewayLimaManager {
        let daemon_uid = Uid::current().as_raw();
        let lima_home = operator_lima_home(daemon_uid);
        let gateway_socket = lima_home
            .join(sandbox_core::GATEWAY_INSTANCE_NAME)
            .join("gateway-docker.sock");
        let docker = sandbox_core::docker::DockerRoute::Vm {
            owner_uid: daemon_uid,
            executor: Arc::new(sandbox_core::docker::LocalSocketDockerExecutor::new(
                gateway_socket,
                lima_home.clone(),
            )),
        };
        let in_vm = sandbox_core::in_vm::InVmRoute::new(
            daemon_uid,
            Arc::new(sandbox_core::in_vm::LocalLimactlInVmExecutor::new(
                sandbox_core::GATEWAY_INSTANCE_NAME,
                lima_home.clone(),
            )),
        );
        GatewayLimaManager::new(
            lima_home,
            Arc::new(DirectLimaExecutor { daemon_uid }),
            docker,
            in_vm,
            daemon_uid,
        )
    }

    /// The contiguous slot set a single-operator pool of `n` slots owns — what
    /// the daemon passes to `ensure_ready` on this host's shape.
    fn slots(n: u16) -> Vec<u16> {
        (0..n).collect()
    }

    // ------------------------------------------------------------------
    // Live integration tests (require a real Lima/QEMU environment)
    // ------------------------------------------------------------------

    /// Full gateway instance lifecycle: create → start → socket-ready →
    /// NIC-discovery → sandboxd-egress bridge → baseline nft policy.
    ///
    /// Verifies every step of `ensure_ready` against a real gateway VM:
    /// - `limactl create sandboxd-gateway` succeeds with the generated template
    /// - `limactl start sandboxd-gateway` succeeds
    /// - The forwarded Docker socket becomes accessible (`docker info`)
    /// - `ip -json link show` discovers exactly `max_slots` limaN NICs
    /// - `sandboxd-egress` Docker bridge exists after ensure_ready
    /// - The baseline nft policy is in place on `eth0`
    /// - A second call to `ensure_ready` succeeds (idempotency: daemon restart
    ///   against a still-running gateway VM must not fail)
    #[test]
    fn integration_gateway_lima_ensure_ready_full_lifecycle() {
        const MAX_SLOTS: u16 = 2; // 2 slots keeps the test fast.

        let manager = build_test_manager();
        let slots = slots(MAX_SLOTS);

        manager
            .ensure_ready(&slots)
            .expect("gateway ensure_ready failed");

        // Verify NIC map was populated.
        let nic_map = manager
            .nic_map()
            .expect("NIC map should be populated after ensure_ready");
        assert_eq!(
            nic_map.discovered_count, MAX_SLOTS as usize,
            "discovered NIC count should match max_slots"
        );
        assert_eq!(nic_map.interface_for_slot(0), Some("lima0"));
        assert_eq!(nic_map.interface_for_slot(1), Some("lima1"));

        // Verify the forwarded Docker socket exists.
        let socket_path = manager.gateway_docker_socket();
        assert!(socket_path.exists(), "gateway Docker socket should exist");

        // Verify sandboxd-egress bridge exists inside the VM.
        let socket_str = format!("unix://{}", socket_path.display());
        let output = std::process::Command::new("docker")
            .args(["-H", &socket_str, "network", "inspect", EGRESS_BRIDGE_NAME])
            .output()
            .expect("docker network inspect should run");
        assert!(
            output.status.success(),
            "sandboxd-egress bridge should exist in gateway VM: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Verify baseline nft policy is loaded inside the VM.
        // Use `sudo nft` because nft requires CAP_NET_ADMIN (root). Lima
        // provisions Ubuntu VMs with passwordless sudo, so this is safe.
        // HOME must be set — Lima panics without it.
        let daemon_uid = Uid::current().as_raw();
        let lima_home = operator_lima_home(daemon_uid);
        let lima_home_str = lima_home.to_string_lossy().into_owned();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let home_str = std::env::var("HOME").unwrap_or_default();
        let nft_output = std::process::Command::new("limactl")
            .args([
                "shell",
                GATEWAY_INSTANCE_NAME,
                "--",
                "bash",
                "-c",
                "sudo nft list table inet sandboxd-gateway-eth0",
            ])
            .env_clear()
            .env("LIMA_HOME", &lima_home_str)
            .env(
                "PATH",
                format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
            )
            .env("HOME", &home_str)
            .env("TERM", "dumb")
            .output()
            .expect("limactl shell nft list should run");
        assert!(
            nft_output.status.success(),
            "sandboxd-gateway-eth0 nft table should exist: {}",
            String::from_utf8_lossy(&nft_output.stderr)
        );

        // Verify idempotency: a second ensure_ready (simulating daemon restart
        // against the still-running gateway VM) must not fail.
        manager
            .ensure_ready(&slots)
            .expect("second ensure_ready (daemon restart simulation) failed");

        // No teardown: leave the gateway VM running so subsequent integration
        // tests in this serial group can reuse the already-provisioned instance
        // without the cost of a full re-create + cloud-init.
    }

    /// Test NIC discovery against a real gateway VM. The test verifies that
    /// `ip -json link show` returns the expected `limaN` interface names.
    #[test]
    fn integration_gateway_lima_nic_discovery_live() {
        // Use max_slots=2 to match the gateway created by the lifecycle test
        // (which uses 2 slots for fast provisioning). NIC discovery asserts the
        // discovered count equals max_slots when the gateway has the right NICs.
        const MAX_SLOTS: u16 = 2;
        let manager = build_test_manager();
        let slots = slots(MAX_SLOTS);
        manager.ensure_ready(&slots).expect("ensure_ready failed");

        let nic_map = manager.nic_map().expect("NIC map should be populated");
        assert_eq!(
            nic_map.discovered_count, MAX_SLOTS as usize,
            "NIC count mismatch: got {}, expected {}",
            nic_map.discovered_count, MAX_SLOTS
        );
        for slot in 0..MAX_SLOTS {
            let expected_name = format!("lima{slot}");
            assert_eq!(
                nic_map.interface_for_slot(slot),
                Some(expected_name.as_str()),
                "slot {slot} should map to {expected_name}"
            );
        }
    }

    /// Test that the `sandboxd-egress` bridge is created inside the gateway VM
    /// and is accessible via the forwarded Docker socket.
    #[test]
    fn integration_gateway_lima_egress_bridge_accessible() {
        let manager = build_test_manager();
        let slots = slots(2);
        manager.ensure_ready(&slots).expect("ensure_ready failed");

        let socket_str = format!("unix://{}", manager.gateway_docker_socket().display());
        let output = std::process::Command::new("docker")
            .args(["-H", &socket_str, "network", "inspect", EGRESS_BRIDGE_NAME])
            .output()
            .expect("docker inspect should run");
        assert!(
            output.status.success(),
            "sandboxd-egress should be accessible from host via forwarded socket"
        );
    }

    /// Test that the baseline eth0 nft policy is applied inside the gateway VM,
    /// and that the `sandboxd-gateway-eth0` table exists and has the expected chains.
    #[test]
    fn integration_gateway_lima_eth0_nft_policy_applied() {
        let manager = build_test_manager();
        let slots = slots(2);
        manager.ensure_ready(&slots).expect("ensure_ready failed");

        let daemon_uid = Uid::current().as_raw();
        let lima_home = operator_lima_home(daemon_uid);
        let lima_home_str = lima_home.to_string_lossy().into_owned();
        let current_path = std::env::var("PATH").unwrap_or_default();

        let home_str = std::env::var("HOME").unwrap_or_default();
        let table_output = std::process::Command::new("limactl")
            .args([
                "shell",
                GATEWAY_INSTANCE_NAME,
                "--",
                "bash",
                "-c",
                "sudo nft list table inet sandboxd-gateway-eth0 2>&1",
            ])
            .env_clear()
            .env("LIMA_HOME", &lima_home_str)
            .env(
                "PATH",
                format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
            )
            .env("HOME", &home_str)
            .env("TERM", "dumb")
            .output()
            .expect("limactl shell should run");
        assert!(
            table_output.status.success(),
            "sandboxd-gateway-eth0 table should exist after ensure_ready; stderr: {}",
            String::from_utf8_lossy(&table_output.stderr)
        );

        let table_content = String::from_utf8_lossy(&table_output.stdout);
        assert!(
            table_content.contains("policy drop"),
            "output chain should have default-drop policy"
        );
        assert!(
            table_content.contains("established") && table_content.contains("related"),
            "output chain should allow established/related"
        );
        // The policy uses an explicit port allow-list (DNS, HTTPS, HTTP) rather than
        // a blanket `ct state new accept`, bounding blast radius per the spec MUST.
        assert!(
            table_content.contains("dport 53"),
            "output chain should allow DNS (port 53)"
        );
        assert!(
            table_content.contains("dport 443"),
            "output chain should allow HTTPS (port 443)"
        );
        assert!(
            table_content.contains("dport 80"),
            "output chain should allow HTTP (port 80)"
        );
        assert!(
            !table_content.contains("ct state new accept"),
            "output chain must NOT have a blanket ct state new accept"
        );
        // Inbound defense: drop new/invalid connections from external parties.
        assert!(
            table_content.contains("invalid") && table_content.contains("new drop"),
            "input chain should drop new/invalid inbound connections on eth0"
        );
    }

    /// Test that NIC count mismatch between discovered NICs and max_slots is
    /// non-fatal: ensure_ready continues with a warning, not an error.
    ///
    /// This test artificially creates a mismatch by using max_slots=4 against
    /// a gateway instance with only 2 NICs.
    #[test]
    fn integration_gateway_lima_nic_count_mismatch_is_non_fatal() {
        // Pool expects 4 NICs but the gateway has only 2 — non-fatal.
        let manager = build_test_manager();
        let slots = slots(4);

        // ensure_ready should succeed even with the mismatch (logs a warning).
        manager
            .ensure_ready(&slots)
            .expect("ensure_ready should not fail on NIC count mismatch");

        let nic_map = manager.nic_map().expect("NIC map should be populated");
        assert_eq!(
            nic_map.discovered_count, 2,
            "discovered_count should reflect actual NICs, not the requested slot count"
        );
        // The two slots the VM cannot serve are absent from the map rather than
        // mapped to an invented name — the sessions that claim them are refused
        // at the claim site instead of landing on an unknown segment.
        assert_eq!(
            nic_map.missing_slots,
            vec![2, 3],
            "slots without a verified interface must be reported missing"
        );
        assert_eq!(nic_map.interface_for_slot(2), None);
        assert_eq!(nic_map.interface_for_slot(3), None);
    }

    /// Test that `ensure_ready` succeeds even if the gateway is already running
    /// (idempotent). Requires the gateway to be pre-started.
    #[test]
    fn integration_gateway_lima_ensure_ready_idempotent_when_running() {
        let manager = build_test_manager();
        let slots = slots(2);

        manager
            .ensure_ready(&slots)
            .expect("first ensure_ready failed");
        manager
            .ensure_ready(&slots)
            .expect("second ensure_ready failed (idempotent)");
    }

    // ------------------------------------------------------------------
    // Recovery primitive tests (Pass 2b)
    //
    // These tests exercise `probe_docker_health`, `force_stop_instance`,
    // and `restart_instance_for_recovery` against a live gateway VM.
    // They require the same infrastructure as the lifecycle test:
    // - macOS host with Lima ≥ 1.2.0 and QEMU on PATH
    // - `sandboxd-gateway` Lima instance running (or ensured ready below)
    // - socket_vmnet pool daemons present
    //
    // Each test calls `ensure_ready()` as a guard/setup step rather than
    // relying on a shared pre-started instance, so they can be run
    // individually without the lifecycle test running first.
    // ------------------------------------------------------------------

    /// `probe_docker_health` returns `Ok(true)` when the gateway is running
    /// and `Ok(false)` after `force_stop_instance`.
    ///
    /// Verifies the two observable states the recovery orchestrator relies
    /// on: a healthy probe and a "connection refused / timed out" probe
    /// that signals the instance is down.
    ///
    /// After the test, the gateway instance is left stopped. Callers that
    /// need it running should call `ensure_ready()` afterwards; the
    /// subsequent `integration_gateway_lima_force_stop_is_idempotent` and
    /// `integration_gateway_lima_restart_for_recovery_*` tests call
    /// `ensure_ready()` themselves as a guard.
    #[test]
    fn integration_gateway_lima_probe_docker_health_reflects_state() {
        const MAX_SLOTS: u16 = 2;
        let manager = build_test_manager();
        let slots = slots(MAX_SLOTS);

        // Ensure the gateway is up before probing.
        manager
            .ensure_ready(&slots)
            .expect("ensure_ready failed before probe test");

        // Healthy instance → probe must return Ok(true).
        let healthy = manager
            .probe_docker_health()
            .expect("probe_docker_health returned Err on a running instance");
        assert!(
            healthy,
            "probe_docker_health must return true when the gateway is running"
        );

        // Force-stop the instance to simulate a crash.
        manager
            .force_stop_instance()
            .expect("force_stop_instance failed");

        // Stopped instance → probe must return Ok(false), not Err.
        // The Docker socket is no longer reachable so the probe will get
        // a connection-refused / timeout, which maps to Ok(false).
        let down = manager
            .probe_docker_health()
            .expect("probe_docker_health must return Ok(false) on a stopped instance, not Err");
        assert!(
            !down,
            "probe_docker_health must return false when the gateway is stopped"
        );

        eprintln!(
            "[integration_gateway_lima_probe_docker_health_reflects_state] PASS: \
             healthy=true then stopped=false"
        );
        // Gateway left stopped; next test calls ensure_ready().
    }

    /// `force_stop_instance` is idempotent: calling it on an already-stopped
    /// instance must succeed (not return an error).
    ///
    /// The recovery orchestrator calls `force_stop_instance` before `start_instance`
    /// without checking the current state; this test verifies that double-stop is safe.
    #[test]
    fn integration_gateway_lima_force_stop_is_idempotent() {
        let manager = build_test_manager();
        let slots = slots(2);

        // Ensure the gateway is running first so the first stop is meaningful.
        manager
            .ensure_ready(&slots)
            .expect("ensure_ready failed in idempotent stop test");

        // First stop.
        manager
            .force_stop_instance()
            .expect("first force_stop_instance failed");

        // Second stop on an already-stopped instance must succeed (idempotent).
        manager
            .force_stop_instance()
            .expect("second force_stop_instance on already-stopped instance must not fail");

        eprintln!(
            "[integration_gateway_lima_force_stop_is_idempotent] PASS: \
             double force-stop succeeded"
        );
        // Gateway left stopped.
    }

    /// `restart_instance_for_recovery` restores the instance to Running, makes
    /// Docker reachable, and re-establishes the egress bridge and eth0 nft policy.
    ///
    /// Exercises the full recovery sequence from the stopped state:
    /// 1. `force_stop_instance` (already performed by previous test, but we
    ///    call `ensure_ready` then `force_stop_instance` to guarantee a clean
    ///    starting state).
    /// 2. `restart_instance_for_recovery` — the method under test.
    /// 3. `instance_state()` must return `"Running"`.
    /// 4. `probe_docker_health()` must return `Ok(true)`.
    /// 5. The egress bridge must still exist (same assertion as the lifecycle test).
    /// 6. The baseline nft policy must still be in place on eth0.
    #[test]
    fn integration_gateway_lima_restart_for_recovery_restores_readiness_and_fabric() {
        const MAX_SLOTS: u16 = 2;
        let manager = build_test_manager();
        let slots = slots(MAX_SLOTS);

        // Bring the gateway up so we start from a known state.
        manager
            .ensure_ready(&slots)
            .expect("ensure_ready failed before recovery restart test");

        // Simulate a crash by force-stopping the instance.
        manager
            .force_stop_instance()
            .expect("force_stop_instance failed before recovery restart");

        // Confirm it is stopped before recovery.
        let state_before = manager
            .instance_state()
            .expect("instance_state() failed after force-stop");
        assert_ne!(
            state_before, "Running",
            "instance must not be Running after force-stop; got: {state_before}"
        );

        // Run the recovery method under test.
        manager
            .restart_instance_for_recovery(&slots)
            .expect("restart_instance_for_recovery failed");

        // 3. instance_state() must now be "Running".
        let state_after = manager
            .instance_state()
            .expect("instance_state() failed after recovery restart");
        assert_eq!(
            state_after, "Running",
            "instance must be Running after restart_instance_for_recovery; got: {state_after}"
        );

        // 4. probe_docker_health() must return Ok(true).
        let healthy = manager
            .probe_docker_health()
            .expect("probe_docker_health returned Err after recovery restart");
        assert!(
            healthy,
            "probe_docker_health must return true after restart_instance_for_recovery"
        );

        // 5. The sandboxd-egress bridge must exist inside the VM.
        let socket_path = manager.gateway_docker_socket();
        let socket_str = format!("unix://{}", socket_path.display());
        let bridge_out = std::process::Command::new("docker")
            .args(["-H", &socket_str, "network", "inspect", EGRESS_BRIDGE_NAME])
            .output()
            .expect("docker network inspect should run");
        assert!(
            bridge_out.status.success(),
            "sandboxd-egress bridge must exist after restart_instance_for_recovery: {}",
            String::from_utf8_lossy(&bridge_out.stderr)
        );

        // 6. The baseline eth0 nft policy must be in place.
        let daemon_uid = Uid::current().as_raw();
        let lima_home = operator_lima_home(daemon_uid);
        let lima_home_str = lima_home.to_string_lossy().into_owned();
        let current_path = std::env::var("PATH").unwrap_or_default();
        let home_str = std::env::var("HOME").unwrap_or_default();
        let nft_out = std::process::Command::new("limactl")
            .args([
                "shell",
                GATEWAY_INSTANCE_NAME,
                "--",
                "bash",
                "-c",
                "sudo nft list table inet sandboxd-gateway-eth0 2>&1",
            ])
            .env_clear()
            .env("LIMA_HOME", &lima_home_str)
            .env(
                "PATH",
                format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
            )
            .env("HOME", &home_str)
            .env("TERM", "dumb")
            .output()
            .expect("limactl shell nft list should run");
        assert!(
            nft_out.status.success(),
            "sandboxd-gateway-eth0 nft table must exist after recovery restart; stderr: {}",
            String::from_utf8_lossy(&nft_out.stderr)
        );

        let nft_content = String::from_utf8_lossy(&nft_out.stdout);
        assert!(
            nft_content.contains("policy drop"),
            "output chain must have default-drop policy after recovery restart"
        );
        assert!(
            nft_content.contains("dport 53"),
            "output chain must allow DNS after recovery restart"
        );

        eprintln!(
            "[integration_gateway_lima_restart_for_recovery_restores_readiness_and_fabric] \
             PASS: Running, docker healthy, egress bridge present, eth0 nft policy in place"
        );
        // Gateway left running — no teardown, reusable by subsequent tests.
    }
}
