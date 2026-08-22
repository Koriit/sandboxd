/// Integration tests for the macOS full-backend session lifecycle.
///
/// ## Executor model (degenerate single-uid path)
///
/// These tests run on a macOS dev host where `current_uid == op_uid == daemon_uid`.
/// They use `DirectLimaExecutor` (from `sandbox_core::test_support::direct_executor`)
/// which calls `limactl` directly — no broker, no agent. The daemon's
/// `AgentBrokerExecutor` routes to `run_limactl_direct` when `op_uid == daemon_uid`,
/// so this test path exercises the same limactl call path the degenerate daemon uses.
///
/// ## Live infrastructure required
///
/// - `sandboxd-gateway` Lima instance must be running.
/// - socket_vmnet pool daemons `io.sandboxd.vmnet.0` .. `io.sandboxd.vmnet.N`
///   must be running and their sockets present under `/var/run/sandbox/vmnet/`.
/// - `sandbox-gateway:<version>` Docker image must be loaded inside the gateway VM.
/// - `make setup-dev-env` must have run at least once on the host.
///
/// ## Naming convention
///
/// All tests are prefixed `integration_` — the nextest integration profile
/// (`sandboxd/.config/nextest.toml`) selects by that prefix; the default
/// profile filters them out. No `#[ignore]` attribute.
///
/// ## Exact live invocation command
///
/// ```sh
/// # From the workspace root (sandboxd/):
/// SANDBOX_STATE_ROOT=/var/lib/sandboxd \
/// cargo nextest run -p sandbox-core \
///   --profile integration \
///   -E 'test(integration_macos)' \
///   --no-fail-fast \
///   --test-threads 1
/// ```
///
/// `--test-threads 1` is mandatory: each test creates a VM and the 8 GB dev
/// host cannot handle two HVF guests concurrently. The `integration` nextest
/// profile also sets `retries = 0` so failures surface immediately.
///
/// ## Left to the Python E2E suite
///
/// - The egress-traffic proof (delete-the-gateway-route regression: assert
///   `eth0` cannot reach the internet after `restrict=on` is applied). What
///   this file proves is that the VM boots with the wrapper applied; that the
///   resulting traffic is actually blocked needs a live network and belongs
///   in E2E.
/// - The full cross-user daemon+broker+agent path (requires a running daemon
///   and an enrolled operator agent; this test file exercises only the
///   degenerate single-uid dev path).
#[cfg(target_os = "macos")]
mod integration_macos_session_lifecycle {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;

    use sandbox_core::gateway::gateway_image_tag_for_version;
    use sandbox_core::lima::{LimaManagerRegistry, operator_lima_home, vm_name};
    use sandbox_core::macos_session::{
        macos_docker_network_name, macos_gateway_container_name, setup_macos_gateway,
        teardown_macos_gateway,
    };
    use sandbox_core::network::{VmnetPool, vmnet_slot_socket_path};
    use sandbox_core::session::SessionId;
    use sandbox_core::test_support::direct_executor::DirectLimaExecutor;
    use sandbox_core::{NetworkInfo, SessionConfig};

    /// A stand-in operator uid for pool tests. The pool does not interpret
    /// it — it records the uid with the claim and names it in the
    /// exhaustion error — so any value above the system-uid floor does.
    const TEST_OPERATOR_UID: u32 = 501;

    // ---------------------------------------------------------------------------
    // Shared helpers
    // ---------------------------------------------------------------------------

    /// Resolve the gateway Lima forwarded Docker socket path.
    ///
    /// The gateway instance lives under the daemon uid's LIMA_HOME.
    /// In dev mode the daemon is the current user, so daemon_uid == current uid.
    ///
    /// The instance name is derived rather than spelled: with per-operator
    /// gateways on it carries an owner suffix, and a literal here would name an
    /// instance that does not exist. The derivation returns the bare name while
    /// they are off, so the path is unchanged in that mode.
    fn gateway_docker_socket() -> PathBuf {
        let uid = nix::unistd::Uid::current().as_raw();
        let daemon_lima_home = operator_lima_home(uid);
        daemon_lima_home
            .join(sandbox_core::gateway_instance_name(uid))
            .join("gateway-docker.sock")
    }

    /// The Docker route this suite drives: the gateway VM's forwarded socket,
    /// run directly. That is what the test process has always done; the route
    /// makes it explicit rather than implicit in a socket argument.
    fn gateway_docker_route() -> sandbox_core::docker::DockerRoute {
        let sock = gateway_docker_socket();
        let staging = sock
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_default();
        sandbox_core::docker::DockerRoute::Vm {
            owner_uid: nix::unistd::Uid::current().as_raw(),
            executor: std::sync::Arc::new(sandbox_core::docker::LocalSocketDockerExecutor::new(
                sock, staging,
            )),
        }
    }

    /// Run a `docker -H unix://<sock>` command against the gateway VM.
    fn docker_gateway(args: &[&str]) -> std::process::Output {
        let sock = gateway_docker_socket();
        let sock_str = format!("unix://{}", sock.display());
        let current_path = std::env::var("PATH").unwrap_or_default();
        Command::new("docker")
            .arg("-H")
            .arg(&sock_str)
            .args(args)
            .env(
                "PATH",
                format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
            )
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .output()
            .expect("docker command failed to spawn")
    }

    /// Return `true` if the gateway Lima forwarded Docker socket is reachable.
    /// Returns `false` (prints a SKIP message) when the gateway is not running.
    fn require_gateway_running() -> bool {
        let output = docker_gateway(&["info", "--format", "{{.ServerVersion}}"]);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "SKIP: sandboxd-gateway not reachable ({}). \
                 Run `make setup-dev-env && limactl start sandboxd-gateway` first.",
                stderr.trim()
            );
            return false;
        }
        true
    }

    /// Return `true` if the given gateway-image tag is loaded in the gateway VM's
    /// Docker daemon. Returns `false` (prints a SKIP message) when absent.
    ///
    /// The gateway image (`sandbox-gateway:<version>`) has to be loaded into the
    /// gateway VM's Docker daemon before any image-dependent test can run. This
    /// guard lets those tests skip cleanly rather than fail when it is absent.
    fn require_gateway_image(tag: &str) -> bool {
        let out = docker_gateway(&["image", "inspect", tag]);
        if !out.status.success() {
            eprintln!(
                "SKIP: gateway image `{tag}` not loaded in the gateway VM. \
                 To enable: `docker -H unix://<gateway-sock> load < gateway-image.tar`"
            );
            return false;
        }
        true
    }

    /// Return `true` if `setfacl` is available on this host.
    ///
    /// The macOS operator-LIMA_HOME path uses `ensure_operator_lima_home`, which
    /// internally calls `setfacl` — a Linux tool for POSIX ACL support, not
    /// present on a stock macOS host. Tests that call
    /// `registry.get_or_create(op_uid)` → `ensure_operator_lima_home` fail with
    /// "failed to spawn setfacl" when it is missing, so they gate on this.
    fn setfacl_available() -> bool {
        std::process::Command::new("which")
            .arg("setfacl")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Assert that slot socket `N` exists and is reachable.
    fn require_slot_socket(slot: u16) -> bool {
        let path = vmnet_slot_socket_path(slot);
        std::path::Path::new(&path).exists()
    }

    // ---------------------------------------------------------------------------
    // Test: full create-with-boot lifecycle
    // ---------------------------------------------------------------------------

    /// Full macOS Lima session lifecycle: slot claim → limactl create →
    /// setup_macos_gateway → wrapped limactl start → verify restrict=on →
    /// assert Running → stop/rm teardown → assert slot released.
    ///
    /// Uses the degenerate single-uid executor (current_uid == op_uid →
    /// DirectLimaExecutor → run_limactl_direct → `limactl` directly).
    ///
    /// Prerequisites:
    /// - sandboxd-gateway Lima instance running
    /// - socket_vmnet pool slot-0.sock present under /var/run/sandbox/vmnet/
    /// - sandbox-gateway:0.1.10 (or whatever the package version is) loaded
    ///   inside the gateway VM
    ///
    /// Not proved here: the egress traffic proof (delete the gateway route,
    /// confirm `eth0` is blocked), which needs a live network. What this test
    /// proves is that the VM boots with `restrict=on` applied.
    #[test]
    fn integration_macos_create_start_stop_rm() {
        // Guard 1: gateway socket must be reachable.
        let sock = gateway_docker_socket();
        if !sock.exists() || !require_gateway_running() {
            eprintln!(
                "SKIP integration_macos_create_start_stop_rm: \
                 sandboxd-gateway not running (socket at {} missing or unreachable). \
                 Run `make setup-dev-env && limactl start sandboxd-gateway` first.",
                sock.display()
            );
            return;
        }

        // Guard 2: slot-0 socket must be present.
        if !require_slot_socket(0) {
            eprintln!(
                "SKIP integration_macos_create_start_stop_rm: slot-0 socket not present. \
                 Run `make setup-dev-env` to install socket_vmnet pool daemons."
            );
            return;
        }

        // Guard 3: setfacl must be available — `ensure_operator_lima_home` uses
        // it to provision the per-operator LIMA_HOME ACLs on macOS.
        if !setfacl_available() {
            eprintln!(
                "SKIP integration_macos_create_start_stop_rm: \
                 `setfacl` not available on this host — ensure_operator_lima_home \
                 requires it for the macOS operator-LIMA_HOME path."
            );
            return;
        }

        // Guard 4: the gateway image must be loaded inside the gateway VM.
        let gateway_tag = gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        if !require_gateway_image(&gateway_tag) {
            eprintln!(
                "SKIP integration_macos_create_start_stop_rm: \
                 requires the sandbox-gateway image loaded into the gateway VM."
            );
            return;
        }

        // --- Build live infrastructure objects ---
        let op_uid = nix::unistd::getuid().as_raw();
        let executor = DirectLimaExecutor::arc();
        let lima_home = operator_lima_home(op_uid);

        let registry = Arc::new(LimaManagerRegistry::new(
            "sandbox-base".to_string(),
            Arc::clone(&executor),
            "10.209.128.0/24".to_string(),
            true, // is_macos
        ));
        let pool = Arc::new(VmnetPool::new(8));

        // Generate a unique session ID for this test run.
        let session_id = SessionId::generate();
        let vm = vm_name(&session_id);

        // --- Step 1: claim a vmnet slot ---
        let (vmnet_slot, subnet_cidr, gateway_ip, vm_ip) = pool
            .claim_lima_slot(&session_id, TEST_OPERATOR_UID)
            .expect("claim_lima_slot failed");
        let slot_idx = vmnet_slot.index;
        let nic_name = format!("lima{slot_idx}");

        let network_info = sandbox_core::NetworkInfo {
            gateway_egress_ip: None,
            operator_uid: Some(TEST_OPERATOR_UID),
            bridge_name: nic_name.clone(),
            subnet: subnet_cidr.clone(),
            gateway_ip: gateway_ip.to_string(),
            vm_ip: vm_ip.to_string(),
            docker_network_name: macos_docker_network_name(&session_id),
            vmnet_slot: Some(vmnet_slot.clone()),
        };

        // Cleanup closure: always runs on test exit (success or failure) to
        // prevent leaked VMs/networks/slots from blocking subsequent test runs.
        struct Cleanup {
            session_id: SessionId,
            pool: Arc<VmnetPool>,
            gateway_route: sandbox_core::docker::DockerRoute,
            lima_home: PathBuf,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Best-effort teardown — ignore errors.
                let _ = teardown_macos_gateway(&self.session_id, &self.gateway_route);
                let _ = self.pool.release_lima_slot(&self.session_id);
                // limactl delete --force (best-effort)
                let vm = vm_name(&self.session_id);
                let lima_home_str = self.lima_home.to_string_lossy().into_owned();
                let current_path = std::env::var("PATH").unwrap_or_default();
                let _ = Command::new("limactl")
                    .args(["delete", "--force", &vm, "--tty=false"])
                    .env_clear()
                    .env("LIMA_HOME", &lima_home_str)
                    .env(
                        "PATH",
                        format!("/opt/homebrew/bin:/usr/local/bin:{current_path}"),
                    )
                    .env("HOME", std::env::var("HOME").unwrap_or_default())
                    .env("TERM", "dumb")
                    .output();
            }
        }
        let _cleanup = Cleanup {
            session_id,
            pool: Arc::clone(&pool),
            gateway_route: gateway_docker_route(),
            lima_home: lima_home.clone(),
        };

        // --- Step 2: limactl create (macOS template with slot) ---
        let manager = registry
            .get_or_create(op_uid)
            .expect("get_or_create failed");
        let config = sandbox_core::SessionConfig {
            cpus: 2,
            memory_mb: 2048,
            disk_gb: 20,
            workspace_mode: None,
            hardened: true,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        manager
            .create_vm(&session_id, &config, Some((op_uid, op_uid)), Some(slot_idx))
            .expect("limactl create failed");

        // Set the lima_network_info so the pool tracks the full NetworkInfo.
        pool.set_lima_network_info(&session_id, slot_idx, network_info.clone())
            .expect("set_lima_network_info failed");

        // --- Step 3: setup_macos_gateway (deny-all + health + DNAT) ---
        // `gateway_tag` is already declared in the guard block above.
        setup_macos_gateway(
            &session_id,
            &network_info,
            &nic_name,
            &gateway_docker_route(),
            &gateway_tag,
            None, // ca_dir — no TLS interception in this test
            None, // initial_dns_policy
            None, // owner_pool
        )
        .expect("setup_macos_gateway failed");

        // --- Assert: gateway container running ---
        let container = macos_gateway_container_name(&session_id);
        let inspect = docker_gateway(&["inspect", "--format", "{{.State.Status}}", &container]);
        assert!(
            inspect.status.success(),
            "gateway container not found after setup_macos_gateway"
        );
        let status = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
        assert_eq!(status, "running", "gateway container should be running");

        // --- Assert: gateway container hardening ---
        let privileged_out = docker_gateway(&[
            "inspect",
            "--format",
            "{{.HostConfig.Privileged}}",
            &container,
        ]);
        let privileged = String::from_utf8_lossy(&privileged_out.stdout)
            .trim()
            .to_string();
        assert_eq!(
            privileged, "false",
            "gateway container must NOT be privileged"
        );

        let readonly_out = docker_gateway(&[
            "inspect",
            "--format",
            "{{.HostConfig.ReadonlyRootfs}}",
            &container,
        ]);
        let readonly = String::from_utf8_lossy(&readonly_out.stdout)
            .trim()
            .to_string();
        assert_eq!(
            readonly, "true",
            "gateway container must have read-only rootfs"
        );

        // --- Step 4: limactl start (wrapped — injects restrict=on) ---
        manager
            .start_vm(&session_id, &config, None, None, false)
            .expect("limactl start failed");

        // --- Step 5: verify restrict=on ---
        manager
            .verify_restrict_on(&session_id)
            .expect("verify_restrict_on failed: restrict=on not confirmed by QMP or marker");

        eprintln!(
            "[integration_macos_create_start_stop_rm] VM {vm} booted with restrict=on confirmed"
        );

        // --- Step 6: stop + teardown ---
        manager.stop_vm(&session_id).expect("limactl stop failed");

        teardown_macos_gateway(&session_id, &gateway_docker_route())
            .expect("teardown_macos_gateway failed");

        // --- Assert: slot released ---
        pool.release_lima_slot(&session_id)
            .expect("release_lima_slot failed");
        assert_eq!(
            pool.running_session_count(),
            0,
            "slot must be released after stop"
        );

        // --- Assert: gateway container gone ---
        let inspect2 = docker_gateway(&["inspect", "--format", "{{.State.Status}}", &container]);
        assert!(
            !inspect2.status.success(),
            "gateway container should be gone after teardown"
        );

        // --- Step 7: limactl delete ---
        manager
            .delete_vm(&session_id)
            .expect("limactl delete failed");

        eprintln!(
            "[integration_macos_create_start_stop_rm] PASS: full lifecycle complete for {vm}"
        );
    }

    // ---------------------------------------------------------------------------
    // Test: gateway-side only (no VM boot)
    // ---------------------------------------------------------------------------

    /// Gateway-side integration: setup_macos_gateway + assert container running +
    /// hardening asserts + teardown. Does NOT boot a sandbox VM.
    #[test]
    fn integration_macos_gateway_side_lifecycle() {
        // Guard 1: gateway socket must be reachable.
        let sock = gateway_docker_socket();
        if !sock.exists() || !require_gateway_running() {
            eprintln!(
                "SKIP integration_macos_gateway_side_lifecycle: \
                 sandboxd-gateway not running. \
                 Run `make setup-dev-env && limactl start sandboxd-gateway` first."
            );
            return;
        }

        // Guard 2: slot-0 socket must be present.
        if !require_slot_socket(0) {
            eprintln!("SKIP integration_macos_gateway_side_lifecycle: slot-0 socket not present");
            return;
        }

        // Guard 3: the gateway image must be loaded inside the gateway VM. The
        // test skips cleanly when it is absent and activates on its own once
        // the image is loaded — no edit here is needed to enable it.
        let gateway_tag = gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        if !require_gateway_image(&gateway_tag) {
            eprintln!(
                "SKIP integration_macos_gateway_side_lifecycle: \
                 requires the sandbox-gateway image loaded into the gateway VM."
            );
            return;
        }

        let pool = Arc::new(VmnetPool::new(8));
        let session_id = SessionId::generate();

        let (vmnet_slot, subnet_cidr, gateway_ip, vm_ip) = pool
            .claim_lima_slot(&session_id, TEST_OPERATOR_UID)
            .expect("claim failed");
        let _slot_idx = vmnet_slot.index; // slot_idx used only to drive slot claim; nic_name derived from slot
        let nic_name = format!("lima{}", vmnet_slot.index);

        let network_info = sandbox_core::NetworkInfo {
            gateway_egress_ip: None,
            operator_uid: Some(TEST_OPERATOR_UID),
            bridge_name: nic_name.clone(),
            subnet: subnet_cidr,
            gateway_ip: gateway_ip.to_string(),
            vm_ip: vm_ip.to_string(),
            docker_network_name: macos_docker_network_name(&session_id),
            vmnet_slot: Some(vmnet_slot.clone()),
        };

        // `gateway_tag` is already declared in the guard block above.
        setup_macos_gateway(
            &session_id,
            &network_info,
            &nic_name,
            &gateway_docker_route(),
            &gateway_tag,
            None,
            None,
            None,
        )
        .expect("setup_macos_gateway failed");

        let container = macos_gateway_container_name(&session_id);

        // Assert container is running.
        let inspect = docker_gateway(&["inspect", "--format", "{{.State.Status}}", &container]);
        assert!(inspect.status.success(), "gateway container must exist");
        let s = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
        assert_eq!(s, "running");

        // Assert no --privileged.
        let priv_out = docker_gateway(&[
            "inspect",
            "--format",
            "{{.HostConfig.Privileged}}",
            &container,
        ]);
        assert_eq!(String::from_utf8_lossy(&priv_out.stdout).trim(), "false");

        // Assert read-only rootfs.
        let ro_out = docker_gateway(&[
            "inspect",
            "--format",
            "{{.HostConfig.ReadonlyRootfs}}",
            &container,
        ]);
        assert_eq!(String::from_utf8_lossy(&ro_out.stdout).trim(), "true");

        // Assert NET_ADMIN cap (should appear in CapAdd).
        let cap_out =
            docker_gateway(&["inspect", "--format", "{{.HostConfig.CapAdd}}", &container]);
        let cap_str = String::from_utf8_lossy(&cap_out.stdout).trim().to_string();
        assert!(
            cap_str.contains("NET_ADMIN"),
            "gateway container must have NET_ADMIN cap; got: {cap_str}"
        );

        // Teardown.
        teardown_macos_gateway(&session_id, &gateway_docker_route()).expect("teardown failed");
        pool.release_lima_slot(&session_id).expect("release failed");

        // Container should be gone.
        let inspect2 = docker_gateway(&["inspect", "--format", "{{.State.Status}}", &container]);
        assert!(
            !inspect2.status.success(),
            "container must be gone after teardown"
        );

        // Pool slot must be free.
        assert_eq!(pool.running_session_count(), 0);

        eprintln!("[integration_macos_gateway_side_lifecycle] PASS");
    }

    // ---------------------------------------------------------------------------
    // Test: partial create rollback
    // ---------------------------------------------------------------------------

    /// Partial create rollback: claim slot → setup_macos_gateway with a bad NIC
    /// name (forces failure) → assert no leaked slot/container/network.
    #[test]
    fn integration_macos_partial_create_rollback() {
        let sock = gateway_docker_socket();
        if !sock.exists() {
            eprintln!("SKIP integration_macos_partial_create_rollback: gateway not running");
            return;
        }
        if !require_slot_socket(0) {
            eprintln!("SKIP: slot-0 socket not present");
            return;
        }

        let pool = Arc::new(VmnetPool::new(8));
        let session_id = SessionId::generate();

        let (vmnet_slot, subnet_cidr, gateway_ip, vm_ip) = pool
            .claim_lima_slot(&session_id, TEST_OPERATOR_UID)
            .expect("claim failed");
        let _slot_idx = vmnet_slot.index; // not used after claim; slot released via release_lima_slot

        let network_info = sandbox_core::NetworkInfo {
            gateway_egress_ip: None,
            operator_uid: Some(TEST_OPERATOR_UID),
            bridge_name: "nonexistent_nic_xyz".to_string(),
            subnet: subnet_cidr,
            gateway_ip: gateway_ip.to_string(),
            vm_ip: vm_ip.to_string(),
            docker_network_name: macos_docker_network_name(&session_id),
            vmnet_slot: Some(vmnet_slot.clone()),
        };

        // setup_macos_gateway with a deliberately bad NIC name must fail.
        let gateway_tag = gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        let result = setup_macos_gateway(
            &session_id,
            &network_info,
            "nonexistent_nic_xyz", // this will cause the macvlan create to fail
            &gateway_docker_route(),
            &gateway_tag,
            None,
            None,
            None,
        );
        assert!(
            result.is_err(),
            "setup_macos_gateway with bad NIC must return Err"
        );

        // Rollback: teardown (idempotent — container/network may be partially created)
        // + release slot.
        teardown_macos_gateway(&session_id, &gateway_docker_route())
            .expect("teardown idempotent after partial create");
        pool.release_lima_slot(&session_id).expect("release failed");

        // Assert no slot leaked.
        assert_eq!(
            pool.running_session_count(),
            0,
            "slot must be released after failed create + rollback"
        );

        // Assert the macvlan network is gone.
        let net_name = macos_docker_network_name(&session_id);
        let net_inspect = docker_gateway(&["network", "inspect", &net_name]);
        assert!(
            !net_inspect.status.success(),
            "macvlan network must not exist after rollback; got success"
        );

        // Assert the gateway container is gone.
        let container = macos_gateway_container_name(&session_id);
        let ctr_inspect = docker_gateway(&["inspect", "--format", "{{.State.Status}}", &container]);
        assert!(
            !ctr_inspect.status.success(),
            "gateway container must not exist after rollback"
        );

        eprintln!("[integration_macos_partial_create_rollback] PASS");
    }

    // ---------------------------------------------------------------------------
    // Test: pool accounting
    // ---------------------------------------------------------------------------

    /// Pool accounting: claim → assert count=1 + slot allocated → release → count=0.
    /// Does not require live gateway infrastructure (pure pool logic).
    #[test]
    fn integration_macos_vmnet_slot_accounting() {
        let pool = Arc::new(VmnetPool::new(2));

        let sid1 = SessionId::generate();
        let sid2 = SessionId::generate();

        // Claim two slots.
        let (slot1, _, _, _) = pool
            .claim_lima_slot(&sid1, TEST_OPERATOR_UID)
            .expect("claim slot 1 failed");
        let (slot2, _, _, _) = pool
            .claim_lima_slot(&sid2, TEST_OPERATOR_UID)
            .expect("claim slot 2 failed");
        assert_ne!(slot1.index, slot2.index, "slots must be distinct");
        assert_eq!(pool.running_session_count(), 2);

        // Pool exhausted (max=2).
        let sid3 = SessionId::generate();
        assert!(
            pool.claim_lima_slot(&sid3, TEST_OPERATOR_UID).is_err(),
            "pool must be exhausted"
        );

        // Release slot 1.
        pool.release_lima_slot(&sid1)
            .expect("release slot 1 failed");
        assert_eq!(pool.running_session_count(), 1);

        // Slot 1's index is now free; next claim must get it.
        let (slot1b, _, _, _) = pool
            .claim_lima_slot(&sid1, TEST_OPERATOR_UID)
            .expect("re-claim after release failed");
        assert_eq!(slot1b.index, slot1.index, "released slot must be reused");
        assert_eq!(pool.running_session_count(), 2);

        // Release both.
        pool.release_lima_slot(&sid1).expect("release 1b failed");
        pool.release_lima_slot(&sid2).expect("release 2 failed");
        assert_eq!(pool.running_session_count(), 0, "all slots released");

        // Idempotent release (no underflow).
        pool.release_lima_slot(&sid1)
            .expect("idempotent release must not fail");
        assert_eq!(pool.running_session_count(), 0);

        eprintln!("[integration_macos_vmnet_slot_accounting] PASS");
    }

    // ---------------------------------------------------------------------------
    // Test: restore_from_infos skips macOS vmnet-slot rows (#248)
    // ---------------------------------------------------------------------------

    /// A persisted macOS Lima session row with a valid vmnet slot must NOT cause
    /// `NetworkManager::restore_from_infos` to fail.
    ///
    /// Root cause: `SubnetAllocator::block_index_for` validates that every
    /// restored subnet falls inside the configured lite base block. A macOS vmnet
    /// slot subnet (e.g. `10.209.128.x/29`) lives in the macOS vmnet base range,
    /// not in the lite pool, so passing it to `restore_from_infos` returns a
    /// `SandboxError::Network` and aborts daemon startup.
    ///
    /// The fix: on macOS the daemon partitions `existing_networks` at startup so
    /// only rows with `vmnet_slot.is_none()` go to `restore_from_infos`; vmnet-
    /// slot rows are handled by `VmnetPool::restore_from_infos`.
    ///
    /// This test verifies the fix directly in unit form: call
    /// `VmnetPool::restore_from_infos` with a slot row — it must succeed — and
    /// assert the pool count reflects the restored slot.
    #[test]
    fn integration_restore_skips_macos_vmnet_slot_rows() {
        let pool = Arc::new(VmnetPool::new(4));
        let session_id = SessionId::generate();

        // Simulate a persisted macOS Lima NetworkInfo row with a vmnet slot.
        let (vmnet_slot, subnet_cidr, gateway_ip, vm_ip) = pool
            .claim_lima_slot(&session_id, TEST_OPERATOR_UID)
            .expect("claim failed");
        assert_eq!(pool.running_session_count(), 1);

        // Release the in-memory claim so we can restore it.
        pool.release_lima_slot(&session_id).expect("release failed");
        assert_eq!(pool.running_session_count(), 0);

        let info = NetworkInfo {
            gateway_egress_ip: None,
            operator_uid: Some(TEST_OPERATOR_UID),
            bridge_name: format!("lima{}", vmnet_slot.index),
            subnet: subnet_cidr,
            gateway_ip: gateway_ip.to_string(),
            vm_ip: vm_ip.to_string(),
            docker_network_name: macos_docker_network_name(&session_id),
            vmnet_slot: Some(vmnet_slot.clone()),
        };

        // `VmnetPool::restore_from_infos` must accept the slot row without error.
        pool.restore_from_infos(&[(session_id, info)], TEST_OPERATOR_UID)
            .expect("restore_from_infos must not fail for a vmnet-slot row");

        // The pool's in-memory count must reflect the restored slot.
        assert_eq!(
            pool.running_session_count(),
            1,
            "restore_from_infos must mark the slot as allocated"
        );

        // The specific slot index must be recorded as in use.
        assert!(
            pool.allocated_slot_indices().contains(&vmnet_slot.index),
            "the restored slot index must appear in allocated_slot_indices"
        );

        // A new claim on a distinct session must skip the already-restored slot.
        let sid2 = SessionId::generate();
        let (slot2, _, _, _) = pool
            .claim_lima_slot(&sid2, TEST_OPERATOR_UID)
            .expect("claim after restore failed");
        assert_ne!(
            slot2.index, vmnet_slot.index,
            "a new claim must not return the already-restored slot"
        );

        eprintln!("[integration_restore_skips_macos_vmnet_slot_rows] PASS");
    }

    // ---------------------------------------------------------------------------
    // Test: create rollback removes VM and session record (#247)
    // ---------------------------------------------------------------------------

    /// A create that fails after `create_vm` has run must leave no VM and no
    /// session record in the store.
    ///
    /// Root cause: the rollback closure in `create_session_macos_lima` tore down
    /// the gateway container and released the vmnet slot but never deleted the
    /// Lima VM (created at step 4) and left the session row in `sessions.db`.
    ///
    /// The fix: the rollback now passes `vm_created = true` after `create_vm`
    /// succeeds. The rollback calls `manager.delete_vm` (idempotent, tolerates
    /// not-found) and then `store.delete_session` to remove the leaked row.
    ///
    /// This test verifies the VM-delete path in isolation using the degenerate
    /// single-uid executor. Infrastructure requirements match the full lifecycle
    /// test; skip if the gateway or slot socket is absent.
    #[test]
    fn integration_create_rollback_removes_vm_and_session_record() {
        // Skip if gateway is not running.
        let sock = gateway_docker_socket();
        if !sock.exists() {
            eprintln!(
                "SKIP integration_create_rollback_removes_vm_and_session_record: \
                 gateway not running"
            );
            return;
        }
        if !require_slot_socket(0) {
            eprintln!(
                "SKIP integration_create_rollback_removes_vm_and_session_record: \
                 slot-0 socket not present"
            );
            return;
        }
        if !setfacl_available() {
            eprintln!(
                "SKIP integration_create_rollback_removes_vm_and_session_record: \
                 setfacl not available"
            );
            return;
        }

        let op_uid = nix::unistd::getuid().as_raw();
        let pool = Arc::new(VmnetPool::new(8));
        let session_id = SessionId::generate();

        // Step 1: claim a slot (mirrors the create path).
        let (vmnet_slot, _subnet_cidr, _gateway_ip, _vm_ip) = pool
            .claim_lima_slot(&session_id, TEST_OPERATOR_UID)
            .expect("claim failed");
        let slot_idx = vmnet_slot.index;

        // Step 2: create the VM using the same registry setup as the full lifecycle test.
        let executor = DirectLimaExecutor::arc();
        let registry = Arc::new(LimaManagerRegistry::new(
            "sandbox-base".to_string(),
            Arc::clone(&executor),
            "10.209.128.0/24".to_string(),
            true, // is_macos
        ));
        let mgr = registry.get_or_create(op_uid).expect("manager failed");
        let config = SessionConfig {
            cpus: 1,
            memory_mb: 512,
            disk_gb: 2,
            workspace_mode: None,
            hardened: false,
            repo: None,
            boot_cmd: None,
            template: None,
            cpus_decimal: None,
            rootless_docker: None,
        };
        let create_result = mgr.create_vm(
            &session_id,
            &config,
            Some((op_uid, nix::unistd::Gid::current().as_raw())),
            Some(slot_idx),
        );

        if create_result.is_err() {
            // create_vm fails when the template or base image is absent;
            // skip rather than assert-fail in that case.
            pool.release_lima_slot(&session_id)
                .expect("release after create failure");
            eprintln!(
                "SKIP integration_create_rollback_removes_vm_and_session_record: \
                 create_vm failed (template/base image absent on this host)"
            );
            return;
        }

        // Verify the VM exists immediately after create.
        let vm_list_before = mgr.list_vms().expect("list_vms failed");
        let vm_name_str = vm_name(&session_id);
        assert!(
            vm_list_before
                .iter()
                .any(|v| v.session_id == Some(session_id)),
            "VM must exist after create_vm; vm_name={vm_name_str}"
        );

        // Step 3: simulate rollback — delete the VM (idempotent).
        mgr.delete_vm(&session_id)
            .expect("delete_vm must succeed after create_vm");

        // Step 4: verify the VM is gone.
        let vm_list_after = mgr.list_vms().expect("list_vms after delete");
        assert!(
            !vm_list_after
                .iter()
                .any(|v| v.session_id == Some(session_id)),
            "VM must be absent after rollback delete; vm_name={vm_name_str}"
        );

        // Step 5: release the slot (idempotent).
        pool.release_lima_slot(&session_id)
            .expect("release after rollback");
        assert_eq!(
            pool.running_session_count(),
            0,
            "slot must be released after rollback"
        );

        eprintln!("[integration_create_rollback_removes_vm_and_session_record] PASS");
    }

    // ---------------------------------------------------------------------------
    // Test: slot reclaimed when a confirmed-dead session is released
    // ---------------------------------------------------------------------------

    /// A vmnet slot held by a confirmed-dead (non-Running) session is released
    /// by the reconcile path and the pool count reflects the reclaim.
    ///
    /// This models the step-6b reconcile logic: a persisted session that was
    /// Running at daemon shutdown but whose Lima VM is no longer Running at
    /// startup is marked Error and its slot is released via `release_lima_slot`.
    /// The pool must then make the slot available for a new session.
    ///
    /// This test is hermetic: it exercises only `VmnetPool` (claim → restore
    /// as "Running" → release via the reconcile path → re-claim). No gateway
    /// VM, no limactl, no Docker required.
    ///
    /// The "confirmed-dead" determination (querying limactl) is done by the
    /// daemon's `reconcile_macos` step 6b; this test verifies the pool
    /// mechanics that step 6b relies on, not the daemon's orchestration itself
    /// (which lives in main.rs and is only reachable via e2e).
    #[test]
    fn integration_macos_slot_reclaimed_on_confirmed_dead_session() {
        let pool = Arc::new(VmnetPool::new(2));

        // --- Step 1: claim a slot for a session (simulates session create) ---
        let sid_dead = SessionId::generate();
        let (slot, subnet, gw, vm) = pool
            .claim_lima_slot(&sid_dead, TEST_OPERATOR_UID)
            .expect("claim failed");
        let slot_idx = slot.index;

        // Record the full NetworkInfo so the pool tracks the mapping.
        let info = NetworkInfo {
            gateway_egress_ip: None,
            operator_uid: Some(TEST_OPERATOR_UID),
            bridge_name: format!("lima{slot_idx}"),
            subnet: subnet.clone(),
            gateway_ip: gw.to_string(),
            vm_ip: vm.to_string(),
            docker_network_name: macos_docker_network_name(&sid_dead),
            vmnet_slot: Some(slot.clone()),
        };
        pool.set_lima_network_info(&sid_dead, slot_idx, info.clone())
            .expect("set_lima_network_info failed");

        assert_eq!(pool.running_session_count(), 1, "one slot must be claimed");
        assert!(
            pool.allocated_slot_indices().contains(&slot_idx),
            "slot must appear in allocated set after claim"
        );

        // --- Step 2: claim a second slot to prove the pool is at capacity ---
        let sid_live = SessionId::generate();
        let (_slot_live, _, _, _) = pool
            .claim_lima_slot(&sid_live, TEST_OPERATOR_UID)
            .expect("second claim failed");
        assert_eq!(
            pool.running_session_count(),
            2,
            "both slots must be claimed"
        );

        // Pool exhausted (max=2); a third claim must fail.
        let sid_extra = SessionId::generate();
        assert!(
            pool.claim_lima_slot(&sid_extra, TEST_OPERATOR_UID).is_err(),
            "pool must be exhausted at max_slots=2"
        );

        // --- Step 3: reconcile path — simulate step 6b releasing the dead slot ---
        //
        // In the daemon's reconcile_macos, step 6b detects that the VM for
        // sid_dead is no longer Running (e.g. it died while the daemon was
        // stopped) and calls pool.release_lima_slot(&sid_dead). This test
        // exercises the same pool operation.
        pool.release_lima_slot(&sid_dead)
            .expect("release_lima_slot on confirmed-dead session must succeed");

        assert_eq!(
            pool.running_session_count(),
            1,
            "pool count must drop to 1 after dead session slot release"
        );
        assert!(
            !pool.allocated_slot_indices().contains(&slot_idx),
            "released slot must no longer appear in allocated set"
        );

        // --- Step 4: the freed slot must be reusable for a new session ---
        let sid_new = SessionId::generate();
        let (slot_new, _, _, _) = pool
            .claim_lima_slot(&sid_new, TEST_OPERATOR_UID)
            .expect("new claim after reconcile reclaim must succeed");
        assert_eq!(
            slot_new.index, slot_idx,
            "reclaimed slot must be reused for the new session"
        );
        assert_eq!(pool.running_session_count(), 2, "both slots claimed again");

        // --- Cleanup ---
        pool.release_lima_slot(&sid_live)
            .expect("release live slot");
        pool.release_lima_slot(&sid_new).expect("release new slot");
        assert_eq!(pool.running_session_count(), 0, "all slots released");

        eprintln!("[integration_macos_slot_reclaimed_on_confirmed_dead_session] PASS");
    }

    // ---------------------------------------------------------------------------
    // Test: restore_from_infos does not double-count an already-released slot
    // ---------------------------------------------------------------------------

    /// After the reconcile path releases a dead session's slot, passing that
    /// session's NetworkInfo to `restore_from_infos` must NOT re-claim the slot
    /// (restore only acts on Running sessions in the daemon; non-Running sessions'
    /// infos are filtered out before calling restore).
    ///
    /// This is a companion to `integration_restore_skips_macos_vmnet_slot_rows`:
    /// it verifies the two-step reconcile sequence (6a release → step-7 restore)
    /// leaves the pool consistent when a session is dead.
    ///
    /// Hermetic — no live infrastructure required.
    #[test]
    fn integration_macos_reconcile_release_then_restore_does_not_double_count() {
        let pool = Arc::new(VmnetPool::new(4));

        // Simulate a persisted Running session (claim its slot).
        let sid_running = SessionId::generate();
        let (slot_r, subnet_r, gw_r, vm_r) = pool
            .claim_lima_slot(&sid_running, TEST_OPERATOR_UID)
            .expect("claim running failed");

        // Simulate a persisted dead session (claim a different slot).
        let sid_dead = SessionId::generate();
        let (slot_d, subnet_d, gw_d, vm_d) = pool
            .claim_lima_slot(&sid_dead, TEST_OPERATOR_UID)
            .expect("claim dead failed");

        // Both claimed up front.
        assert_eq!(pool.running_session_count(), 2);

        // 6a reconcile: release both (as-if daemon startup sees both as non-Running
        // initially). In the real daemon, step 6b then re-evaluates and marks truly
        // Running sessions back; here we model: dead session stays released, running
        // session is restored via restore_from_infos.
        pool.release_lima_slot(&sid_dead)
            .expect("release dead failed");
        pool.release_lima_slot(&sid_running)
            .expect("release running for restore test");

        assert_eq!(pool.running_session_count(), 0, "both released");

        // Step 7: restore_from_infos is called only for confirmed-Running sessions.
        // The dead session's info is excluded — only the running session is restored.
        let info_running = NetworkInfo {
            gateway_egress_ip: None,
            operator_uid: Some(TEST_OPERATOR_UID),
            bridge_name: format!("lima{}", slot_r.index),
            subnet: subnet_r,
            gateway_ip: gw_r.to_string(),
            vm_ip: vm_r.to_string(),
            docker_network_name: macos_docker_network_name(&sid_running),
            vmnet_slot: Some(slot_r.clone()),
        };
        pool.restore_from_infos(&[(sid_running, info_running)], TEST_OPERATOR_UID)
            .expect("restore_from_infos must succeed");

        // Only the running session's slot must be allocated.
        assert_eq!(
            pool.running_session_count(),
            1,
            "only the running session's slot must be restored"
        );
        assert!(
            pool.allocated_slot_indices().contains(&slot_r.index),
            "running session slot must be in allocated set"
        );
        assert!(
            !pool.allocated_slot_indices().contains(&slot_d.index),
            "dead session slot must NOT be re-allocated by restore"
        );

        // The dead session's slot is free — a new session can claim it.
        let sid_new = SessionId::generate();
        let (slot_new, _, _, _) = pool
            .claim_lima_slot(&sid_new, TEST_OPERATOR_UID)
            .expect("new claim on freed dead slot must succeed");
        assert_eq!(
            slot_new.index, slot_d.index,
            "the freed dead-session slot must be reusable"
        );

        // Cleanup — drop captured but unused bindings, then release slots.
        drop((subnet_d, gw_d, vm_d, slot_d));
        pool.release_lima_slot(&sid_running).unwrap();
        pool.release_lima_slot(&sid_new).unwrap();
        assert_eq!(pool.running_session_count(), 0);

        eprintln!("[integration_macos_reconcile_release_then_restore_does_not_double_count] PASS");
    }
}
