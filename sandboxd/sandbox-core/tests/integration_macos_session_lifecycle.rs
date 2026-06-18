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
/// ## Deferred to M20-S6 (Python E2E)
///
/// - The egress-traffic proof (delete-the-gateway-route regression: assert
///   `eth0` cannot reach the internet after `restrict=on` is applied). M20-S4
///   proves the VM BOOTS with the wrapper; M20-S6 proves traffic is blocked.
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
        teardown_macos_gateway, verify_restrict_on,
    };
    use sandbox_core::network::{VmnetPool, vmnet_slot_socket_path};
    use sandbox_core::session::SessionId;
    use sandbox_core::test_support::direct_executor::DirectLimaExecutor;

    // ---------------------------------------------------------------------------
    // Shared helpers
    // ---------------------------------------------------------------------------

    /// Resolve the gateway Lima forwarded Docker socket path.
    ///
    /// The gateway instance lives under the daemon uid's LIMA_HOME.
    /// In dev mode the daemon is the current user, so daemon_uid == current uid.
    fn gateway_docker_socket() -> PathBuf {
        let uid = nix::unistd::Uid::current().as_raw();
        let daemon_lima_home = operator_lima_home(uid);
        daemon_lima_home
            .join("sandboxd-gateway")
            .join("gateway-docker.sock")
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
    /// The gateway image (`sandbox-gateway:<version>`) is loaded inside the
    /// gateway Lima VM at M22-S5; until then this guard skips image-dependent
    /// tests cleanly.
    fn require_gateway_image(tag: &str) -> bool {
        let out = docker_gateway(&["image", "inspect", tag]);
        if !out.status.success() {
            eprintln!(
                "SKIP: gateway image `{tag}` not loaded in the gateway VM \
                 (deferred to M22-S5; the full test runs at M20-S6 e2e bring-up). \
                 To enable: `docker -H unix://<gateway-sock> load < gateway-image.tar`"
            );
            return false;
        }
        true
    }

    /// Return `true` if `setfacl` is available on this host.
    ///
    /// The macOS operator-LIMA_HOME path uses `ensure_operator_lima_home`, which
    /// internally calls `setfacl` (Linux-only for POSIX ACL support). On macOS
    /// this is absent until the minimal M21 slice lands (todo #236). Tests that
    /// call `registry.get_or_create(op_uid)` → `ensure_operator_lima_home` will
    /// fail with "failed to spawn setfacl" when it's missing.
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
    /// DEFERRED TO M20-S6: the egress traffic proof (delete gateway route,
    /// confirm eth0 blocked). This test proves the VM boots with restrict=on.
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

        // Guard 3: setfacl must be available (ensure_operator_lima_home requires it on
        // macOS until the M21 minimal slice lands; todo #236).
        if !setfacl_available() {
            eprintln!(
                "SKIP integration_macos_create_start_stop_rm: \
                 `setfacl` not available on this host — ensure_operator_lima_home \
                 requires it for the macOS operator-LIMA_HOME path (deferred to M21, \
                 todo #236). The full live HVF boot runs at M20-S6 e2e bring-up."
            );
            return;
        }

        // Guard 4: the gateway image must be loaded inside the gateway VM.
        let gateway_tag = gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        if !require_gateway_image(&gateway_tag) {
            eprintln!(
                "SKIP integration_macos_create_start_stop_rm: \
                 requires the sandbox-gateway image loaded into the gateway VM (M22-S5); \
                 the full live HVF boot runs at M20-S6 e2e bring-up."
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
            .claim_lima_slot(&session_id)
            .expect("claim_lima_slot failed");
        let slot_idx = vmnet_slot.index;
        let nic_name = format!("lima{slot_idx}");

        let network_info = sandbox_core::NetworkInfo {
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
            gateway_sock: PathBuf,
            lima_home: PathBuf,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Best-effort teardown — ignore errors.
                let _ = teardown_macos_gateway(&self.session_id, &self.gateway_sock);
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
            gateway_sock: sock.clone(),
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
            &sock,
            &gateway_tag,
            None, // ca_dir (deferred to M20-S6+)
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
        verify_restrict_on(&session_id, &lima_home)
            .expect("verify_restrict_on failed: wrapper marker not found or wrong content");

        eprintln!(
            "[integration_macos_create_start_stop_rm] VM {vm} booted with restrict=on confirmed"
        );

        // --- Step 6: stop + teardown ---
        manager.stop_vm(&session_id).expect("limactl stop failed");

        teardown_macos_gateway(&session_id, &sock).expect("teardown_macos_gateway failed");

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

        // Guard 3: the gateway image must be loaded inside the gateway VM.
        // The image load is deferred to M22-S5; until then this test skips
        // cleanly and auto-activates when the image is available at M20-S6
        // e2e bring-up.
        let gateway_tag = gateway_image_tag_for_version(env!("CARGO_PKG_VERSION"));
        if !require_gateway_image(&gateway_tag) {
            eprintln!(
                "SKIP integration_macos_gateway_side_lifecycle: \
                 requires the sandbox-gateway image loaded into the gateway VM (M22-S5); \
                 the full gateway-side exercise runs at M20-S6 e2e bring-up."
            );
            return;
        }

        let pool = Arc::new(VmnetPool::new(8));
        let session_id = SessionId::generate();

        let (vmnet_slot, subnet_cidr, gateway_ip, vm_ip) =
            pool.claim_lima_slot(&session_id).expect("claim failed");
        let _slot_idx = vmnet_slot.index; // slot_idx used only to drive slot claim; nic_name derived from slot
        let nic_name = format!("lima{}", vmnet_slot.index);

        let network_info = sandbox_core::NetworkInfo {
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
            &sock,
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
        teardown_macos_gateway(&session_id, &sock).expect("teardown failed");
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

        let (vmnet_slot, subnet_cidr, gateway_ip, vm_ip) =
            pool.claim_lima_slot(&session_id).expect("claim failed");
        let _slot_idx = vmnet_slot.index; // not used after claim; slot released via release_lima_slot

        let network_info = sandbox_core::NetworkInfo {
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
            &sock,
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
        teardown_macos_gateway(&session_id, &sock)
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
        let (slot1, _, _, _) = pool.claim_lima_slot(&sid1).expect("claim slot 1 failed");
        let (slot2, _, _, _) = pool.claim_lima_slot(&sid2).expect("claim slot 2 failed");
        assert_ne!(slot1.index, slot2.index, "slots must be distinct");
        assert_eq!(pool.running_session_count(), 2);

        // Pool exhausted (max=2).
        let sid3 = SessionId::generate();
        assert!(
            pool.claim_lima_slot(&sid3).is_err(),
            "pool must be exhausted"
        );

        // Release slot 1.
        pool.release_lima_slot(&sid1)
            .expect("release slot 1 failed");
        assert_eq!(pool.running_session_count(), 1);

        // Slot 1's index is now free; next claim must get it.
        let (slot1b, _, _, _) = pool
            .claim_lima_slot(&sid1)
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
}
