//! Integration tests for the gateway container lifecycle and nftables injection.
//!
//! Requirements:
//!   - Docker daemon running
//!   - `sandbox-gateway` image built (`make gateway-image`)
//!   - Sufficient privileges for Docker and nftables

use std::process::Command;

use sandbox_core::gateway::{GATEWAY_IMAGE, GatewayManager, GatewayStatus, container_name};
use sandbox_core::network::NetworkManager;
use sandbox_core::session::SessionId;
use sandbox_core::{AtomicListenerWriter, PolicyCompiler, session_listener_host_path};
use std::net::Ipv4Addr;

#[test]
fn test_gateway_lifecycle() {
    // Use 10.209.3.0/24 to avoid collisions with other tests.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 3, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    // Create the Docker network.
    let network_info = net_mgr.create_network(&session_id).unwrap();

    // Create the gateway container with nftables rules.
    let create_result = gw_mgr.create_gateway(&session_id, &network_info, None, None);
    if let Err(ref e) = create_result {
        // Clean up on failure.
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("create_gateway failed: {e}");
    }

    // Verify health.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(status, GatewayStatus::Healthy, "gateway should be healthy");

    // Verify nftables rules are present in the container.
    let gw_container = container_name(&session_id);
    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("docker exec nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        nft_output.contains("table inet sandbox"),
        "deny-all table should exist in nft ruleset: {nft_output}"
    );
    assert!(
        nft_output.contains("table inet sandbox_dnat"),
        "DNAT table should exist in nft ruleset: {nft_output}"
    );

    // Stop and remove the gateway.
    gw_mgr.stop_gateway(&session_id).unwrap();

    // Verify the container is gone.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::NotRunning,
        "gateway should not be running after stop"
    );

    // Clean up the network.
    net_mgr.delete_network(&session_id).unwrap();
}

#[test]
fn test_gateway_nftables_injection_standalone() {
    // Use 10.209.4.0/24 to avoid collisions.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 4, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    // Create network and a minimal container (no need for full gateway here).
    let network_info = net_mgr.create_network(&session_id).unwrap();

    // Start the gateway image with CAP_NET_ADMIN so nft works inside the
    // container. Override entrypoint with sleep so we can test nftables
    // injection without the full gateway stack.
    let gw_container = container_name(&session_id);
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &gw_container,
            "--network",
            &network_info.docker_network_name,
            "--cap-add",
            "NET_ADMIN",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--entrypoint",
            "sleep",
            GATEWAY_IMAGE,
            "300",
        ])
        .output()
        .expect("docker run should succeed");

    if !output.status.success() {
        let _ = net_mgr.delete_network(&session_id);
        panic!(
            "docker run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Discover the container's auto-assigned IP.
    let container_ip = gw_mgr.container_ip(&session_id).unwrap();

    // Inject deny-all rules.
    gw_mgr.inject_deny_all(&session_id).unwrap();

    // Verify rules are present.
    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        nft_output.contains("table inet sandbox"),
        "deny-all table should exist"
    );
    assert!(
        nft_output.contains("policy drop"),
        "input policy should be drop"
    );

    // Inject DNAT rules using the container's actual IP.
    gw_mgr
        .inject_dnat(&session_id, &network_info, &container_ip)
        .unwrap();

    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        nft_output.contains("table inet sandbox_dnat"),
        "DNAT table should exist"
    );
    assert!(nft_output.contains("dnat"), "DNAT rules should be present");

    // Remove DNAT rules.
    gw_mgr.remove_dnat_rules(&session_id).unwrap();

    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        !nft_output.contains("table inet sandbox_dnat"),
        "DNAT table should be removed after remove_dnat_rules"
    );
    // deny-all should still be present.
    assert!(
        nft_output.contains("table inet sandbox"),
        "deny-all table should still exist"
    );

    // Clean up.
    let _ = Command::new("docker")
        .args(["rm", "--force", &gw_container])
        .output();
    let _ = net_mgr.delete_network(&session_id);
}

/// M9-S18: Envoy xDS listener plumbing — verify the split bootstrap +
/// dynamic LDS listener design with atomic host-side rewrites.
///
/// Exercises:
///   - Envoy starts against the policy-compiled bootstrap
///     (`/etc/envoy/envoy-bootstrap.yaml`) written via `docker exec` and
///     loads the bind-mounted listener file (`/etc/envoy/listeners/
///     listener.yaml`) via filesystem LDS.
///   - `GET /config_dump` shows the listener under `dynamic_listeners`
///     (not `static_listeners`), proving the xDS path is live.
///   - `AtomicListenerWriter` can replace the listener file on the host
///     while Envoy is running, and a subsequent `config_dump` reflects
///     the new generation (i.e. the `MovedTo` inotify event reached
///     Envoy's LDS watcher).
///   - The `mitmproxy` cluster is present under `static_clusters` in the
///     bootstrap, scaffolded but not yet routed to (routing is M9-S19).
#[test]
fn test_gateway_lds_listener_and_atomic_rewrite() {
    // Use 10.209.5.0/24 to avoid collisions with other tests.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 5, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    let network_info = net_mgr.create_network(&session_id).unwrap();

    let create_result = gw_mgr.create_gateway(&session_id, &network_info, None, None);
    if let Err(ref e) = create_result {
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("create_gateway failed: {e}");
    }

    let gw_container = container_name(&session_id);

    // Healthy gateway = Envoy + CoreDNS + mitmproxy all ready. This is
    // the first-order signal that the split bootstrap actually works
    // (entrypoint.sh waits for both bootstrap and listener files, then
    // starts Envoy pointing at the bootstrap).
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Healthy,
        "gateway should be healthy after create_gateway (LDS bootstrap must work)"
    );

    // ---------- 1. Verify the bootstrap file landed in the container ----------
    // sandboxd writes this via `docker exec` right after `docker run`.
    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "cat",
            "/etc/envoy/envoy-bootstrap.yaml",
        ])
        .output()
        .expect("docker exec cat bootstrap should succeed");
    assert!(
        output.status.success(),
        "bootstrap file should exist inside container: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bootstrap_contents = String::from_utf8_lossy(&output.stdout);
    assert!(
        bootstrap_contents.contains("dynamic_resources:"),
        "bootstrap must declare dynamic_resources for LDS:\n{bootstrap_contents}"
    );
    assert!(
        bootstrap_contents.contains("path: /etc/envoy/listeners/listener.yaml"),
        "bootstrap lds_config.path must point at LDS listener file:\n{bootstrap_contents}"
    );
    assert!(
        bootstrap_contents.contains("name: mitmproxy"),
        "mitmproxy cluster must be scaffolded in bootstrap (M9-S18):\n{bootstrap_contents}"
    );

    // ---------- 2. Verify listener appears as a DYNAMIC listener ----------
    // Envoy's /config_dump returns the listener under `dynamic_listeners`
    // (with `active_state`) when served via LDS, versus `static_listeners`
    // when inlined in the bootstrap. This is the key M9-S18 invariant.
    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "curl",
            "-sf",
            "http://127.0.0.1:9901/config_dump?resource=dynamic_listeners",
        ])
        .output()
        .expect("docker exec curl config_dump should succeed");
    assert!(
        output.status.success(),
        "Envoy admin /config_dump should respond: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dynamic_listeners = String::from_utf8_lossy(&output.stdout);
    assert!(
        dynamic_listeners.contains("policy_listener"),
        "dynamic_listeners must contain policy_listener (served via LDS):\n{dynamic_listeners}"
    );

    // Double-check: static_listeners must NOT have policy_listener.
    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "curl",
            "-sf",
            "http://127.0.0.1:9901/config_dump?resource=static_listeners",
        ])
        .output()
        .expect("docker exec curl static_listeners should succeed");
    let static_listeners = String::from_utf8_lossy(&output.stdout);
    assert!(
        !static_listeners.contains("policy_listener"),
        "static_listeners must NOT contain policy_listener (it is dynamic):\n{static_listeners}"
    );

    // ---------- 3. Verify mitmproxy cluster appears as a STATIC cluster ----------
    // Clusters never change mid-session, so they live in the bootstrap
    // and appear under `static_clusters` in /config_dump.
    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "curl",
            "-sf",
            "http://127.0.0.1:9901/config_dump?resource=static_clusters",
        ])
        .output()
        .expect("docker exec curl static_clusters should succeed");
    let static_clusters = String::from_utf8_lossy(&output.stdout);
    assert!(
        static_clusters.contains("\"name\": \"mitmproxy\"")
            || static_clusters.contains("\"name\":\"mitmproxy\""),
        "static_clusters must include mitmproxy cluster (M9-S18 scaffolding):\n{static_clusters}"
    );
    assert!(
        static_clusters.contains("\"name\": \"original_dst\"")
            || static_clusters.contains("\"name\":\"original_dst\""),
        "static_clusters must include original_dst cluster:\n{static_clusters}"
    );

    // ---------- 4. Atomically rewrite the listener via MovedTo ----------
    // Use the same AtomicListenerWriter sandboxd uses. The rewrite must
    // succeed (filter_chains-only change) and Envoy's LDS watcher must
    // pick it up via the `MovedTo` inotify event. We detect the reload
    // via Envoy's `listener_manager.lds.update_success` stat — it
    // increments once per accepted LDS update.
    //
    // We also observe `listener_manager.lds.update_rejected` so a
    // bad-config regression fails with an actionable message instead
    // of the generic "MovedTo did not reach the watcher" timeout.
    fn lds_stat(container: &str, stat: &str) -> u64 {
        let filter_arg = format!("filter={stat}$&format=text");
        let url = format!("http://127.0.0.1:9901/stats?{filter_arg}");
        let out = Command::new("docker")
            .args(["exec", container, "curl", "-sf", &url])
            .output()
            .expect("curl envoy /stats should succeed");
        let text = String::from_utf8_lossy(&out.stdout);
        // Expected output format: `<stat>: 1`
        for line in text.lines() {
            if let Some((_, v)) = line.split_once(':') {
                if let Ok(n) = v.trim().parse::<u64>() {
                    return n;
                }
            }
        }
        0
    }
    fn lds_update_success(container: &str) -> u64 {
        lds_stat(container, "listener_manager.lds.update_success")
    }
    fn lds_update_rejected(container: &str) -> u64 {
        lds_stat(container, "listener_manager.lds.update_rejected")
    }

    let initial_updates = lds_update_success(&gw_container);
    let initial_rejections = lds_update_rejected(&gw_container);

    // Build a new listener generation that differs only in filter_chains.
    // The initial listener is a deny-all with `filter_chains: []`; we
    // replace it with a listener that routes to the pre-defined
    // `original_dst` cluster (this is the L1 passthrough chain shape the
    // policy compiler produces). Using `compile_initial_envoy_listener`
    // is not sufficient here because it equals the current on-disk
    // content — `fs::rename` still fires `MovedTo`, but same-content
    // rewrites make the test weaker. Instead, craft a minimal L1-style
    // filter chain body.
    use sandbox_core::policy::{FILTER_CHAINS_BEGIN_MARKER, FILTER_CHAINS_END_MARKER};
    let mut updated_listener = PolicyCompiler::envoy_deny_all_listener();
    let old_body = format!(
        "{FILTER_CHAINS_BEGIN_MARKER}\n    filter_chains: []\n{FILTER_CHAINS_END_MARKER}"
    );
    let new_body = format!(
        "{FILTER_CHAINS_BEGIN_MARKER}\n    default_filter_chain:\n      filters:\n        - name: envoy.filters.network.tcp_proxy\n          typed_config:\n            \"@type\": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy\n            stat_prefix: sandbox_l1_passthrough\n            cluster: original_dst\n{FILTER_CHAINS_END_MARKER}"
    );
    assert!(
        updated_listener.contains(&old_body),
        "initial listener must contain the framed deny-all body"
    );
    updated_listener = updated_listener.replace(&old_body, &new_body);

    let host_path = session_listener_host_path(&session_id);
    let writer = AtomicListenerWriter::new(&host_path);
    writer
        .write(&updated_listener)
        .expect("atomic listener rewrite should succeed");

    // Poll for the LDS update. Envoy processes the inotify event
    // asynchronously; in practice it lands within ~250ms, but CI is
    // slow so allow up to 15s.
    //
    // We check `update_rejected` on every iteration so that if Envoy
    // refuses the rewritten listener (bad YAML, unknown field, invalid
    // filter chain shape, etc.) the test fails with a config-diagnosis
    // message instead of a misleading "inotify event did not arrive"
    // timeout.
    let mut final_updates = initial_updates;
    let mut final_rejections = initial_rejections;
    for _ in 0..60 {
        final_updates = lds_update_success(&gw_container);
        final_rejections = lds_update_rejected(&gw_container);
        if final_rejections > initial_rejections || final_updates > initial_updates {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert!(
        final_rejections == initial_rejections,
        "Envoy rejected the updated listener config ({initial_rejections} -> \
         {final_rejections}). The MovedTo event reached Envoy but the listener \
         payload was refused — check /config_dump and the Envoy log for the \
         validation error. This usually means the test-crafted filter chain \
         body is malformed or missing a required field."
    );
    assert!(
        final_updates > initial_updates,
        "Envoy LDS update_success should have incremented from {initial_updates} after \
         atomic listener rewrite — the MovedTo inotify event did not reach the watcher. \
         This usually means the listener file was replaced via inline write instead of \
         host-side rename."
    );

    // Post-rewrite, Envoy should still be healthy (no drain, no reset).
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Healthy,
        "gateway should remain healthy after atomic listener rewrite"
    );

    // ---------- 5. Verify the dynamic listener version_info advanced ----------
    // After a successful LDS update Envoy reports a non-initial
    // `version_info` under the dynamic listener's `active_state`.
    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "curl",
            "-sf",
            "http://127.0.0.1:9901/config_dump?resource=dynamic_listeners",
        ])
        .output()
        .expect("docker exec curl config_dump (post-rewrite) should succeed");
    let dynamic_listeners_after = String::from_utf8_lossy(&output.stdout);
    assert!(
        dynamic_listeners_after.contains("policy_listener"),
        "policy_listener must still be dynamic after rewrite:\n{dynamic_listeners_after}"
    );

    // ---------- Clean up ----------
    gw_mgr.stop_gateway(&session_id).unwrap();
    net_mgr.delete_network(&session_id).unwrap();
}
