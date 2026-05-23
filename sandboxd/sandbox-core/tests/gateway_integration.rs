//! Integration tests for the gateway container lifecycle and nftables injection.
//!
//! Requirements:
//!   - Docker daemon running
//!   - `sandbox-gateway` image built (`make gateway-image`)
//!   - Sufficient privileges for Docker and nftables
//!
//! ## Gate
//!
//! Every test in this file is named `integration_*` and is selected
//! by the `integration` nextest profile (see
//! `sandboxd/.config/nextest.toml`). The default profile filters
//! these out so `make test` / `cargo nextest run --workspace` stays
//! hermetic with no Docker dependency; `make test-integration`
//! invokes the `integration` profile after building the gateway image.

use std::process::Command;

use sandbox_core::gateway::{
    GatewayManager, GatewayStatus, container_name, gateway_image_tag_for_version,
};
use sandbox_core::network::NetworkManager;
use sandbox_core::session::SessionId;
use sandbox_core::{
    AssuranceLevel, AtomicListenerWriter, Destination, DockerExecLdsProbe, EVENTS_DIR_IN_CONTAINER,
    LdsAckOutcome, LdsStatsProbe, Policy, PolicyCompiler, PolicyDistributor, PolicyRule, Protocol,
    session_events_host_dir, session_listener_host_path, wait_for_lds_ack,
};
use std::net::Ipv4Addr;
use std::time::Duration;

#[test]
fn integration_gateway_lifecycle() {
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

    // Verify health. No policy has been applied yet, so the bootstrap
    // listener (empty `filter_chains`) is rejected by Envoy and
    // `total_listeners_active == 0`. The two-stage gateway_status
    // probe (#52) reports this as `Starting`, not `Healthy` — the
    // listener-aware verdict is the contract these tests pin.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Starting,
        "gateway should be Starting (healthcheck OK but no active listener) immediately \
         after create_gateway with no policy applied"
    );

    // Verify nftables rules are present in the container.
    let gw_container = container_name(&session_id);
    let output = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("docker exec nft list should succeed");

    let nft_output = String::from_utf8_lossy(&output.stdout);

    // The gateway exposes exactly two nftables tables after
    // `create_gateway` (before any policy is applied): `sandbox`
    // (deny-all forward/input baseline) and `sandbox_dnat` (DNS →
    // CoreDNS, all other TCP → Envoy:10000). Once a policy is
    // applied, `sandbox_policy` joins the set — giving the
    // three-table steady state. The legacy `sandbox_l3` transparent-
    // DNAT table is gone: L3 traffic reaches mitmproxy via Envoy
    // CONNECT tunneling, not kernel-level redirection.
    //
    // We positively assert the full set rather than just checking for
    // known tables, so a future regression that leaks a fourth table
    // (e.g. a debug `sandbox_tmp`) fails here.
    let tables: std::collections::HashSet<&str> = nft_output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            // `nft list ruleset` emits `table inet <name> {` as the
            // header for each table; strip whitespace and the opening
            // brace.
            trimmed
                .strip_prefix("table inet ")
                .and_then(|rest| rest.split_whitespace().next())
        })
        .collect();
    let expected: std::collections::HashSet<&str> =
        ["sandbox", "sandbox_dnat"].into_iter().collect();
    assert_eq!(
        tables, expected,
        "gateway nftables tables must be exactly {{sandbox, sandbox_dnat}} \
         after create_gateway (no policy applied yet); got {tables:?}. \
         Full ruleset:\n{nft_output}"
    );

    // mitmproxy runs in regular (forward-proxy) mode on loopback —
    // it must NOT listen on 0.0.0.0:8080, the loopback 18080 port
    // must be open inside the container, and crucially nothing must
    // be listening on 18080 on the VM-facing IP (mitmproxy must bind
    // loopback only — "nothing is listening on 18080 on the VM-facing IP"). A
    // regression that bound mitmproxy to 0.0.0.0:18080 instead of
    // 127.0.0.1:18080 would expose the forward proxy to the sandboxed
    // VM and short-circuit the Envoy filter chains.
    //
    // The gateway image is minimal (no `ss` / `netstat` binaries), so we
    // parse `/proc/net/tcp` directly. Each listening socket has state
    // `0A`; local_address is `<IP>:<PORT>` — IP is little-endian hex,
    // port is big-endian hex (network byte order).
    //   127.0.0.1:18080 → `0100007F:46A0`
    //   0.0.0.0:8080    → `00000000:1F90`
    //   0.0.0.0:18080   → `00000000:46A0` (must never appear)
    let proc_net_tcp = Command::new("docker")
        .args(["exec", &gw_container, "cat", "/proc/net/tcp"])
        .output()
        .expect("docker exec cat /proc/net/tcp should succeed");
    let listeners = String::from_utf8_lossy(&proc_net_tcp.stdout);
    // Listening sockets: second column = local addr; fourth column = state (0A = LISTEN).
    let mut listen_addrs: Vec<&str> = Vec::new();
    for line in listeners.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[3] == "0A" {
            listen_addrs.push(cols[1]);
        }
    }
    assert!(
        listen_addrs.contains(&"0100007F:46A0"),
        "mitmproxy must listen on 127.0.0.1:18080; listening sockets: {listen_addrs:?}\n{listeners}"
    );
    assert!(
        !listen_addrs.contains(&"00000000:1F90"),
        "mitmproxy must no longer listen on 0.0.0.0:8080 (transparent-mode leftover); listening sockets: {listen_addrs:?}"
    );
    // Loopback-bind guard: the only listener on port 46A0 (18080) must
    // be on 0100007F (127.0.0.1). Any other 18080 binding (most
    // importantly 00000000:46A0 for 0.0.0.0) would mean mitmproxy's
    // forward proxy is reachable from the VM-facing IP.
    let rogue_18080: Vec<&&str> = listen_addrs
        .iter()
        .filter(|a| a.ends_with(":46A0") && !a.starts_with("0100007F:"))
        .collect();
    assert!(
        rogue_18080.is_empty(),
        "mitmproxy must be bound to loopback only; found non-loopback \
         listeners on port 18080: {rogue_18080:?}. Full listening sockets: \
         {listen_addrs:?}"
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
fn integration_gateway_nftables_injection_standalone() {
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
            &gateway_image_tag_for_version(env!("CARGO_PKG_VERSION")),
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

/// Envoy xDS listener plumbing — verify the split bootstrap +
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
///     bootstrap. The L3 cutover routes every L3 filter chain to this
///     cluster via `tcp_proxy.tunneling_config`.
#[test]
fn integration_gateway_lds_listener_and_atomic_rewrite() {
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

    // Pre-policy verdict: gateway processes (Envoy admin /ready, CoreDNS,
    // mitmproxy, deny-logger) are all up — but the deny-all bootstrap
    // listener (empty `filter_chains`) is rejected by Envoy at runtime
    // so `total_listeners_active == 0`. The two-stage gateway_status
    // probe reports this as `Starting`, not `Healthy` (#52). Post-#52,
    // a `Healthy` verdict here would indicate the listener-aware probe
    // regressed.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Starting,
        "gateway should be Starting (no active listener pre-policy) after create_gateway"
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
        "mitmproxy cluster must be defined in bootstrap:\n{bootstrap_contents}"
    );

    // ---------- 2. Verify listener appears as a DYNAMIC listener ----------
    // Envoy's /config_dump returns the listener under `dynamic_listeners`
    // (with `active_state`) when served via LDS, versus `static_listeners`
    // when inlined in the bootstrap. This is the key xDS-split invariant.
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
        "static_clusters must include mitmproxy cluster (L3 cutover target):\n{static_clusters}"
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
    // Witnesses for the post-rewrite "listener actually loaded, end-state
    // stable" assertions further below.
    fn listener_added(container: &str) -> u64 {
        lds_stat(container, "listener_manager.listener_added")
    }
    fn listener_create_success(container: &str) -> u64 {
        lds_stat(container, "listener_manager.listener_create_success")
    }
    fn listener_modified(container: &str) -> u64 {
        lds_stat(container, "listener_manager.listener_modified")
    }
    fn listener_in_place_updated(container: &str) -> u64 {
        lds_stat(container, "listener_manager.listener_in_place_updated")
    }
    fn total_listeners_active(container: &str) -> u64 {
        lds_stat(container, "listener_manager.total_listeners_active")
    }
    fn total_listeners_draining(container: &str) -> u64 {
        lds_stat(container, "listener_manager.total_listeners_draining")
    }

    let initial_updates = lds_update_success(&gw_container);
    let initial_rejections = lds_update_rejected(&gw_container);
    // Snapshot the listener-lifecycle witnesses *before* the rewrite —
    // post-rewrite assertions below compare against these. (The
    // `listener_modified` / `listener_in_place_updated` witnesses for
    // the second rewrite — section 4c — capture their own pre-snapshots
    // closer to the second `writer.write` call so the deltas attribute
    // cleanly to that mutation.)
    let initial_added = listener_added(&gw_container);
    let initial_create_success = listener_create_success(&gw_container);

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
    let old_body =
        format!("{FILTER_CHAINS_BEGIN_MARKER}\n    filter_chains: []\n{FILTER_CHAINS_END_MARKER}");
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

    // Post-rewrite, the rewrite added a working listener — gateway
    // verdict should flip from `Starting` (zero active listeners) to
    // `Healthy` (>= 1 active listener). Post-#52 this transition is
    // the load-bearing contract for the listener-aware health check.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Healthy,
        "gateway should flip to Healthy after the rewrite installs an active listener"
    );

    // ---------- 4b. Listener-lifecycle witnesses (post-#52 contract) ----------
    // The `Healthy` verdict above already incorporates Envoy's
    // `total_listeners_active >= 1` gauge (post-#52 two-stage probe).
    // The stats checks below pin the underlying counters directly so
    // a regression in the probe's parsing layer surfaces as a
    // counter-mismatch rather than a green `gateway_status` masking
    // an invisible regression — and to lock the warm-restart-with-
    // drain witnesses introduced by Path B for #51.
    //
    // Witnesses asserted (text-format /stats, matching the precedent
    // helpers in this file at ~lines 423 and 723):
    //   - `listener_manager.listener_added` advanced or
    //     `listener_manager.listener_create_success` advanced — proves
    //     Envoy actually processed the rewrite into an active listener
    //     (defends against a "MovedTo arrived but Envoy never built the
    //     listener" failure mode that `lds.update_success` alone does
    //     not catch).
    //   - `listener_manager.total_listeners_active >= 1` — proves a
    //     listener is loaded and serving (the deny-all bootstrap is
    //     rejected by Envoy, so this gauge is 0 before the rewrite —
    //     the rewrite is what makes it 1).
    //   - `listener_manager.total_listeners_draining == 0` once Envoy
    //     finishes warming — proves no listener is stuck in drain. The
    //     gauge can transiently be 1 mid-rewrite, so we poll briefly
    //     for it to settle (mirrors the `update_success` poll above).
    let final_added = listener_added(&gw_container);
    let final_create_success = listener_create_success(&gw_container);
    let final_total_active = total_listeners_active(&gw_container);
    assert!(
        final_added > initial_added || final_create_success > initial_create_success,
        "neither listener_added ({initial_added} -> {final_added}) nor \
         listener_create_success ({initial_create_success} -> {final_create_success}) \
         advanced across the rewrite. Envoy reported lds.update_success but apparently \
         never built the listener — check /config_dump for a stuck-in-warming listener."
    );
    assert!(
        final_total_active >= 1,
        "listener_manager.total_listeners_active = {final_total_active} after rewrite; \
         expected >= 1. The deny-all bootstrap listener is rejected by Envoy, so the \
         rewrite is what must produce an active listener. A value of 0 here means the \
         rewritten listener was accepted by LDS but failed to come up (likely warming \
         stuck or the listener was immediately drained)."
    );
    // Poll briefly for `total_listeners_draining` to settle to 0.
    // Envoy's warm-restart path (the path the current emit shape uses)
    // transiently bumps this gauge while the previous generation drains.
    // It must return to 0 in the steady state — a non-zero terminal
    // value would mean a listener is stuck draining.
    let mut final_draining = total_listeners_draining(&gw_container);
    for _ in 0..60 {
        if final_draining == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        final_draining = total_listeners_draining(&gw_container);
    }
    assert_eq!(
        final_draining, 0,
        "listener_manager.total_listeners_draining = {final_draining} after waiting for \
         drain to complete; expected 0 in the steady state. A listener is stuck draining \
         after the rewrite — connections to it will be reset when the drain timer fires."
    );

    // ---------- 4c. Lock in the warm-restart-with-drain contract (#51) ----------
    // The previous block witnessed that the FIRST rewrite (deny-all empty
    // -> populated) is processed as a listener *add* (`listener_added`
    // ticks). To exercise — and lock in — the path Envoy actually takes
    // for a *mutation* of the populated listener (the steady-state shape
    // hit by every DNS-rotation-driven rewrite), we perform a second
    // rewrite that differs only in `stat_prefix` inside the
    // filter-chains body and verify the warm-restart-with-drain witnesses.
    //
    // What this asserts (the Path B contract chosen for #51):
    //   - The listener's *identity* is preserved across the rewrite: it
    //     is still named `policy_listener`, still served as a dynamic
    //     listener, and `lds.update_success` advances cleanly without
    //     `lds.update_rejected` advancing.
    //   - The mutation traverses Envoy's warm-restart-with-drain path,
    //     not the in-place update path:
    //       * `listener_manager.listener_modified` advances (the warm-
    //         restart witness).
    //       * `listener_manager.listener_in_place_updated` does NOT
    //         advance (the in-place witness — pinned at 0 to lock the
    //         current behavior; if Envoy ever activates the in-place
    //         path here, this test must be updated alongside the
    //         rustdoc on `PolicyCompiler::compile_envoy_listener` so
    //         design comment and runtime stay aligned).
    //       * `total_listeners_draining` settles back to 0 in the
    //         steady state (re-checked after this rewrite).
    //
    // This is intentionally a tighter contract than #22's "Healthy and
    // active" witnesses: we are pinning the runtime-observed semantics
    // so future regressions (e.g. a framing change that flips Envoy
    // into rebuild-as-new-listener, or a YAML shape that switches to
    // in-place) surface as a test failure rather than a silent shift.
    let pre2_updates = lds_update_success(&gw_container);
    let pre2_rejections = lds_update_rejected(&gw_container);
    let pre2_modified = listener_modified(&gw_container);
    let pre2_in_place = listener_in_place_updated(&gw_container);
    let pre2_draining = total_listeners_draining(&gw_container);

    // Build a generation that differs from `updated_listener` only in the
    // `stat_prefix` value — strictly inside the filter-chains body, no
    // framing change. The atomic writer's invariant must accept this.
    let updated_listener_v2 = updated_listener.replace(
        "stat_prefix: sandbox_l1_passthrough",
        "stat_prefix: sandbox_l1_passthrough_v2",
    );
    assert_ne!(
        updated_listener, updated_listener_v2,
        "second-rewrite content must differ from first-rewrite content \
         (stat_prefix substitution should have changed the body)"
    );
    writer
        .write(&updated_listener_v2)
        .expect("second atomic listener rewrite (stat_prefix-only) should succeed");

    // Wait up to 15s for Envoy to resolve the second rewrite.
    let mut post2_updates = pre2_updates;
    let mut post2_rejections = pre2_rejections;
    for _ in 0..60 {
        post2_updates = lds_update_success(&gw_container);
        post2_rejections = lds_update_rejected(&gw_container);
        if post2_rejections > pre2_rejections || post2_updates > pre2_updates {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert!(
        post2_rejections == pre2_rejections,
        "Envoy rejected the second listener rewrite ({pre2_rejections} -> \
         {post2_rejections}). Stat-prefix-only diff should be a clean LDS update — \
         a rejection indicates the framing changed unexpectedly or the YAML is \
         malformed."
    );
    assert!(
        post2_updates > pre2_updates,
        "Envoy LDS update_success should have advanced from {pre2_updates} after \
         the second atomic rewrite; got {post2_updates}. Either the MovedTo event \
         did not reach Envoy or the writer reported success without renaming."
    );

    // The mutation should advance `listener_modified` (warm-restart witness)
    // and leave `listener_in_place_updated` unchanged (in-place witness pinned
    // at 0 — the Path B contract for #51). `total_listeners_draining`
    // advances because the previous generation is now draining (Envoy's
    // default drain timer is 600s, so we do NOT wait for it to return to
    // 0 — its mere advancement is the witness).
    let post2_modified = listener_modified(&gw_container);
    let post2_in_place = listener_in_place_updated(&gw_container);
    let post2_draining = total_listeners_draining(&gw_container);
    let post2_active = total_listeners_active(&gw_container);
    assert!(
        post2_modified > pre2_modified,
        "listener_manager.listener_modified did not advance ({pre2_modified} -> \
         {post2_modified}) across a populated->populated filter-chains rewrite. \
         Envoy is no longer treating this rewrite as a warm-restart — either it \
         switched to the in-place path (check listener_in_place_updated and update \
         this test + the design comment in policy.rs), or the rewrite was processed \
         as a fresh add (check listener_added). Behavior change vs. the runtime \
         contract documented on `PolicyCompiler::compile_envoy_listener`."
    );
    assert_eq!(
        post2_in_place, pre2_in_place,
        "listener_manager.listener_in_place_updated advanced ({pre2_in_place} -> \
         {post2_in_place}) across a populated->populated filter-chains rewrite. \
         Envoy has activated its in-place update path — connection preservation \
         across edits may now be possible. Update both this assertion and the \
         design comment on `PolicyCompiler::compile_envoy_listener` (it currently \
         documents warm-restart-with-drain as the runtime path)."
    );
    assert!(
        post2_draining > pre2_draining,
        "listener_manager.total_listeners_draining did not advance ({pre2_draining} \
         -> {post2_draining}) across the second rewrite. The warm-restart-with-drain \
         contract requires the previous listener generation to enter drain when the \
         new generation warms in; not seeing this means Envoy either took the \
         in-place path (check listener_in_place_updated) or the new generation \
         failed to install (check listener_modified and listener_added)."
    );
    assert!(
        post2_active >= 1,
        "listener_manager.total_listeners_active = {post2_active} after second \
         rewrite; expected >= 1. The new (warm-restart) generation must be active \
         before the old one drains — a value of 0 here indicates the new listener \
         failed to come up."
    );

    // Listener identity is preserved across the second rewrite — the
    // `policy_listener` resource is still served from the dynamic-listeners
    // section. This is the load-bearing contract for /config_dump-driven
    // observability and the apply-policy-through-real-gateway test.
    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "curl",
            "-sf",
            "http://127.0.0.1:9901/config_dump?resource=dynamic_listeners",
        ])
        .output()
        .expect("docker exec curl config_dump (post-second-rewrite) should succeed");
    let dynamic_listeners_v2 = String::from_utf8_lossy(&output.stdout);
    assert!(
        dynamic_listeners_v2.contains("policy_listener"),
        "policy_listener must still be present in dynamic_listeners after the \
         stat-prefix-only second rewrite — listener identity must survive warm-\
         restart-with-drain:\n{dynamic_listeners_v2}"
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

/// End-to-end check that [`wait_for_lds_ack`] correctly waits for a
/// real Envoy to ack an atomic listener rewrite (#38).
///
/// Background. Before this helper landed, the DNS propagation loop
/// flipped `propagated=true` the moment the listener-file rename
/// returned, leaving a 100–300 ms window where Envoy was still
/// serving the prior generation (or briefly draining). The cargo
/// and github-repo E2Es repro'd this as TCP-RST/Connection-refused
/// failures within ~50 ms of `propagated=true`. The helper closes
/// the race by polling Envoy admin `/stats` until
/// `(lds.update_success + lds.update_rejected) >= pre_attempt + 1`
/// — i.e. Envoy has resolved the rewrite, accept or reject. This
/// test runs the helper against a real Envoy to confirm:
///
///   1. The pre-rewrite snapshot of `lds.update_attempt` returns
///      from the `DockerExecLdsProbe` against a live admin port.
///   2. `wait_for_lds_ack` returns `Accepted` after a benign
///      filter-chain rewrite (the same one the LDS listener
///      integration test uses), within the deadline.
///   3. By the time the helper returns `Accepted`, Envoy reports
///      `update_success` strictly greater than the pre-rewrite
///      snapshot — i.e. the `Accepted` outcome is not a false
///      positive.
///
/// This is the production-side counterpart to the hermetic unit
/// tests in `sandbox-core::lds_ack::tests`: those drive the helper
/// with a fake probe to exercise the success / reject / timeout
/// state machine; this test confirms the production probe and the
/// production Envoy actually agree on the wire.
#[test]
fn integration_wait_for_lds_ack_observes_real_envoy_ack() {
    // 10.209.8.0/24 — distinct from the other gateway tests.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 8, 0), 24).unwrap();
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
    // Pre-policy: bootstrap listener is rejected, no active listener
    // (#52). The wait_for_lds_ack helper exercises the LDS path
    // independent of `gateway_status`, so `Starting` is the right
    // pre-condition here — we are about to provoke a successful
    // rewrite that flips `total_listeners_active` to 1 below.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Starting,
        "gateway should be Starting (no active listener pre-rewrite) before exercising LDS ack"
    );

    // We need a Tokio runtime because `wait_for_lds_ack` is async
    // and `DockerExecLdsProbe::fetch_counters` uses `tokio::process`.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime should build");

    // Independent helper to read `lds.update_success` synchronously
    // for the post-condition assertion below — keeps the test free
    // of an additional async hop just for the witness check.
    fn lds_update_success(container: &str) -> u64 {
        let url = "http://127.0.0.1:9901/stats?\
                   filter=^listener_manager\\.lds\\.update_success$&format=text";
        let out = Command::new("docker")
            .args(["exec", container, "curl", "-sf", url])
            .output()
            .expect("docker exec curl /stats should succeed");
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some((_, v)) = line.split_once(':') {
                if let Ok(n) = v.trim().parse::<u64>() {
                    return n;
                }
            }
        }
        0
    }

    // 1. Snapshot pre-rewrite counters via the production probe.
    //    This is exactly the call sandboxd's DNS loop makes before
    //    rewriting the listener — if it can't reach Envoy admin
    //    here, the daemon side will fail the same way.
    let probe = DockerExecLdsProbe::new(&session_id);
    let pre = rt
        .block_on(probe.fetch_counters())
        .expect("DockerExecLdsProbe must reach Envoy admin in a healthy gateway");
    let initial_success = lds_update_success(&gw_container);

    // 2. Atomic listener rewrite — same shape as the LDS listener
    //    integration test: switch the deny-all bootstrap body
    //    (`filter_chains: []`) to a single L1 passthrough chain
    //    routing to the pre-defined `original_dst` cluster. Envoy
    //    must accept this; rejection here would mean the test
    //    fixture itself is broken (assertion further down catches
    //    that).
    use sandbox_core::policy::{FILTER_CHAINS_BEGIN_MARKER, FILTER_CHAINS_END_MARKER};
    let mut updated_listener = PolicyCompiler::envoy_deny_all_listener();
    let old_body =
        format!("{FILTER_CHAINS_BEGIN_MARKER}\n    filter_chains: []\n{FILTER_CHAINS_END_MARKER}");
    let new_body = format!(
        "{FILTER_CHAINS_BEGIN_MARKER}\n    default_filter_chain:\n      filters:\n        - name: envoy.filters.network.tcp_proxy\n          typed_config:\n            \"@type\": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy\n            stat_prefix: sandbox_l1_passthrough\n            cluster: original_dst\n{FILTER_CHAINS_END_MARKER}"
    );
    assert!(
        updated_listener.contains(&old_body),
        "initial deny-all listener must contain the framed `filter_chains: []` body so \
         the test can swap it; the fixture is stale otherwise"
    );
    updated_listener = updated_listener.replace(&old_body, &new_body);

    let host_path = session_listener_host_path(&session_id);
    AtomicListenerWriter::new(&host_path)
        .write(&updated_listener)
        .expect("atomic listener rewrite should succeed");

    // 3. The real ack-wait. 5s deadline matches sandboxd's runtime
    //    setting; 100ms poll matches the daemon's poll_interval.
    //    On CI the inotify event typically lands in <250 ms; if the
    //    helper times out here it means either Envoy actually never
    //    saw the rewrite (possible bind-mount or watcher bug) or
    //    the 5s deadline is too aggressive for this host.
    let outcome = rt.block_on(wait_for_lds_ack(
        &probe,
        pre,
        Duration::from_secs(5),
        Duration::from_millis(100),
    ));

    // 4. Assertions. We pin `Accepted` (not just "anything but
    //    TimedOut") because a `Rejected` here would mean the
    //    test-crafted listener body is malformed and the production
    //    daemon's would-be propagation flip is being correctly
    //    suppressed — a bug in the test fixture, not a regression
    //    in the helper. We also pin that `update_success` actually
    //    advanced past `initial_success`, ruling out the
    //    "helper returned Accepted but Envoy never updated" failure
    //    mode (would be a bug in the helper's edge-attribution).
    assert_eq!(
        outcome,
        LdsAckOutcome::Accepted,
        "wait_for_lds_ack must observe a real Envoy ack within the deadline; \
         got {outcome:?}. If TimedOut, Envoy never re-read the listener — \
         check the LDS filesystem watcher and the bind-mount path. If Rejected, \
         the test-crafted listener body is malformed — Envoy refused it; \
         inspect the Envoy log inside container {gw_container} for the \
         validation error."
    );
    let final_success = lds_update_success(&gw_container);
    assert!(
        final_success > initial_success,
        "lds.update_success must have incremented from {initial_success} after the \
         rewrite was acked; got {final_success}. The helper returned Accepted but \
         Envoy disagrees — the edge-attribution logic in `wait_for_lds_ack` is \
         miscounting."
    );

    // ---------- Clean up ----------
    gw_mgr.stop_gateway(&session_id).unwrap();
    net_mgr.delete_network(&session_id).unwrap();
}

/// The gateway container must expose a per-session events bind mount
/// into which the three JSONL producers (Envoy access log, CoreDNS
/// plugin, mitmproxy addon) append structured event lines that
/// sandboxd tails via `inotify`.
///
/// This test asserts three lifecycle properties of that bind:
///   1. `create_gateway` creates the host-side events dir.
///   2. The mount is wired end-to-end — a file written on the host
///      inside the events dir is visible inside the container at
///      [`EVENTS_DIR_IN_CONTAINER`], and a file written inside the
///      container at that path shows up on the host. Both directions
///      are asserted because bind-mount misconfigurations often only
///      fail one way (e.g. wrong `:ro` vs `:rw` spec, or the mount
///      target getting shadowed by the `/var/log` tmpfs).
///   3. `stop_gateway` removes the host events dir.
#[test]
fn integration_gateway_container_has_events_bind_mount() {
    // Use 10.209.6.0/24 to avoid collisions with the other gateway
    // tests in this file.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 6, 0), 24).unwrap();
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
    let events_host_dir = session_events_host_dir(&session_id);

    // ---------- 1. Host-side events dir exists post-create ----------
    assert!(
        events_host_dir.is_dir(),
        "create_gateway must have created the events host dir at {}",
        events_host_dir.display()
    );

    // ---------- 2a. Host → container propagation ----------
    // Write a file on the host inside the events dir and assert the
    // container sees it at EVENTS_DIR_IN_CONTAINER.
    let host_probe = events_host_dir.join("host_probe.jsonl");
    std::fs::write(&host_probe, b"{\"from\":\"host\"}\n")
        .expect("writing host-side probe file should succeed");

    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "cat",
            &format!("{EVENTS_DIR_IN_CONTAINER}/host_probe.jsonl"),
        ])
        .output()
        .expect("docker exec cat host_probe should succeed");
    assert!(
        output.status.success(),
        "host_probe.jsonl written to {} must be visible inside container at {EVENTS_DIR_IN_CONTAINER}; \
         the bind mount is broken or the /var/log tmpfs is shadowing it. \
         docker exec stderr: {}",
        events_host_dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "{\"from\":\"host\"}",
        "host → container content must round-trip through the bind mount"
    );

    // ---------- 2b. Container → host propagation ----------
    // Write a file inside the container at EVENTS_DIR_IN_CONTAINER and
    // assert it appears on the host under the events dir. Producers in
    // later phases (Envoy, CoreDNS plugin, mitmproxy addon) will write
    // here, so this direction is the one sandboxd's ingest layer
    // depends on.
    let output = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "sh",
            "-c",
            &format!(
                "printf '{{\"from\":\"container\"}}\\n' > {EVENTS_DIR_IN_CONTAINER}/container_probe.jsonl"
            ),
        ])
        .output()
        .expect("docker exec write container_probe should succeed");
    assert!(
        output.status.success(),
        "writing inside container at {EVENTS_DIR_IN_CONTAINER} must succeed \
         (mount must be :rw, not :ro). stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let host_view = events_host_dir.join("container_probe.jsonl");
    let contents =
        std::fs::read_to_string(&host_view).expect("container_probe.jsonl must appear on host");
    assert_eq!(
        contents.trim(),
        "{\"from\":\"container\"}",
        "container → host content must round-trip through the bind mount"
    );

    // ---------- 3. Post-stop host dir cleanup ----------
    gw_mgr.stop_gateway(&session_id).unwrap();

    assert!(
        !events_host_dir.exists(),
        "stop_gateway must remove the events host dir at {}",
        events_host_dir.display()
    );

    // ---------- Clean up the network ----------
    net_mgr.delete_network(&session_id).unwrap();
}

/// Verify the `SANDBOX_KEEP_SESSION_EVENTS` debug flag preserves the
/// per-session events host directory across `stop_gateway`. Required for
/// post-mortem debugging of E2E failures: the JSONL files (`mitmproxy.jsonl`,
/// `coredns.jsonl`, `envoy.jsonl`, plus the deny-logger output) are the
/// proof of which layer denied a connection. Without this flag the
/// session-removal cleanup wipes them before a human can look.
///
/// This test mutates a process env var. It is safe under nextest's
/// default per-test-process isolation, but the test snapshots and
/// restores the var to be robust against future runner changes that
/// might serialise tests within a process.
#[test]
fn integration_gateway_keep_session_events_preserves_events_dir() {
    // Use 10.209.7.0/24 to avoid collisions with the other gateway
    // tests in this file.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 7, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    let network_info = net_mgr.create_network(&session_id).unwrap();

    let create_result = gw_mgr.create_gateway(&session_id, &network_info, None, None);
    if let Err(ref e) = create_result {
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("create_gateway failed: {e}");
    }

    let events_host_dir = session_events_host_dir(&session_id);
    assert!(
        events_host_dir.is_dir(),
        "create_gateway must have created the events host dir at {}",
        events_host_dir.display()
    );

    // Drop a marker file so a successful preserve-on-stop is observable
    // beyond just "the directory exists" — the actual JSONL contents are
    // what a human looks at during debugging.
    let marker = events_host_dir.join("debug_marker.jsonl");
    std::fs::write(&marker, b"{\"from\":\"keep-session-events test\"}\n")
        .expect("writing marker file should succeed");

    // Snapshot and set the flag, run stop_gateway, restore. The unsafe
    // block matches the env-mutation pattern used in
    // `events_host_root` / `listener_host_root` unit tests.
    let prior = std::env::var("SANDBOX_KEEP_SESSION_EVENTS").ok();
    // SAFETY: env mutation is process-global; nextest gives each test
    // its own process under the integration profile, so the unsafe
    // block is sound.
    unsafe {
        std::env::set_var("SANDBOX_KEEP_SESSION_EVENTS", "1");
    }

    let stop_result = gw_mgr.stop_gateway(&session_id);

    unsafe {
        match prior {
            Some(v) => std::env::set_var("SANDBOX_KEEP_SESSION_EVENTS", v),
            None => std::env::remove_var("SANDBOX_KEEP_SESSION_EVENTS"),
        }
    }

    stop_result.expect("stop_gateway must succeed even with KEEP_SESSION_EVENTS");

    // The flag's contract: the events host dir AND its contents survive.
    assert!(
        events_host_dir.exists(),
        "with SANDBOX_KEEP_SESSION_EVENTS set, stop_gateway must NOT \
         remove the events host dir at {}",
        events_host_dir.display()
    );
    let preserved = std::fs::read_to_string(&marker)
        .expect("marker file must survive stop_gateway under the keep flag");
    assert_eq!(
        preserved.trim(),
        "{\"from\":\"keep-session-events test\"}",
        "preserved marker contents must round-trip unchanged"
    );

    // Manual cleanup: the test caused the leak deliberately, so it
    // owns the cleanup. (The "leaked" dir lives on tmpfs and is at
    // most a few KB; we still tidy up so successive test runs don't
    // accumulate.)
    let _ = std::fs::remove_dir_all(&events_host_dir);
    net_mgr.delete_network(&session_id).unwrap();
}

/// End-to-end policy distribution through a real gateway container.
///
/// Compiles a non-trivial policy (CIDR-backed L1 rule + L2 domain rule +
/// L3 domain rule) and pushes it through `PolicyDistributor::distribute`
/// against a live gateway. Asserts the four production-side acceptance
/// signals:
///   1. `distribute()` returns `Ok(())` end-to-end (no
///      silent-failure-swallowing inside any of the five steps).
///   2. nftables: `nft list ruleset` lists both `sandbox_dnat` and
///      `sandbox_policy` after distribute, and `nft -c` accepts the
///      live ruleset (the in-container parser is the authoritative
///      arbiter; if `policy_distributor.inject_nftables_ruleset_public`
///      had silently dropped a syntax error this catches it).
///   3. Envoy: `listener_manager.lds.update_success` increments and
///      `listener_manager.lds.update_rejected` does not change — the
///      newly-served listener was accepted.
///   4. CoreDNS: `/health` still responds 200, the policy file landed
///      with the expected non-empty body, and the daemon picked it up
///      (post-reload, the configured allowed domain appears in the
///      `/etc/coredns/policy.conf` file inside the container — if the
///      `write_file_to_container` step had silently failed the
///      distributor would have returned Err, but we additionally pin
///      the on-disk shape so a "wrote empty file" regression surfaces).
///
/// Catches: nft syntax bugs in `compile_nftables`, Envoy schema drift
/// in `compile_envoy_listener`, mitmproxy/CoreDNS file-write addon
/// drift, and silent-failure swallowing inside any distribute step.
/// Complements the validator-only tests in `validators.rs`: those
/// validate the static compiler output against the validator CLIs in
/// isolation; this one runs the full inject path and observes the
/// running daemons' reactions.
#[test]
fn integration_apply_policy_through_real_gateway() {
    // Distinct subnet to avoid collisions with the other gateway tests.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 7, 0), 24).unwrap();
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

    // Sanity: gateway processes must be up *before* distribute,
    // otherwise an unrelated startup flake would masquerade as a
    // distribute failure. Pre-policy the verdict is `Starting`
    // (healthcheck.sh OK, no active listener — #52); the distribute
    // call below flips it to `Healthy` by installing a populated
    // listener.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Starting,
        "gateway should be Starting (no active listener pre-distribute) before policy distribution"
    );

    // Helper: read an Envoy stat counter via /stats?filter=...&format=text.
    fn envoy_stat(container: &str, stat: &str) -> u64 {
        let url = format!("http://127.0.0.1:9901/stats?filter={stat}$&format=text");
        let out = Command::new("docker")
            .args(["exec", container, "curl", "-sf", &url])
            .output()
            .expect("curl envoy /stats should succeed");
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some((_, v)) = line.split_once(':') {
                if let Ok(n) = v.trim().parse::<u64>() {
                    return n;
                }
            }
        }
        0
    }

    // Snapshot Envoy LDS counters so we can detect the listener reload
    // triggered by PolicyDistributor's atomic listener rewrite.
    let initial_updates = envoy_stat(&gw_container, "listener_manager.lds.update_success");
    let initial_rejections = envoy_stat(&gw_container, "listener_manager.lds.update_rejected");

    // Build a non-trivial policy that exercises every distribute step:
    //   - L1 CIDR rule -> populates nftables `policy_allow_tcp` set
    //     (so `compiled.nftables_rules` is non-empty and step 3
    //     actually injects)
    //   - L2 domain rule -> populates CoreDNS allowed list
    //   - L3 domain rule -> emits Envoy listener filter chain (with
    //     empty DnsCache the filter chain is suppressed; we still
    //     route through `compile` so the listener differs from the
    //     deny-all initial)
    let policy = Policy {
        version: "2.0.0".to_string(),
        rules: vec![
            PolicyRule {
                host: Destination::Cidr("140.82.112.0/20".to_string()),
                level: AssuranceLevel::Transport,
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("L1 CIDR — populates policy_allow_tcp".to_string()),
            },
            PolicyRule {
                host: Destination::Domain("pinned.example.com".to_string()),
                level: AssuranceLevel::Tls,
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("L2 — appears in CoreDNS allowlist".to_string()),
            },
            PolicyRule {
                host: Destination::Domain("monitored.example.com".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![sandbox_core::HttpFilter {
                        method: sandbox_core::HttpMethod::Get,
                        path: "/api/*".to_string(),
                    }],
                },
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("L3 — emits mitmproxy rule".to_string()),
            },
        ],
    };

    let compiled = PolicyCompiler::compile(&policy, &network_info)
        .expect("non-trivial policy should compile cleanly");

    // Sanity: ensure compile produced non-empty nftables rules so that
    // the distribute path actually exercises nftables injection (a
    // domain-only policy would short-circuit step 3 to a flush-only
    // path, weakening the test's coverage).
    assert!(
        !compiled.nftables_rules.is_empty(),
        "fixture must yield non-empty nftables rules so distribute exercises injection; \
         got empty output for policy: {policy:?}"
    );

    // ---------- Distribute end-to-end ----------
    PolicyDistributor::distribute(&session_id, &compiled, &gw_mgr).unwrap_or_else(|e| {
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("PolicyDistributor::distribute failed end-to-end: {e}");
    });

    // ---------- 1. nftables acceptance ----------
    // The live ruleset must contain both managed tables. If
    // `inject_nftables_ruleset_public` had silently dropped a syntax
    // error, the ruleset would be in some half-state — we positively
    // pin both tables.
    let nft_listing = Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("nft list ruleset should succeed");
    assert!(
        nft_listing.status.success(),
        "nft list ruleset failed post-distribute: stderr={}",
        String::from_utf8_lossy(&nft_listing.stderr)
    );
    let live_ruleset = String::from_utf8_lossy(&nft_listing.stdout);
    assert!(
        live_ruleset.contains("table inet sandbox_dnat"),
        "live ruleset must include sandbox_dnat post-distribute; got:\n{live_ruleset}"
    );
    assert!(
        live_ruleset.contains("table inet sandbox_policy"),
        "live ruleset must include sandbox_policy post-distribute; got:\n{live_ruleset}"
    );

    // Re-validate the LIVE ruleset via `nft -c -f -`. The kernel parser
    // is the authoritative arbiter of nftables syntax; this rejects
    // any `ct original tcp dport`-class regression in `compile_nftables`
    // that the unit-test `.contains()` assertions would let through.
    let nft_check = {
        use std::io::Write;
        let mut child = Command::new("docker")
            .args(["exec", "-i", &gw_container, "nft", "-c", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("docker exec nft -c should spawn");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(compiled.nftables_rules.as_bytes())
            .expect("piping ruleset to nft -c should succeed");
        child.wait_with_output().expect("nft -c should complete")
    };
    assert!(
        nft_check.status.success(),
        "nft -c rejected the distributed ruleset (parser syntax check):\
         \n--- ruleset ---\n{}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        compiled.nftables_rules,
        String::from_utf8_lossy(&nft_check.stdout),
        String::from_utf8_lossy(&nft_check.stderr)
    );

    // ---------- 2. Envoy acceptance ----------
    // PolicyDistributor's step 5 atomically rewrites the listener file;
    // Envoy's filesystem LDS watcher must accept it (update_success
    // increments; update_rejected does not). Poll up to 15s — in
    // practice the watcher fires within ~250ms but CI is slow.
    let mut final_updates = initial_updates;
    let mut final_rejections = initial_rejections;
    for _ in 0..60 {
        final_updates = envoy_stat(&gw_container, "listener_manager.lds.update_success");
        final_rejections = envoy_stat(&gw_container, "listener_manager.lds.update_rejected");
        if final_rejections > initial_rejections || final_updates > initial_updates {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert!(
        final_rejections == initial_rejections,
        "Envoy rejected the distributed listener config ({initial_rejections} -> \
         {final_rejections}). The MovedTo event reached Envoy but the listener \
         payload was refused — check /config_dump and the Envoy log for the \
         validation error."
    );
    assert!(
        final_updates > initial_updates,
        "Envoy LDS update_success did not increment from {initial_updates} after \
         distribute — the atomic listener rewrite did not produce a MovedTo \
         event Envoy could see."
    );

    // ---------- 3. CoreDNS acceptance ----------
    // The /health endpoint must still respond 200 (the daemon stayed
    // up). The policy file must have landed inside the container with
    // the expected allowed domains — if `write_file_to_container` had
    // silently no-op'd, distribute would have failed, but we pin the
    // on-disk shape so a "wrote empty file" regression surfaces too.
    let coredns_health = Command::new("docker")
        .args([
            "exec",
            &gw_container,
            "curl",
            "-sf",
            "http://127.0.0.1:8180/health",
        ])
        .output()
        .expect("curl coredns /health should succeed");
    assert!(
        coredns_health.status.success(),
        "CoreDNS /health failed post-distribute: stderr={}",
        String::from_utf8_lossy(&coredns_health.stderr)
    );

    let coredns_policy = Command::new("docker")
        .args(["exec", &gw_container, "cat", "/etc/coredns/policy.conf"])
        .output()
        .expect("cat coredns policy.conf should succeed");
    assert!(
        coredns_policy.status.success(),
        "reading /etc/coredns/policy.conf failed post-distribute: stderr={}",
        String::from_utf8_lossy(&coredns_policy.stderr)
    );
    let coredns_text = String::from_utf8_lossy(&coredns_policy.stdout);
    assert!(
        coredns_text.contains("pinned.example.com"),
        "CoreDNS policy file must list the L2 allowed domain post-distribute; got:\n{coredns_text}"
    );
    assert!(
        coredns_text.contains("monitored.example.com"),
        "CoreDNS policy file must list the L3 allowed domain post-distribute; got:\n{coredns_text}"
    );

    // ---------- 4. Gateway remains healthy ----------
    // Composite signal: Envoy + CoreDNS + mitmproxy + deny-logger all
    // still up. Catches the case where one component crashed mid-
    // distribute (e.g. Envoy panicked on a malformed listener) but
    // distribute happened to return Ok because the rejection happened
    // in the daemon, not in the Rust-side write.
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Healthy,
        "gateway must remain healthy after distribute"
    );

    // ---------- Clean up ----------
    gw_mgr.stop_gateway(&session_id).unwrap();
    net_mgr.delete_network(&session_id).unwrap();
}

/// Pins the fatal-create contract (todo #16, todo #46) end-to-end.
///
/// `fail_explicit_policy_apply_marks_session_error_and_returns_5xx`
/// (in `sandboxd/src/main.rs` tests) is the hermetic unit test for the
/// daemon-side handler: it injects a synthetic
/// `SandboxError::Gateway(...)` into `fail_explicit_policy_apply` and
/// pins the 500 + `SessionState::Error` contract. That test covers the
/// state-transition + HTTP-mapping side of the failure but mocks out
/// the trigger — it does not exercise a real
/// `PolicyDistributor::distribute` failure.
///
/// This test fills the remaining gap. It builds a syntactically-valid
/// policy whose compile output the live nft kernel parser rejects,
/// runs `PolicyDistributor::distribute` against a real gateway
/// container, and asserts:
///
///   1. `distribute()` returns `Err(SandboxError::Gateway(...))`.
///      Variant — not message — because the daemon's
///      `error_response()` mapping keys on the variant; the
///      `Gateway` arm is the one that produces the 500 the unit
///      test pins.
///   2. The earlier distribute steps (CoreDNS + mitmproxy) reach the
///      container before the nftables step fails, so we know the
///      failure is genuinely from the kernel parser and not an
///      unrelated step-1/step-2 wobble.
///
/// **Failure shape.** Two CIDR rules at the same `(port, protocol)`
/// whose prefixes overlap: `10.0.0.0/8` and `10.1.0.0/16` both fall
/// into the IPv4 space `10.0.0.0/8`. Both pass `validate_cidr`
/// (parseable IPv4, prefix <= 32) and both are distinct
/// `(host, port)` keys (different `Destination::Cidr` strings), so
/// `PolicyCompiler::validate` accepts the policy. Compilation
/// emits both as elements of the `policy_allow_tcp` set with
/// `flags interval`, which is precisely the configuration the
/// pinned nftables 1.0.6 (gateway image) rejects with
/// `Error: Could not process rule: File exists`. Verified via
/// `nft -c -f -` on the gateway image during the test design pass —
/// see commit message for the captured stderr.
///
/// **Why this matters.** The unit test pins the helper's behaviour
/// when an error is handed in, but a regression that broke the trigger
/// path (e.g. a reordering that swallowed the distribute Err inside
/// `apply_policy`, or a mapping change that demoted `Gateway` to a
/// non-fatal variant) would let the unit test stay green while the
/// real failure mode silently regressed. This test pins the trigger
/// — the bridge between "distribute rejected the policy" and "the
/// caller observes an Err the daemon can map to a 5xx".
///
/// Uses 10.209.9.0/24 to avoid collisions with the other
/// `integration_*` gateway tests (8.0/24 is taken by
/// `integration_gateway_status_witnesses_active_listener`).
#[test]
fn integration_distribute_returns_err_when_gateway_rejects_policy() {
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 9, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    let network_info = net_mgr.create_network(&session_id).unwrap();

    let create_result = gw_mgr.create_gateway(&session_id, &network_info, None, None);
    if let Err(ref e) = create_result {
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("create_gateway failed: {e}");
    }

    // Pre-flight: gateway must be at least at the post-create
    // baseline. If create_gateway returned Ok but the container is
    // already wedged, an unrelated startup flake would masquerade as
    // a distribute rejection. Pre-policy the listener-aware verdict
    // is `Starting` (#52); the test does not depend on a populated
    // listener — distribute fails on the nftables step (step 3),
    // before it ever rewrites the listener file.
    let pre_status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        pre_status,
        GatewayStatus::Starting,
        "gateway must be Starting after create_gateway (no policy applied yet); \
         got {pre_status:?}. An unhealthy gateway here would make a distribute \
         failure ambiguous."
    );

    // Two overlapping `policy_allow_tcp` set elements at the same
    // (port, protocol) — see test docstring for why this passes
    // `compile` and is rejected by the live nft parser.
    let policy = Policy {
        version: "2.0.0".to_string(),
        rules: vec![
            PolicyRule {
                host: Destination::Cidr("10.0.0.0/8".to_string()),
                level: AssuranceLevel::Transport,
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("supernet — overlaps with the /16 below".to_string()),
            },
            PolicyRule {
                host: Destination::Cidr("10.1.0.0/16".to_string()),
                level: AssuranceLevel::Transport,
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("subnet of 10.0.0.0/8 — triggers nft interval overlap".to_string()),
            },
        ],
    };

    // Sanity: compile must succeed — the failure we are pinning is
    // distribute-side, not validate-side. If a future
    // `PolicyCompiler::validate` change adds a CIDR-overlap pre-check,
    // that would short-circuit the production path before distribute
    // is called and this test would lose its purpose.
    let compiled = PolicyCompiler::compile(&policy, &network_info)
        .expect("overlapping-CIDR policy must still compile (rejection is gateway-side)");
    assert!(
        compiled.nftables_rules.contains("10.0.0.0/8 . 443"),
        "compile output must carry the supernet element so the kernel sees the overlap; \
         got:\n{}",
        compiled.nftables_rules
    );
    assert!(
        compiled.nftables_rules.contains("10.1.0.0/16 . 443"),
        "compile output must carry the subnet element so the kernel sees the overlap; \
         got:\n{}",
        compiled.nftables_rules
    );

    // ---------- Distribute: must fail at the nftables step ----------
    let result = PolicyDistributor::distribute(&session_id, &compiled, &gw_mgr);

    // Tear down before any further assertion so a panic doesn't leak
    // the gateway container + network on the failure path.
    let _ = gw_mgr.stop_gateway(&session_id);
    let _ = net_mgr.delete_network(&session_id);

    // Contract 1: distribute returns Err. Without the gateway-side
    // rejection wired through, `inject_nftables_ruleset_public` would
    // have to silently swallow the kernel's "File exists" error — that
    // would be the regression this test catches.
    let err = result.expect_err(
        "PolicyDistributor::distribute must return Err when nft rejects the ruleset \
         (overlapping CIDR intervals); production code's apply_policy depends on this Err \
         to trigger fail_explicit_policy_apply (todo #16)",
    );

    // Contract 2: variant is `SandboxError::Gateway`. We pin on the
    // variant rather than the message because:
    //   - `error_response` maps `Gateway` to 500; a regression that
    //     remapped distribute's error to e.g. `Internal` would leave
    //     the unit test green but break the documented HTTP contract.
    //   - The kernel error string (`File exists` vs `interval
    //     overlaps` vs a future nft message) is upstream and likely to
    //     drift; the variant is our contract.
    assert!(
        matches!(err, sandbox_core::SandboxError::Gateway(_)),
        "distribute must surface nft rejection as SandboxError::Gateway so error_response \
         maps it to 500 (the variant the todo #16 unit test pins); got: {err:?}"
    );
}

/// Pins the listener-aware health-check contract (#52).
///
/// Before this fix, `gateway_status()` reported `Healthy` whenever
/// `/healthcheck.sh` succeeded — i.e. as long as Envoy admin /ready,
/// CoreDNS /health, mitmproxy and the deny-logger were all up. That
/// missed the failure mode where Envoy is listening on the admin port
/// but has zero data-plane listeners (the bootstrap listener with
/// empty `filter_chains` is rejected, so until a policy lands the
/// container *cannot* serve client traffic). To callers driving a
/// session through readiness gates, `Healthy` was a lie.
///
/// Two-stage probe (`gateway.rs`):
///   1. composite `/healthcheck.sh` — process liveness
///   2. `listener_manager.total_listeners_active` via Envoy admin
///      `/stats?filter=^listener_manager\.total_listeners_active$&format=text`
///
/// Verdict matrix:
///   - stage 1 fails              → `Unhealthy`
///   - stage 1 OK, count == 0     → `Starting`   (boot window)
///   - stage 1 OK, count >= 1     → `Healthy`
///   - stage 1 OK, stage 2 errors → `Healthy`    (fall back; admin
///     stats reachability isn't strictly required for serving)
///
/// This test pins the count==0 → `Starting` and count>=1 → `Healthy`
/// arms end-to-end against a real gateway container. The
/// `/healthcheck.sh fails` arm is exercised by the `Unhealthy` arm
/// in `integration_gateway_lifecycle` (kill-the-container path).
#[test]
fn integration_gateway_status_witnesses_active_listener() {
    // Distinct subnet to avoid collisions with the other gateway tests.
    let net_mgr = NetworkManager::new(Ipv4Addr::new(10, 209, 8, 0), 24).unwrap();
    let gw_mgr = GatewayManager::new();
    let session_id = SessionId::generate();

    let network_info = net_mgr.create_network(&session_id).unwrap();

    let create_result = gw_mgr.create_gateway(&session_id, &network_info, None, None);
    if let Err(ref e) = create_result {
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("create_gateway failed: {e}");
    }

    // ---------- Stage A: pre-policy ----------
    // create_gateway lays down the bootstrap listener YAML with empty
    // `filter_chains`, which Envoy rejects. The composite healthcheck
    // still succeeds (Envoy /ready returns 200, CoreDNS up, mitmproxy
    // up, deny-logger up) — so the OLD verdict was `Healthy`. The
    // listener-aware verdict is `Starting`: count is observably 0.
    let count = gw_mgr.gateway_listener_active_count(&session_id);
    assert_eq!(
        count,
        Some(0),
        "pre-policy: total_listeners_active must be 0 (bootstrap listener rejected); \
         got {count:?}. If this is None, Envoy admin /stats wasn't reachable — \
         which makes the listener-aware probe fall back to Healthy."
    );
    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Starting,
        "pre-policy: gateway_status must be Starting (healthcheck.sh OK, \
         active-listener count 0); got {status:?}"
    );

    // ---------- Stage B: apply L1 CIDR policy ----------
    // The simplest policy that yields a populated listener: an L1 CIDR
    // rule produces nftables `policy_allow_tcp` and an Envoy listener
    // with a real filter chain. After distribute, Envoy's LDS accepts
    // the rewrite and `total_listeners_active` flips to 1.
    let policy = Policy {
        version: "2.0.0".to_string(),
        rules: vec![PolicyRule {
            host: Destination::Cidr("140.82.112.0/20".to_string()),
            level: AssuranceLevel::Transport,
            port: 443,
            protocol: Protocol::Tcp,
            reason: Some("L1 CIDR — minimum to populate the listener".to_string()),
        }],
    };
    let compiled = PolicyCompiler::compile(&policy, &network_info)
        .expect("L1 CIDR policy should compile cleanly");

    PolicyDistributor::distribute(&session_id, &compiled, &gw_mgr).unwrap_or_else(|e| {
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("PolicyDistributor::distribute failed end-to-end: {e}");
    });

    // Poll up to 15s for active count to advance — in practice the
    // LDS update lands in <1s, but CI is slow.
    let mut final_count: Option<u64> = None;
    for _ in 0..60 {
        final_count = gw_mgr.gateway_listener_active_count(&session_id);
        if matches!(final_count, Some(n) if n >= 1) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        matches!(final_count, Some(n) if n >= 1),
        "post-distribute: total_listeners_active should advance to >= 1 within 15s; \
         got {final_count:?}. The LDS rewrite did not produce an accepted listener."
    );

    let status = gw_mgr.gateway_status(&session_id).unwrap();
    assert_eq!(
        status,
        GatewayStatus::Healthy,
        "post-distribute: gateway_status must flip to Healthy (active listener \
         witnessed); got {status:?}"
    );

    // ---------- Clean up ----------
    gw_mgr.stop_gateway(&session_id).unwrap();
    net_mgr.delete_network(&session_id).unwrap();
}
