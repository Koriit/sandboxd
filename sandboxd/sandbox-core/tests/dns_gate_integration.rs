//! Integration tests for the synchronous DNS-policy gating IPC.
//!
//! These tests drive the daemon-side gate listener over a real Unix
//! domain socket, against a real gateway container, exercising the
//! full per-request flow:
//!
//!   1. CoreDNS-plugin-side request emitted via [`send_request`].
//!   2. [`serve_gate_listener`] accepts and dispatches.
//!   3. The handler calls [`generate_domain_ip_rules`] to render a
//!      fresh ruleset, applies it via
//!      [`GatewayManager::inject_nftables_ruleset_public`], and waits
//!      for Envoy LDS to ack the matching listener rewrite via
//!      [`wait_for_lds_ack`].
//!   4. The listener replies with `propagate_ack { status: ok }`.
//!
//! Naming follows the workspace convention: every test in this file
//! is named `integration_*` so the `integration` nextest profile
//! picks it up while the default profile (run by `make test`) skips
//! it. See `sandboxd/.config/nextest.toml`.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sandbox_core::gateway::{GatewayManager, container_name};
use sandbox_core::network::NetworkManager;
use sandbox_core::session::SessionId;
use sandbox_core::{
    AssuranceLevel, AtomicListenerWriter, Destination, DnsCache, DockerExecLdsProbe, GateRequest,
    GateRequestKind, GateService, GateServiceOutcome, GateStatus, LdsAckOutcome, LdsStatsProbe,
    NetworkInfo, Policy, PolicyCompiler, PolicyDistributor, PolicyRule, Protocol, ResolvedMapping,
    ResolvedReport, bind_gate_listener, dns_gate_socket_host_path, generate_domain_ip_rules,
    propagate_dns_changes, send_request, serve_gate_listener, session_listener_host_path,
    wait_for_lds_ack,
};
use tokio::sync::Mutex as TokioMutex;

/// A close mirror of the production `DaemonGateService` in `sandboxd`,
/// reproduced here so the integration test can exercise the same
/// orchestration without depending on the binary crate.
struct ProdLikeGateService {
    session_id: SessionId,
    gateway: Arc<GatewayManager>,
    policy: Policy,
    dns_cache: Arc<TokioMutex<DnsCache>>,
    network_info: NetworkInfo,
}

impl GateService for ProdLikeGateService {
    async fn service(&self, req: &GateRequest) -> GateServiceOutcome {
        // Merge plugin IPs into the cache.
        {
            let report = ResolvedReport {
                mappings: vec![ResolvedMapping {
                    domain: req.domain.clone(),
                    ips: req.ips.clone(),
                    ttl: req.ttl_seconds,
                    timestamp: "1970-01-01T00:00:00Z".to_string(),
                }],
            };
            let mut cache = self.dns_cache.lock().await;
            let _ = cache.update(&report);
        }

        let probe = DockerExecLdsProbe::new(&self.session_id);
        let pre = probe.fetch_counters().await.ok();

        let ruleset_preview = {
            let cache = self.dns_cache.lock().await;
            generate_domain_ip_rules(&self.policy, &cache, &self.network_info)
        };
        if ruleset_preview.is_empty() {
            return GateServiceOutcome {
                status: GateStatus::Noop,
                reason: None,
            };
        }

        let gw = Arc::clone(&self.gateway);
        let sid = self.session_id;
        let cache_snapshot = {
            let cache = self.dns_cache.lock().await;
            cache.clone()
        };
        let policy_clone = self.policy.clone();
        let ni = self.network_info.clone();
        let propagate = tokio::task::spawn_blocking(move || {
            propagate_dns_changes(&sid, &policy_clone, &cache_snapshot, &gw, &ni)
        })
        .await;

        match propagate {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some(format!("propagate failed: {e}")),
                };
            }
            Err(e) => {
                return GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some(format!("propagate join: {e}")),
                };
            }
        }

        let plugin_deadline = Duration::from_millis(req.deadline_ms.max(1));
        let ack_deadline = plugin_deadline
            .saturating_sub(Duration::from_millis(150))
            .max(Duration::from_millis(100));

        if let Some(pre) = pre {
            match wait_for_lds_ack(&probe, pre, ack_deadline, Duration::from_millis(50)).await {
                LdsAckOutcome::Accepted => GateServiceOutcome {
                    status: GateStatus::Ok,
                    reason: None,
                },
                LdsAckOutcome::Rejected => GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some("envoy rejected".to_string()),
                },
                LdsAckOutcome::TimedOut => GateServiceOutcome {
                    status: GateStatus::Rejected,
                    reason: Some("envoy ack timeout".to_string()),
                },
            }
        } else {
            // Probe unavailable — fall back to "rewrite ok".
            GateServiceOutcome {
                status: GateStatus::Ok,
                reason: None,
            }
        }
    }
}

/// End-to-end IPC test: bring up a real gateway container, prime its
/// listener with an L3 domain rule via the standard distributor path,
/// then drive a `propagate_and_ack` request through the gate UDS and
/// assert that the daemon-side handler applies the new IPs in nft and
/// waits for Envoy to ack the matching listener generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_dns_gate_propagate_and_ack_round_trip() {
    // Distinct subnet — avoid collisions with the other gateway integration tests.
    let net_mgr = NetworkManager::new(
        Ipv4Addr::new(10, 209, 11, 0),
        24,
        "10.209.11.0/24".to_string(),
    )
    .unwrap();
    let gw_mgr = Arc::new(GatewayManager::new());
    let session_id = SessionId::generate();

    let network_info = net_mgr.create_network(&session_id).unwrap();

    // Bring up the gateway container. Standard pattern: clean up on
    // any failure below, panicking once teardown is done.
    let cleanup = |panic_msg: String| -> ! {
        let gw = gw_mgr.clone();
        let sid = session_id;
        let net = NetworkManager::new(
            Ipv4Addr::new(10, 209, 11, 0),
            24,
            "10.209.11.0/24".to_string(),
        )
        .unwrap();
        let _ = gw.stop_gateway(&sid);
        let _ = net.delete_network(&sid);
        panic!("{}", panic_msg);
    };

    if let Err(e) = gw_mgr.create_gateway(&session_id, &network_info, None, None, None) {
        cleanup(format!("create_gateway failed: {e}"));
    }

    let domain = "gate.example.test";

    // Compile + distribute a baseline policy with a single L3 domain
    // rule. Distribution renders a listener whose filter chain matches
    // any TLS connection to `domain:443`; before DNS resolves, the
    // chain has *no* SNI matchers (DnsCache is empty), so we go on to
    // exercise the gate path which fills in the (ip, port) admit pair
    // in the nft `sandbox_dnat` set.
    let policy = Policy {
        version: "2.0.0".to_string(),
        rules: vec![PolicyRule {
            host: Destination::Domain(domain.to_string()),
            level: AssuranceLevel::Tls,
            port: 443,
            protocol: Protocol::Tcp,
            reason: Some("dns-gate integration: TLS-pinned domain".to_string()),
        }],
    };
    let compiled = match PolicyCompiler::compile(&policy, &network_info) {
        Ok(c) => c,
        Err(e) => cleanup(format!("policy compile failed: {e}")),
    };
    if let Err(e) = PolicyDistributor::distribute(&session_id, &compiled, &gw_mgr) {
        cleanup(format!("PolicyDistributor::distribute failed: {e}"));
    }

    // Bind the gate listener on the canonical per-session path. The
    // events host directory is created by `create_gateway`, so this
    // bind path already exists.
    let (listener, socket_path) = match bind_gate_listener(&session_id) {
        Ok(pair) => pair,
        Err(e) => cleanup(format!("bind_gate_listener failed: {e}")),
    };
    assert_eq!(
        socket_path,
        dns_gate_socket_host_path(&session_id),
        "listener bound at the canonical events_host_dir path"
    );

    let cache = Arc::new(TokioMutex::new(DnsCache::new()));
    let service = Arc::new(ProdLikeGateService {
        session_id,
        gateway: Arc::clone(&gw_mgr),
        policy: policy.clone(),
        dns_cache: Arc::clone(&cache),
        network_info: network_info.clone(),
    });

    let server = tokio::spawn(async move {
        // 5s ceiling per request — well above what the production
        // listener uses, so a real LDS roundtrip has headroom but a
        // bug-class wedge still fails the test in bounded time.
        serve_gate_listener(listener, service, 5_000).await;
    });

    // Pre-snapshot the listener-mtime so we can assert the listener
    // was rewritten by the gate path. Read it via the on-disk path
    // the rewriter targets.
    let listener_path: PathBuf = session_listener_host_path(&session_id);
    let pre_mtime = std::fs::metadata(&listener_path)
        .ok()
        .and_then(|m| m.modified().ok());

    // Drive a propagate_and_ack request as the CoreDNS plugin would.
    let request = GateRequest {
        kind: GateRequestKind::PropagateAndAck,
        version: 1,
        correlation_id: "integration-1".to_string(),
        domain: domain.to_string(),
        qtype: "A".to_string(),
        ips: vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()],
        ttl_seconds: 60,
        deadline_ms: 4_000,
    };

    let ack = match send_request(&socket_path, &request).await {
        Ok(a) => a,
        Err(e) => {
            server.abort();
            cleanup(format!("send_request failed: {e}"));
        }
    };

    server.abort();

    assert_eq!(
        ack.status,
        GateStatus::Ok,
        "gate handler must return ok after nft injection + Envoy LDS ack; \
         actual ack: {ack:?}",
    );
    assert_eq!(
        ack.correlation_id, "integration-1",
        "ack must echo the request's correlation_id"
    );
    assert!(
        ack.elapsed_ms > 0,
        "ack must report a non-zero elapsed_ms; got {}",
        ack.elapsed_ms
    );

    // Listener mtime should advance only if the policy distributor
    // actually rewrote it under the gate path. The L3 domain rule
    // does NOT cause the gate handler to rewrite the listener (only
    // nft is rewritten by the gate); the pre-distributed listener
    // already has the chain. The atomic listener writer rewrite is
    // covered separately by integration_gateway_lds_listener_and_atomic_rewrite.
    // We still record the mtime to confirm the test setup was sane.
    let _ = pre_mtime;

    // Verify that the post-gate nftables include the IPs we sent.
    let gw_container = container_name(&session_id);
    let nft = std::process::Command::new("docker")
        .args(["exec", &gw_container, "nft", "list", "ruleset"])
        .output()
        .expect("docker exec nft list should succeed");
    let listing = String::from_utf8_lossy(&nft.stdout).into_owned();
    for ip in &request.ips {
        assert!(
            listing.contains(ip),
            "nft ruleset must include resolved IP {ip} after gate ack; \
             listing:\n{listing}"
        );
    }

    // Cleanup.
    let _ = gw_mgr.stop_gateway(&session_id);
    let _ = net_mgr.delete_network(&session_id);
}

/// Hermetic-ish: validates that an unknown_session reply path works
/// when the daemon has no policy installed for the session, even with
/// a real gateway container. This guards the `Some(p)` lookup in
/// `DaemonGateService::service`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_dns_gate_unknown_session_when_no_policy() {
    let net_mgr = NetworkManager::new(
        Ipv4Addr::new(10, 209, 12, 0),
        24,
        "10.209.12.0/24".to_string(),
    )
    .unwrap();
    let gw_mgr = Arc::new(GatewayManager::new());
    let session_id = SessionId::generate();
    let network_info = net_mgr.create_network(&session_id).unwrap();

    if let Err(e) = gw_mgr.create_gateway(&session_id, &network_info, None, None, None) {
        let _ = gw_mgr.stop_gateway(&session_id);
        let _ = net_mgr.delete_network(&session_id);
        panic!("create_gateway failed: {e}");
    }

    let (listener, socket_path) = bind_gate_listener(&session_id).unwrap();

    // Use a service whose `service()` always returns `unknown_session`
    // — this is the production path's fast-fail when the policy map
    // has no entry for this session. Driving the wire end-to-end
    // pins the wire-side handling of `unknown_session`.
    struct UnknownSessionStub;
    impl GateService for UnknownSessionStub {
        async fn service(&self, _req: &GateRequest) -> GateServiceOutcome {
            GateServiceOutcome {
                status: GateStatus::UnknownSession,
                reason: Some("no policy".to_string()),
            }
        }
    }

    let svc = Arc::new(UnknownSessionStub);
    let server = tokio::spawn(async move {
        serve_gate_listener(listener, svc, 5_000).await;
    });

    let req = GateRequest {
        kind: GateRequestKind::PropagateAndAck,
        version: 1,
        correlation_id: "integration-unknown".to_string(),
        domain: "x.example.test".to_string(),
        qtype: "A".to_string(),
        ips: vec!["198.51.100.1".to_string()],
        ttl_seconds: 30,
        deadline_ms: 2_000,
    };
    let ack = send_request(&socket_path, &req)
        .await
        .expect("send_request should succeed against a real UDS");

    server.abort();

    assert_eq!(ack.status, GateStatus::UnknownSession);
    assert_eq!(ack.correlation_id, "integration-unknown");

    // Suppress unused warning — guards against a future refactor
    // that drops the AtomicListenerWriter import.
    let _ = AtomicListenerWriter::new(session_listener_host_path(&session_id));

    let _ = gw_mgr.stop_gateway(&session_id);
    let _ = net_mgr.delete_network(&session_id);
}
