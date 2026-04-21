//! External-validator harness for the policy compiler's outputs.
//!
//! These tests run the compiler against a representative v2 policy and
//! feed its outputs through the real tools that consume them in
//! production:
//!
//! - `nft -c -f -` (with `CAP_NET_ADMIN` inside the gateway container)
//!   syntax-checks the compiler's nftables ruleset plus the
//!   `generate_domain_ip_rules` DNS-join output. Catches concat-set
//!   shape regressions the Rust string assertions would miss.
//! - `envoy --mode validate` loads the compiler's bootstrap + listener
//!   YAML and exits 0 only if the static config (including the
//!   `destination_port` `FilterChainMatch` predicates added in M10-S1
//!   Phase 3A) passes Envoy's own schema validation against the
//!   version pinned in the gateway image.
//! - `serde_json::from_str::<MitmproxyConfig>` round-trips the
//!   compiler's mitmproxy JSON through the Rust-side `MitmproxyConfig`
//!   Deserialize impl. This is a hermetic smoke test; it does not
//!   require Docker.
//!
//! ## Gate
//!
//! Every test is `#[ignore]` and additionally short-circuits unless
//! `SANDBOX_TEST_VALIDATORS=1` is set. The Makefile target
//! `make test-validators` at the repo root sets the env var, builds
//! the gateway image, and invokes `cargo nextest run` with
//! `--run-ignored only -E 'test(/validator_/)'` so the default
//! workspace test run stays hermetic (no Docker dependency).
//!
//! ## Requirements when enabled
//!
//! - Docker daemon reachable via the local socket.
//! - `sandbox-gateway` image built (`make gateway-image`).
//! - Kernel permits `CAP_NET_ADMIN` containers (`--cap-add=NET_ADMIN`);
//!   no `--privileged` required.
//! - Sufficient disk to spin up a short-lived container per test run.
//!
//! ## Container lifecycle
//!
//! The two Docker-backed tests spawn a long-running `sleep infinity`
//! container from the `sandbox-gateway` image and `docker exec` the
//! validators against it. A RAII wrapper (`TestContainer`) runs
//! `docker rm -f` in its `Drop` impl so the container is cleaned up
//! even on panic. Each test uses its own container with a unique name
//! derived from the test name + timestamp to allow parallel runs.

use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use sandbox_core::network::NetworkInfo;
use sandbox_core::policy::SCHEMA_VERSION;
use sandbox_core::{
    AssuranceLevel, BOOTSTRAP_FILE_IN_CONTAINER, Destination, DnsCache, HttpFilter, HttpMethod,
    LISTENER_DIR_IN_CONTAINER, LISTENER_FILE_IN_CONTAINER, MitmproxyConfig, Policy, PolicyCompiler,
    PolicyRule, Protocol, ResolvedMapping, ResolvedReport, generate_domain_ip_rules,
};

// ---------------------------------------------------------------------------
// Env gate
// ---------------------------------------------------------------------------

const ENV_GATE: &str = "SANDBOX_TEST_VALIDATORS";
const GATEWAY_IMAGE: &str = "sandbox-gateway";

/// Returns `true` when the validator harness is explicitly enabled.
///
/// We require `SANDBOX_TEST_VALIDATORS=1` rather than any non-empty
/// value so accidental inheritance (e.g. a shell function exporting a
/// debug string) does not silently flip the gate.
fn env_gate_enabled() -> bool {
    std::env::var(ENV_GATE).map(|v| v == "1").unwrap_or(false)
}

/// Short-circuits the current test (returning `true`) unless the
/// validator gate is enabled. Prints a standard `SKIP` line so
/// cargo-nextest's output makes the skip reason obvious.
fn skip_unless_enabled(test_name: &str) -> bool {
    if env_gate_enabled() {
        false
    } else {
        eprintln!(
            "SKIP {test_name}: set {ENV_GATE}=1 to enable external-validator tests \
             (requires Docker + `make gateway-image`)"
        );
        true
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Representative v2 policy exercising all three assurance levels.
///
/// Mirrors the `mixed_l1_l2_l3_policy` fixture used inside `policy.rs`'s
/// private test module, but re-declared here because it is not part of
/// the crate's public surface. Keeping it local avoids widening the
/// public API for a test-only fixture.
fn fixture_policy() -> Policy {
    Policy {
        version: SCHEMA_VERSION.to_string(),
        rules: vec![
            PolicyRule {
                host: Destination::Domain("github.com".to_string()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("L1 transport passthrough".to_string()),
                level: AssuranceLevel::Transport,
            },
            PolicyRule {
                host: Destination::Domain("pinned.example.com".to_string()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("L2 TLS passthrough".to_string()),
                level: AssuranceLevel::Tls,
            },
            PolicyRule {
                host: Destination::Domain("monitored.example.com".to_string()),
                port: 443,
                protocol: Protocol::Tcp,
                reason: Some("L3 MITM with GET /api/* allowed".to_string()),
                level: AssuranceLevel::Http {
                    http_filters: vec![HttpFilter {
                        method: HttpMethod::Get,
                        path: "/api/*".to_string(),
                    }],
                },
            },
        ],
    }
}

/// DnsCache seeded with fixture IPs for every L1/L3 domain in the
/// policy. Without seeded IPs the compiler fail-closes and emits no
/// filter chain for those rules, which would reduce the validator's
/// coverage of the compiler's happy path.
fn seeded_dns_cache() -> DnsCache {
    let mut cache = DnsCache::new();
    cache.update(&ResolvedReport {
        mappings: vec![
            ResolvedMapping {
                domain: "github.com".to_string(),
                ips: vec!["140.82.114.4".to_string()],
                ttl: 60,
                timestamp: "2026-04-22T00:00:00Z".to_string(),
            },
            ResolvedMapping {
                domain: "monitored.example.com".to_string(),
                ips: vec!["10.3.3.3".to_string()],
                ttl: 60,
                timestamp: "2026-04-22T00:00:00Z".to_string(),
            },
        ],
    });
    cache
}

/// Synthetic `NetworkInfo` for the tests. The bridge/network names do
/// not need to exist — the compiler consumes the subnet and gateway IP
/// strings only. Using a distinct subnet per test class avoids any
/// collision with other integration tests that might run in parallel.
fn test_network_info() -> NetworkInfo {
    NetworkInfo {
        bridge_name: "sb-validator-test".to_string(),
        subnet: "10.209.15.0/28".to_string(),
        gateway_ip: "10.209.15.2".to_string(),
        vm_ip: "10.209.15.3".to_string(),
        docker_network_name: "sandbox-net-validator".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Container lifecycle (RAII)
// ---------------------------------------------------------------------------

/// A short-lived `sandbox-gateway` container spawned with
/// `CAP_NET_ADMIN` and entrypoint `sleep infinity`. Drops run
/// `docker rm -f` to guarantee cleanup even on test panic.
///
/// The container name is derived from the caller-supplied `label` and
/// the current time-since-epoch in nanos, so concurrent test runs on
/// the same machine (CI parallelism or local `cargo nextest -j`)
/// cannot collide on the name.
struct TestContainer {
    name: String,
}

impl TestContainer {
    fn spawn(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!("sandboxd-validator-{label}-{nanos}");

        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                &name,
                "--cap-add=NET_ADMIN",
                "--entrypoint",
                "sleep",
                GATEWAY_IMAGE,
                "infinity",
            ])
            .output()
            .expect("docker run should be invokable; ensure Docker daemon is running");

        assert!(
            output.status.success(),
            "docker run failed for container {name}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        Self { name }
    }
}

impl Drop for TestContainer {
    fn drop(&mut self) {
        // Best-effort teardown: swallow any error — Drop must not
        // panic, and a stale container from a prior run would already
        // have failed the `docker run` step above.
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

// ---------------------------------------------------------------------------
// docker exec helpers
// ---------------------------------------------------------------------------

/// Run a command inside the container and feed `stdin` on its stdin
/// pipe. Returns the raw `Output` so the caller can assert on exit
/// status and inspect stdout/stderr.
fn exec_with_stdin(container: &str, cmd: &[&str], stdin: &str) -> Output {
    let mut args = vec!["exec", "-i", container];
    args.extend_from_slice(cmd);

    let mut child = Command::new("docker")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("docker exec should spawn");

    {
        use std::io::Write;
        let mut child_stdin = child.stdin.take().expect("child stdin should be piped");
        child_stdin
            .write_all(stdin.as_bytes())
            .expect("writing stdin to docker exec should succeed");
    }

    child
        .wait_with_output()
        .expect("docker exec should complete")
}

/// Run a command inside the container without stdin.
fn exec(container: &str, cmd: &[&str]) -> Output {
    let mut args = vec!["exec", container];
    args.extend_from_slice(cmd);
    Command::new("docker")
        .args(&args)
        .output()
        .expect("docker exec should be invokable")
}

/// Write `content` to `path` inside the container, creating any
/// missing parent directories. Uses `sh -c` + `cat >` via stdin so we
/// do not need to shell-quote the body.
fn write_file_in_container(container: &str, path: &str, content: &str) {
    let parent = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("/");
    let shell = format!("mkdir -p {parent} && cat > {path}");
    let output = exec_with_stdin(container, &["sh", "-c", &shell], content);
    assert!(
        output.status.success(),
        "write_file_in_container({path}) failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `nft -c -f -` accepts the compiler's nftables output plus the
/// DNS-join output from `generate_domain_ip_rules`.
///
/// Rationale: the kernel's nft parser is the ultimate arbiter of
/// ruleset syntax validity, including concat-set element shapes
/// (`ipv4_addr . inet_service`) and the flush+define pattern used by
/// `generate_domain_ip_rules`. A regression that emits a malformed
/// concat-set element would pass Rust-side string-match tests but be
/// rejected by `nft -c`.
///
/// The two emitters share the `sandbox_policy` table — the DNS-join
/// output flushes and re-adds the set elements — so we concatenate
/// both and validate as one ruleset, mirroring how `policy_distributor`
/// pipes them to the kernel in production.
#[test]
#[ignore = "requires Docker + sandbox-gateway image; enable with SANDBOX_TEST_VALIDATORS=1"]
fn validator_nft_check() {
    if skip_unless_enabled("validator_nft_check") {
        return;
    }

    let policy = fixture_policy();
    let network_info = test_network_info();
    let dns_cache = seeded_dns_cache();

    let compiled = PolicyCompiler::compile(&policy, &network_info)
        .expect("fixture policy should compile cleanly");
    let dns_rules = generate_domain_ip_rules(&policy, &dns_cache, &network_info);

    // Feed the base ruleset and the DNS-join output as one input.
    // `generate_domain_ip_rules` is a self-contained flush+add script
    // for the `policy_allow_{tcp,udp}` sets inside `sandbox_policy`,
    // so concatenation produces the steady-state ruleset.
    let combined = format!("{}\n{}\n", compiled.nftables_rules, dns_rules);

    let container = TestContainer::spawn("nft");
    let output = exec_with_stdin(&container.name, &["nft", "-c", "-f", "-"], &combined);

    assert!(
        output.status.success(),
        "nft -c rejected compiler output:\n--- ruleset ---\n{combined}\
         \n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `envoy --mode validate` accepts the compiler's bootstrap + listener
/// YAML (including destination_port-gated filter chains).
///
/// Rationale: Envoy's `--mode validate` loads the static config and
/// initializes listeners/clusters without opening sockets, rejecting
/// anything the pinned Envoy version (1.32.2 per the gateway image)
/// considers ill-formed. The listener uses filesystem LDS
/// (`path_config_source` + `watched_directory`), so we write the
/// listener file to its in-container path before invoking envoy.
///
/// This catches regressions in the compiler's YAML shape that would
/// pass `serde_yaml` round-trips but fail Envoy's schema — for example,
/// an invalid enum value inside `FilterChainMatch.destination_port`'s
/// container, a missing `typed_config.@type` URL, or a tunneling_config
/// field that moved between Envoy releases.
#[test]
#[ignore = "requires Docker + sandbox-gateway image; enable with SANDBOX_TEST_VALIDATORS=1"]
fn validator_envoy_check() {
    if skip_unless_enabled("validator_envoy_check") {
        return;
    }

    let policy = fixture_policy();
    let dns_cache = seeded_dns_cache();

    let bootstrap = PolicyCompiler::compile_envoy_bootstrap();
    let listener = PolicyCompiler::compile_envoy_listener(&policy, &dns_cache);

    let container = TestContainer::spawn("envoy");

    // Write both files to the in-container paths the bootstrap
    // references (path_config_source.path + watched_directory.path).
    write_file_in_container(&container.name, BOOTSTRAP_FILE_IN_CONTAINER, &bootstrap);
    write_file_in_container(&container.name, LISTENER_FILE_IN_CONTAINER, &listener);

    // Sanity: the listener dir must exist (write_file_in_container
    // mkdir -p's the parent, so this is defensive).
    let ls = exec(&container.name, &["ls", LISTENER_DIR_IN_CONTAINER]);
    assert!(
        ls.status.success(),
        "listener dir missing: stderr={}",
        String::from_utf8_lossy(&ls.stderr)
    );

    let output = exec(
        &container.name,
        &[
            "envoy",
            "--mode",
            "validate",
            "-c",
            BOOTSTRAP_FILE_IN_CONTAINER,
        ],
    );

    assert!(
        output.status.success(),
        "envoy --mode validate rejected compiler output:\
         \n--- bootstrap ---\n{bootstrap}\n--- listener ---\n{listener}\
         \n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `compile_mitmproxy` emits JSON that round-trips cleanly through
/// `MitmproxyConfig`'s Deserialize impl.
///
/// Hermetic smoke test — no Docker required; still env-gated so the
/// default workspace test run does not run it. The Python addon
/// consumes this JSON on startup, and the addon's schema expectations
/// line up 1:1 with `MitmproxyConfig` / `MitmproxyRule` /
/// `MitmproxyFilter`. Deserializing through the Rust-side structs
/// catches field-name drift that would silently be ignored by Python's
/// dict-access pattern until a production flow exercised the missing
/// field.
#[test]
#[ignore = "env-gated alongside the Docker-backed validators; enable with SANDBOX_TEST_VALIDATORS=1"]
fn validator_mitmproxy_schema() {
    if skip_unless_enabled("validator_mitmproxy_schema") {
        return;
    }

    let policy = fixture_policy();
    let network_info = test_network_info();

    let compiled = PolicyCompiler::compile(&policy, &network_info)
        .expect("fixture policy should compile cleanly");

    let parsed: MitmproxyConfig =
        serde_json::from_str(&compiled.mitmproxy_config).unwrap_or_else(|e| {
            panic!(
                "mitmproxy config should deserialize; err={e}\nconfig={}",
                compiled.mitmproxy_config
            )
        });

    // Only the L3 rule (monitored.example.com) should appear; L1/L2
    // rules do not emit mitmproxy entries. This asserts the schema
    // shape end-to-end: one (host, port, filters) tuple with the
    // expected values.
    assert_eq!(
        parsed.rules.len(),
        1,
        "expected exactly one mitmproxy rule (from the single L3 fixture entry); got {}: {:?}",
        parsed.rules.len(),
        parsed.rules
    );
    let rule = &parsed.rules[0];
    assert_eq!(rule.host, "monitored.example.com", "rule host mismatch");
    assert_eq!(rule.port, 443, "rule port mismatch");
    assert_eq!(
        rule.filters.len(),
        1,
        "expected exactly one http filter; got {:?}",
        rule.filters
    );
    assert_eq!(rule.filters[0].method, "GET", "filter method mismatch");
    assert_eq!(rule.filters[0].path, "/api/*", "filter path mismatch");
}
