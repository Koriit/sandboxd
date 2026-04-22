//! `sandbox-deny-logger` — a gateway-container component that closes the
//! silent-denial gap in the L3 flow.
//!
//! Spec reference: `2026-04-21-port-explicit-policies-presets-observability-design.md`
//! Part 3 / "Deny-logger component" (lines 724-872).
//!
//! Packet flow: nftables' `sandbox_dnat` prerouting chain conditionally
//! DNATs VM egress — allowed destinations go to Envoy on `:10000`, denied
//! destinations go to this process on `:10001` (TCP) or `:10002` (UDP).
//! The binary reads the pre-DNAT 5-tuple via `SO_ORIGINAL_DST` (TCP) /
//! `IP_RECVORIGDSTADDR` (UDP) and appends one `deny` event per attempt to
//! the per-session JSONL file that sandboxd's ingest watcher tails. TCP
//! is closed with RST; UDP datagrams are discarded. A minimal HTTP server
//! on `:10003` answers `GET /health` so Docker's `HEALTHCHECK` plus
//! sandboxd's component-health probe can observe liveness.
//!
//! Hardening invariants (spec Part 3 / "Hardening rules" §§ 1-6) are
//! baked into the listener code: no peer reads, fixed-size UDP buffer,
//! TCP RST close, rate + concurrency caps with a periodic
//! `rate_limited` summary event.
//!
//! Session awareness intentionally lives in sandboxd, not here: the
//! emitted JSONL has no `session` field. sandboxd stamps the session at
//! ingest time via its `vm_ip → session-id` map.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

mod event;
mod health;
mod limits;
mod tcp;
mod udp;

use event::EventEmitter;
use limits::RateCap;

/// CLI arguments for the deny-logger binary.
///
/// Defaults match the spec's `Listener design` section: TCP on `:10001`,
/// UDP on `:10002`, health on `:10003`, all three bound on `--bind-ip`
/// (gateway_ip). Rate and concurrency caps default to the spec's
/// *suggested* values — tunable via env vars or flags for M10-S6
/// measurement-driven refinement.
#[derive(Parser, Debug)]
#[command(
    name = "sandbox-deny-logger",
    about = "Deny-logger for denied VM egress"
)]
struct Args {
    /// IPv4 bind address for all three listeners.
    ///
    /// Must be the gateway container's bridge IP — not 127.0.0.1.
    /// PREROUTING DNAT to loopback is dropped by the kernel as a martian
    /// destination unless `route_localnet=1` is set on the ingress
    /// interface, which the gateway container does not enable. See spec
    /// Part 3 / "Listener design / Bind address".
    #[arg(long)]
    bind_ip: Ipv4Addr,

    /// JSONL file to append `deny` / `rate_limited` events to.
    ///
    /// Shares a directory with Envoy / CoreDNS / mitmproxy JSONL files
    /// so the per-session bind mount at
    /// `/var/log/gateway/events/<session-id>/` is covered by one ingest
    /// watcher.
    #[arg(long, default_value = "/var/log/gateway/events/deny-logger.jsonl")]
    event_path: PathBuf,

    /// TCP listener port (denied TCP from `sandbox_dnat` lands here).
    #[arg(long, default_value_t = 10001)]
    tcp_port: u16,

    /// UDP listener port (denied UDP from `sandbox_dnat` lands here).
    #[arg(long, default_value_t = 10002)]
    udp_port: u16,

    /// Health probe port. Not in the nftables DNAT set; reached from
    /// inside the container by `HEALTHCHECK` / sandboxd `docker exec`.
    #[arg(long, default_value_t = 10003)]
    health_port: u16,

    /// Per-process event-rate cap, events per second.
    ///
    /// Defaults to the spec's suggested 1000 / session (spec Part 3 /
    /// "Hardening rules" § 5). Each gateway container is per-session, so
    /// the process-wide cap is the per-session cap.
    ///
    /// Overridable via `SANDBOX_DENY_LOGGER_RATE_CAP` (clap env-var
    /// fallback). Final defaults are measurement-driven in M10-S6.
    #[arg(long, env = "SANDBOX_DENY_LOGGER_RATE_CAP", default_value_t = 1000)]
    rate_cap: u32,

    /// Per-process TCP concurrent-connection cap.
    ///
    /// Spec Part 3 / "Hardening rules" § 6. Connections accepted past
    /// the cap are closed immediately and counted into the periodic
    /// rate-limited summary.
    #[arg(long, env = "SANDBOX_DENY_LOGGER_CONN_CAP", default_value_t = 256)]
    conn_cap: u32,
}

fn main() -> ExitCode {
    // Tracing subscriber on stderr — deny events go to `--event-path`
    // (JSONL); tracing logs are operator-facing and kept separate per
    // spec Part 3 / "Listener design" ("structured JSONL").
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    tracing::info!(
        bind_ip = %args.bind_ip,
        tcp_port = args.tcp_port,
        udp_port = args.udp_port,
        health_port = args.health_port,
        event_path = %args.event_path.display(),
        rate_cap = args.rate_cap,
        conn_cap = args.conn_cap,
        "starting sandbox-deny-logger",
    );

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!(error = %err, "tokio runtime build failed");
            return ExitCode::from(1);
        }
    };

    match runtime.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "deny-logger exiting with error");
            ExitCode::from(1)
        }
    }
}

async fn run(args: Args) -> std::io::Result<()> {
    let emitter = Arc::new(EventEmitter::open(&args.event_path)?);
    let rate_cap = Arc::new(RateCap::new(
        args.rate_cap,
        Arc::clone(&emitter),
        chrono::Utc::now(),
    ));

    let tcp_listener = tcp::bind(args.bind_ip, args.tcp_port).await?;
    tracing::info!(port = args.tcp_port, "tcp listener bound");

    let udp_socket = udp::bind(args.bind_ip, args.udp_port).await?;
    tracing::info!(port = args.udp_port, "udp listener bound");

    let health_listener = health::bind(args.bind_ip, args.health_port).await?;
    tracing::info!(port = args.health_port, "health listener bound");

    let tcp_emitter = Arc::clone(&emitter);
    let tcp_rate_cap = Arc::clone(&rate_cap);
    let tcp_task = tokio::spawn(async move {
        if let Err(err) = tcp::run(tcp_listener, tcp_emitter, tcp_rate_cap).await {
            tracing::error!(error = %err, "tcp listener exited with error");
        }
    });

    let udp_emitter = Arc::clone(&emitter);
    let udp_rate_cap = Arc::clone(&rate_cap);
    let udp_task = tokio::spawn(async move {
        if let Err(err) = udp::run(udp_socket, udp_emitter, udp_rate_cap).await {
            tracing::error!(error = %err, "udp listener exited with error");
        }
    });

    let health_emitter = Arc::clone(&emitter);
    let health_task = tokio::spawn(async move {
        if let Err(err) = health::run(health_listener, health_emitter).await {
            tracing::error!(error = %err, "health listener exited with error");
        }
    });

    // Background ticker so a storm that ends on a window boundary
    // still flushes its `rate_limited` summary even when no further
    // traffic arrives. Abort on shutdown.
    let flush_ticker = limits::spawn_flush_ticker(Arc::clone(&rate_cap));

    // Any listener task exiting takes the process down so Docker's
    // HEALTHCHECK flips the container unhealthy and sandboxd's gateway
    // poller restarts it — spec Part 3 / "Liveness posture" forbids a
    // degraded-observability mode.
    let outcome = tokio::select! {
        res = tcp_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = udp_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = health_task => res.map_err(|e| std::io::Error::other(e.to_string())),
    };
    flush_ticker.abort();
    outcome
}
