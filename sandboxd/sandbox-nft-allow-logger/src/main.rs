//! `sandbox-nft-allow-logger` — gateway-container component that
//! closes the UDP allow-flow audit gap.
//!
//! Spec references:
//!   - `2026-05-01-udp-nft-loggers-design.md` Decisions 3, 4, 5 — the
//!     new NFCT-driven allow-flow audit log, the binary-rename family,
//!     and the shared lib crate.
//!
//! Packet flow:
//!
//!   - **UDP allow** (Decision 1): nft's `sandbox_dnat` prerouting
//!     chain matches `policy_allow_udp` and `accept`s — no DNAT, no
//!     userland datapath. The packet exits via MASQUERADE on
//!     POSTROUTING and reaches the upstream directly.
//!   - **Audit signal** (this binary, Decision 3): the kernel's
//!     conntrack subsystem creates a tracked flow for the allowed UDP
//!     and broadcasts an `IPCTNL_MSG_CT_NEW` message on
//!     `NFNLGRP_CONNTRACK_NEW`. This binary subscribes to that
//!     multicast group, filters the stream for UDP at parse time
//!     (`CTA_PROTO_NUM == 17`), extracts the `CTA_TUPLE_ORIG` 5-tuple
//!     (the address the VM dialled — under Decision 1 there is no NAT
//!     in the allow path, so "original-direction" is the literal
//!     destination), and emits one `event: "allow"` JSONL record per
//!     new flow.
//!
//! Skipped:
//!
//!   - **Non-UDP flows** (TCP, ICMP, etc.). TCP allow-path audit is
//!     Envoy's job — emitting a duplicate signal here would
//!     double-count.
//!   - **`NFCT_T_DESTROY`** (Resolution 7). Per-flow lifecycle isn't
//!     a sandbox-policy audit concern; if downstream needs flow-end
//!     timing later, a separate `event: "allow_end"` record can be
//!     added additively.
//!
//! ## 30-second-rollover property
//!
//! Plain UDP flows are tracked by conntrack with a default timeout
//! (`net.netfilter.nf_conntrack_udp_timeout`, 30 s). A flow that
//! goes silent for ≥30 s and resumes triggers a *new* `NFCT_T_NEW`
//! event on the same 5-tuple — the audit log will show two allow
//! records for what an operator might call "one session." This is
//! the property of UDP-via-conntrack, not a bug. Documented in spec
//! Decision 3 and the troubleshooting docs.
//!
//! No test asserts this property: a hermetic fast-clock harness for
//! kernel conntrack timeouts doesn't exist, and a real 30 s sleep in
//! tests is undesirable. Operators see it documented.
//!
//! A minimal HTTP server on `:10004` answers `GET /health` so Docker's
//! `HEALTHCHECK` plus sandboxd's component-health probe can observe
//! liveness.
//!
//! Hardening invariants (per-process rate cap with periodic
//! `rate_limited` summary) are inherited from the shared
//! `sandbox-event-emitter` lib.
//!
//! Session awareness intentionally lives in sandboxd, not here: the
//! emitted JSONL has no `session` field. sandboxd stamps the session
//! at ingest time via its `vm_ip → session-id` map.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use sandbox_event_emitter::{EventEmitter, RateCap, health, spawn_flush_ticker};
use tokio::signal::unix::{SignalKind, signal};

mod nfct;

/// CLI arguments for the nft-allow-logger binary.
///
/// Defaults match the spec's listener-port assignments: health on
/// `:10004` (one above the deny-logger's `:10003` — Decision 4 /
/// Resolution 5). NFCT subscription is groupless on the consumer side
/// (multicast on `NFNLGRP_CONNTRACK_NEW`, family-1 nl_group bit), so
/// there is no group-number CLI knob analogous to NFLOG.
#[derive(Parser, Debug)]
#[command(
    name = "sandbox-nft-allow-logger",
    about = "nft-layer allow-flow audit logger (NFCT subscription, UDP-only)"
)]
struct Args {
    /// IPv4 bind address for the health listener.
    ///
    /// Must be the gateway container's bridge IP. Loopback works in
    /// tests, but production deployments use the bridge IP so the
    /// `HEALTHCHECK` exec probe can reach it consistently.
    #[arg(long)]
    bind_ip: Ipv4Addr,

    /// JSONL file to append `allow` / `rate_limited` events to.
    ///
    /// Shares a directory with Envoy / CoreDNS / mitmproxy / deny-
    /// logger JSONL files so the per-session bind mount at
    /// `/var/log/gateway/events/<session-id>/` is covered by one
    /// ingest watcher. The file name is `nft-allow.jsonl` per
    /// `2026-05-01-udp-nft-loggers-design.md` Resolution 6 (the shorter
    /// `nft-allow` form is preferred over `nft-allow-logger` because
    /// the file already lives in a logger-emitted-events directory —
    /// the `-logger` suffix is implicit context).
    #[arg(long, default_value = "/var/log/gateway/events/nft-allow.jsonl")]
    event_path: PathBuf,

    /// Health probe port. Not in the nftables DNAT set; reached from
    /// inside the container by `HEALTHCHECK` / sandboxd `docker exec`.
    /// `:10004` adjacent to the deny-logger's `:10003`
    /// (`2026-05-01-udp-nft-loggers-design.md` Decision 4); not
    /// load-bearing — the gateway container's port table has nothing
    /// else listening in this range.
    #[arg(long, default_value_t = 10004)]
    health_port: u16,

    /// Per-process event-rate cap, events per second. Inherited from
    /// the deny-logger pattern (Resolution 3 of
    /// `2026-05-01-udp-nft-loggers-design.md` defers per-source rate
    /// caps to a follow-up; the per-process cap suffices for the v1
    /// allow-logger).
    #[arg(long, env = "SANDBOX_ALLOW_LOGGER_RATE_CAP", default_value_t = 1000)]
    rate_cap: u32,
}

fn main() -> ExitCode {
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
        health_port = args.health_port,
        event_path = %args.event_path.display(),
        rate_cap = args.rate_cap,
        "starting sandbox-nft-allow-logger",
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
            tracing::error!(error = %err, "nft-allow-logger exiting with error");
            ExitCode::from(1)
        }
    }
}

async fn run(args: Args) -> std::io::Result<()> {
    // `"allow-logger"` is the on-disk layer tag the daemon-side
    // ingest parser dispatches on; the daemon-side ingest is an
    // additive change rather than a new pipeline
    // (`2026-05-01-udp-nft-loggers-design.md` Decision 5). The same
    // tag drives the EventEmitter's `layer:` line field and is the
    // value the daemon-side `nft_logger.rs` parser keys on alongside
    // the existing `deny-logger` tag.
    let emitter = Arc::new(EventEmitter::open(&args.event_path, "allow-logger")?);
    let rate_cap = Arc::new(RateCap::new(
        args.rate_cap,
        Arc::clone(&emitter),
        chrono::Utc::now(),
    ));

    // NFCT subscriber for the UDP allow path. Hard-fail if the
    // netlink socket cannot be bound: without it the allow-logger
    // would silently miss every UDP allow event, which is strictly
    // worse than going unhealthy and being restarted by Docker's
    // HEALTHCHECK. The conntrack subsystem is loaded inside the
    // gateway container by the existing audit-§2.4 setup;
    // `CAP_NET_ADMIN` is in the run flags.
    let nfct_subscriber = nfct::NfctSubscriber::bind()
        .map_err(|e| std::io::Error::other(format!("nfct bind: {e}")))?;
    tracing::info!("nfct subscriber bound (NETLINK_NETFILTER, NFNLGRP_CONNTRACK_NEW)");
    // Snapshot the netlink fd before moving the subscriber into
    // `spawn_blocking` (mirrors the deny-logger). The SIGTERM
    // handler below uses this fd to call `nfct::shutdown_recv`,
    // which causes the in-flight `recv` to return cleanly.
    let nfct_fd = nfct_subscriber.as_raw_fd();
    let shutdown = Arc::new(AtomicBool::new(false));

    let health_listener = health::bind(args.bind_ip, args.health_port).await?;
    tracing::info!(port = args.health_port, "health listener bound");

    // The NFCT receive loop is a synchronous netlink `recv` per
    // CLAUDE.md's blocking-syscall convention: place it on a
    // dedicated `spawn_blocking` thread so the netlink syscall does
    // not park a tokio worker under sustained traffic. Mirrors the
    // deny-logger's NFLOG receive loop, including the SIGTERM
    // clean-exit contract: shutdown atomic + half-close of the
    // netlink fd so the loop exits within ~1s of SIGTERM rather
    // than relying on the gateway entrypoint's 10-second SIGKILL
    // escalation.
    let nfct_emitter = Arc::clone(&emitter);
    let nfct_rate_cap = Arc::clone(&rate_cap);
    let nfct_shutdown = Arc::clone(&shutdown);
    let mut nfct_task = tokio::task::spawn_blocking(move || {
        if let Err(err) =
            nfct::run_blocking(nfct_subscriber, nfct_emitter, nfct_rate_cap, nfct_shutdown)
        {
            tracing::error!(error = %err, "nfct receiver exited with error");
        }
    });

    let health_emitter = Arc::clone(&emitter);
    let health_task = tokio::spawn(async move {
        // Allow-logger `/health` shape: `nfct_socket` + the rolling
        // `allow_events_emitted_60s` gauge plus parser audit
        // counters (`nfct_emitted`, `nfct_skipped`,
        // `nfct_parse_errors`) so operators get a numeric audit
        // signal without scraping logs. Per-binary builder
        // (Resolution 5) — the lib's HTTP framing is shared with
        // the deny-logger, only the JSON body differs.
        let body_builder = |emitter: &EventEmitter| -> String {
            health::allow_logger_body(
                emitter.events_emitted_60s(),
                nfct::emitted(),
                nfct::skipped(),
                nfct::parse_errors(),
            )
        };
        if let Err(err) = health::run(health_listener, health_emitter, body_builder).await {
            tracing::error!(error = %err, "health listener exited with error");
        }
    });

    let mut flush_ticker = spawn_flush_ticker(Arc::clone(&rate_cap));

    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| std::io::Error::other(format!("install SIGTERM handler: {e}")))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| std::io::Error::other(format!("install SIGINT handler: {e}")))?;

    let outcome = tokio::select! {
        res = &mut nfct_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = health_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = &mut flush_ticker => {
            let err_msg = match res {
                Err(join_err) if join_err.is_panic() => {
                    format!("flush_ticker panicked: {join_err}")
                }
                Err(join_err) => {
                    format!("flush_ticker task ended unexpectedly: {join_err}")
                }
                Ok(()) => "flush_ticker exited; ticker loop must be infinite".to_string(),
            };
            tracing::error!(error = %err_msg, "flush ticker exited unexpectedly");
            Err(std::io::Error::other(err_msg))
        }
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received; shutting down");
            Ok(())
        }
        _ = sigint.recv() => {
            tracing::info!("SIGINT received; shutting down");
            Ok(())
        }
    };

    // Signal the NFCT blocking loop to exit cleanly. See the
    // deny-logger's main.rs for the full rationale; the shape is
    // identical here.
    shutdown.store(true, Ordering::Release);
    nfct::shutdown_recv(nfct_fd);
    if !nfct_task.is_finished() {
        let join_outcome = tokio::time::timeout(Duration::from_secs(1), nfct_task).await;
        if let Err(_elapsed) = join_outcome {
            tracing::warn!(
                "nfct receiver did not exit within 1s of SIGTERM; \
                 falling through to runtime drop (process exit will reap)"
            );
        }
    }

    flush_ticker.abort();
    rate_cap.flush_now(chrono::Utc::now());
    drop(rate_cap);
    drop(emitter);
    outcome
}
