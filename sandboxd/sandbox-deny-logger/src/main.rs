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

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};

mod conntrack;
mod event;
mod health;
mod limits;
mod tcp;
mod udp;

use conntrack::ConntrackLookup;
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

    // Pin the kernel accept-queue backlog to a multiple of `conn_cap`
    // so over-cap connections always reach our `accept()` loop (where
    // they are then RST-closed by the over-cap path) instead of being
    // kernel-dropped at the SYN with ECONNREFUSED. The factor is
    // conservative — typical SOMAXCONN is 4096, our default `conn_cap`
    // is 256, so `4 * conn_cap = 1024` keeps us comfortably below the
    // kernel ceiling while leaving headroom for short bursts. The
    // i32 cast cannot overflow at any plausible conn_cap (clap caps
    // u32 input via the type system).
    let tcp_backlog: i32 = (args.conn_cap.saturating_mul(4))
        .min(i32::MAX as u32)
        .try_into()
        .expect("backlog fits in i32 after .min(i32::MAX as u32)");
    let tcp_listener = tcp::bind(args.bind_ip, args.tcp_port, tcp_backlog).await?;
    tracing::info!(
        port = args.tcp_port,
        backlog = tcp_backlog,
        "tcp listener bound"
    );

    let udp_socket = udp::bind(args.bind_ip, args.udp_port).await?;
    let udp_bind_addr = SocketAddrV4::new(args.bind_ip, args.udp_port);
    tracing::info!(port = args.udp_port, "udp listener bound");

    // Conntrack lookup handle for UDP pre-DNAT recovery (M12-S1).
    // Hard fail if the netlink socket can't be opened: without it the
    // UDP path silently regresses to the post-DNAT bug, which is
    // strictly worse than going unhealthy and being restarted.
    let udp_conntrack = ConntrackLookup::new()
        .map_err(|e| std::io::Error::other(format!("conntrack lookup init: {e}")))?;
    tracing::info!("conntrack netlink socket bound (NETLINK_NETFILTER, CAP_NET_ADMIN)");

    let health_listener = health::bind(args.bind_ip, args.health_port).await?;
    tracing::info!(port = args.health_port, "health listener bound");

    let tcp_emitter = Arc::clone(&emitter);
    let tcp_rate_cap = Arc::clone(&rate_cap);
    let tcp_conn_cap = args.conn_cap;
    let tcp_task = tokio::spawn(async move {
        if let Err(err) = tcp::run(tcp_listener, tcp_emitter, tcp_rate_cap, tcp_conn_cap).await {
            tracing::error!(error = %err, "tcp listener exited with error");
        }
    });

    let udp_emitter = Arc::clone(&emitter);
    let udp_rate_cap = Arc::clone(&rate_cap);
    let udp_task = tokio::spawn(async move {
        if let Err(err) = udp::run(
            udp_socket,
            udp_bind_addr,
            Some(udp_conntrack),
            udp_emitter,
            udp_rate_cap,
        )
        .await
        {
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
    let mut flush_ticker = limits::spawn_flush_ticker(Arc::clone(&rate_cap));

    // Graceful shutdown on SIGTERM (orchestrator request — Docker
    // `docker stop`, sandboxd's gateway restart, Kubernetes lifecycle)
    // and SIGINT (developer Ctrl-C). Both are handled identically:
    // flush any pending rate-limited summary so a quiescent-tail drop
    // still shows up in the JSONL, then return `Ok(())` so the process
    // exits with status 0.
    //
    // SIGTERM handling is not covered by an in-process unit test —
    // spawning the binary and signalling it would exceed the plan's
    // "8-11 atomic commits" budget for marginal coverage of a code
    // path that is structurally obvious (select! arm + flush_now).
    // `limits::tests::flush_now_emits_pending_summary` covers the
    // behavioural core (pending drops flushed via `flush_now`); the
    // shutdown wiring below is reviewable-by-eye.
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| std::io::Error::other(format!("install SIGTERM handler: {e}")))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| std::io::Error::other(format!("install SIGINT handler: {e}")))?;

    // Any listener task exiting takes the process down so Docker's
    // HEALTHCHECK flips the container unhealthy and sandboxd's gateway
    // poller restarts it — spec Part 3 / "Liveness posture" forbids a
    // degraded-observability mode. The flush ticker is on the same
    // contract: if it panics or exits, rate-limited summaries silently
    // stop being flushed for traffic that quiesces on a window
    // boundary, so we let the process die rather than absorb the
    // failure. Polling the ticker via `&mut` keeps ownership in
    // `flush_ticker` so we can still `abort()` it on a non-ticker exit
    // before flushing the closing window — preventing the ticker from
    // racing `rate_cap.flush_now()` below.
    let outcome = tokio::select! {
        res = tcp_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = udp_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = health_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = &mut flush_ticker => {
            // The ticker is `loop { tick; rollover }` — it should
            // never exit on its own. Any resolution is therefore a
            // bug (panic propagated as `JoinError::Panic`, or the
            // task was cancelled out from under us). Surface it as a
            // process error so the container goes unhealthy and
            // sandboxd's gateway monitor restarts us — same posture
            // as a listener task crash.
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

    flush_ticker.abort();
    // Flush any pending rate-limited summary before we drop the
    // emitter — quiescent-tail drops must not disappear on shutdown.
    rate_cap.flush_now(chrono::Utc::now());
    // Emitter's `Mutex<File>` flushes on drop via `EventEmitter`'s
    // own Drop (implicit — `File::drop` flushes the FD buffer).
    drop(rate_cap);
    drop(emitter);
    outcome
}

#[cfg(test)]
mod tests {
    //! Wiring-level tests for the deny-logger's process-liveness
    //! contract. The full `run()` happy path needs real network
    //! listeners and a SIGTERM signal; these tests target the
    //! invariants that are easy to break in isolation:
    //!
    //! - **Flush-ticker panic propagation** (M10-S8 #31): a panic in
    //!   the `spawn_flush_ticker` task must not be silently absorbed
    //!   by tokio's runtime; the `&mut JoinHandle` arm of `run`'s
    //!   `tokio::select!` must observe it and surface an error so
    //!   the process exits non-zero, Docker flips the container to
    //!   unhealthy, and sandboxd's gateway monitor restarts it.
    //!
    //! We don't need to crash the test process — exercising the
    //! `JoinHandle::await → JoinError::Panic` resolution and the
    //! select! arm behaviour proves the wiring holds.

    /// A panic inside a `tokio::spawn`ed task must surface as
    /// `JoinError::is_panic()` when its `JoinHandle` is polled, and
    /// the same handle must fire its `tokio::select!` arm even when
    /// borrowed mutably (`&mut handle`) — the exact pattern used by
    /// `run()` to keep ownership of the ticker through shutdown so
    /// `flush_ticker.abort()` can run after the select returns.
    #[tokio::test]
    async fn flush_ticker_panic_resolves_select_arm_via_mut_borrow() {
        let mut ticker: tokio::task::JoinHandle<()> = tokio::spawn(async {
            // Yield once so the spawn site doesn't observe completion
            // before the select! polls — otherwise the select arm
            // could fire before the panic actually unwinds, masking
            // the panic-detection path we want to exercise.
            tokio::task::yield_now().await;
            panic!("simulated flush_ticker panic");
        });

        // Mirror `run()`'s select! shape: a `&mut handle` arm plus a
        // never-firing arm so the select doesn't degenerate to a
        // bare await (which would also work but wouldn't exercise
        // the same control flow).
        let outcome = tokio::select! {
            res = &mut ticker => {
                match res {
                    Err(e) if e.is_panic() => Err(format!("ticker panicked: {e}")),
                    Err(e) => Err(format!("ticker task ended: {e}")),
                    Ok(()) => Err("ticker exited cleanly".to_string()),
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                Ok(())
            }
        };

        let err = outcome.expect_err("the panic arm must fire before the 5s sleep");
        assert!(
            err.contains("ticker panicked"),
            "expected JoinError::is_panic() match arm to fire; got: {err}"
        );
        // Ownership preserved: even though select! polled `&mut
        // ticker`, we still own the handle and could call
        // `ticker.abort()` here. (The handle is already complete, so
        // abort is a no-op, but the borrow-checker wouldn't allow
        // this if the select! arm had consumed `ticker`.)
        ticker.abort();
    }

    /// Sanity guard: `spawn_flush_ticker` itself is a `tokio::spawn`
    /// of an `async move { … }`, which means a panic in
    /// `cap.maybe_rollover` would be caught by the runtime and
    /// surfaced via the `JoinHandle`. This test asserts the
    /// JoinHandle is observable (i.e. not detached) and its panic
    /// path matches the contract the select! arm relies on. We
    /// exercise the panic path directly via a raw `tokio::spawn`
    /// rather than corrupting `RateCap` state — there is no input
    /// to `maybe_rollover` that panics today, but the wiring must
    /// still surface a future regression.
    #[tokio::test]
    async fn join_handle_panic_path_matches_select_arm_contract() {
        let h: tokio::task::JoinHandle<()> =
            tokio::spawn(async { panic!("expected: panic-path contract probe") });
        let res = h.await;
        match res {
            Err(e) => {
                assert!(
                    e.is_panic(),
                    "tokio::spawn panic must surface as JoinError::is_panic(); got {e:?}"
                );
            }
            Ok(()) => panic!("a panicking task must not resolve to Ok(())"),
        }
    }
}
