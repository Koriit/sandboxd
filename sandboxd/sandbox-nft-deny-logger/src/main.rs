//! `sandbox-nft-deny-logger` — a gateway-container component that closes
//! the silent-denial gap in the L3 flow.
//!
//! Spec references:
//!   - `2026-04-21-port-explicit-policies-presets-observability-design.md`
//!     Part 3 / "Deny-logger component" — original deny-logger contract.
//!   - `2026-05-01-udp-nft-loggers-design.md` Decisions 2, 4, 5 — the
//!     rename and the UDP datapath restructure (DNAT-to-listener → NFLOG
//!     receive).
//!
//! Packet flow:
//!
//!   - **TCP deny**: nftables' `sandbox_dnat` prerouting chain DNATs
//!     denied TCP to `gateway_ip:10001`. This binary `accept(2)`s the
//!     connection, reads `SO_ORIGINAL_DST` to recover the pre-DNAT
//!     destination, emits a `deny` JSONL event, and closes the socket
//!     with RST (SO_LINGER 0).
//!   - **UDP deny**: nft no longer DNATs denied UDP. Instead, the
//!     `sandbox_dnat.prerouting` chain matches unmatched UDP with
//!     `meta l4proto udp log group 1; meta l4proto udp drop`. The
//!     kernel emits one netlink message per drop on NFNLGRP_NFLOG group
//!     1; this binary subscribes to that group, parses the IPv4 + UDP
//!     headers from `NFULA_PAYLOAD`, and emits the deny event with the
//!     pre-DNAT 5-tuple straight from the headers — no userland
//!     datapath, no DNAT, no conntrack lookup.
//!
//! A minimal HTTP server on `:10003` answers `GET /health` so Docker's
//! `HEALTHCHECK` plus sandboxd's component-health probe can observe
//! liveness.
//!
//! Hardening invariants (no peer reads, RST close on TCP, rate +
//! concurrency caps with a periodic `rate_limited` summary) are baked
//! into the listener / receiver code.
//!
//! Session awareness intentionally lives in sandboxd, not here: the
//! emitted JSONL has no `session` field. sandboxd stamps the session at
//! ingest time via its `vm_ip → session-id` map.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use sandbox_event_emitter::{EventEmitter, RateCap, health, spawn_flush_ticker};
use tokio::signal::unix::{SignalKind, signal};

mod nflog;
mod tcp;

/// CLI arguments for the nft-deny-logger binary.
///
/// Defaults match the spec's listener-port assignments: TCP on `:10001`,
/// health on `:10003`. The UDP listener port (`:10002`) is gone — the
/// UDP deny path is now NFLOG-driven, and the NFLOG group number is
/// the new tunable.
#[derive(Parser, Debug)]
#[command(
    name = "sandbox-nft-deny-logger",
    about = "nft-layer deny-logger for denied VM egress (TCP listener + NFLOG UDP receiver)"
)]
struct Args {
    /// IPv4 bind address for the TCP and health listeners.
    ///
    /// Must be the gateway container's bridge IP — not 127.0.0.1.
    /// PREROUTING DNAT to loopback is dropped by the kernel as a
    /// martian destination unless `route_localnet=1` is set on the
    /// ingress interface, which the gateway container does not enable.
    #[arg(long)]
    bind_ip: Ipv4Addr,

    /// JSONL file to append `deny` / `rate_limited` events to.
    ///
    /// Shares a directory with Envoy / CoreDNS / mitmproxy JSONL files
    /// so the per-session bind mount at
    /// `/var/log/gateway/events/<session-id>/` is covered by one ingest
    /// watcher.
    ///
    /// The default file name is `nft-deny.jsonl` per
    /// `2026-05-01-udp-nft-loggers-design.md` Resolution 6 —
    /// coordinated with the daemon-side ingest watcher's known-file glob
    /// (`sandbox-core/src/events/ingest/watcher.rs`). The on-disk
    /// filename is independent of the wire `layer: "deny-logger"`
    /// discriminator, which is what the parser keys on per JSONL line.
    #[arg(long, default_value = "/var/log/gateway/events/nft-deny.jsonl")]
    event_path: PathBuf,

    /// TCP listener port (denied TCP from `sandbox_dnat` lands here).
    #[arg(long, default_value_t = 10001)]
    tcp_port: u16,

    /// Health probe port. Not in the nftables DNAT set; reached from
    /// inside the container by `HEALTHCHECK` / sandboxd `docker exec`.
    #[arg(long, default_value_t = 10003)]
    health_port: u16,

    /// NFLOG group the kernel emits dropped-UDP packets on. Must match
    /// the `nft log group N` value in `gateway.rs`'s prerouting deny
    /// rule. Pinned to `1` per
    /// `2026-05-01-udp-nft-loggers-design.md` Resolution 1.
    #[arg(long, default_value_t = 1)]
    nflog_group: u16,

    /// Per-process event-rate cap, events per second.
    #[arg(long, env = "SANDBOX_DENY_LOGGER_RATE_CAP", default_value_t = 1000)]
    rate_cap: u32,

    /// Per-process TCP concurrent-connection cap.
    #[arg(long, env = "SANDBOX_DENY_LOGGER_CONN_CAP", default_value_t = 256)]
    conn_cap: u32,
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
        tcp_port = args.tcp_port,
        health_port = args.health_port,
        nflog_group = args.nflog_group,
        event_path = %args.event_path.display(),
        rate_cap = args.rate_cap,
        conn_cap = args.conn_cap,
        "starting sandbox-nft-deny-logger",
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
            tracing::error!(error = %err, "nft-deny-logger exiting with error");
            ExitCode::from(1)
        }
    }
}

async fn run(args: Args) -> std::io::Result<()> {
    // `"deny-logger"` is the on-disk layer tag the daemon-side ingest
    // parser keys on (`sandbox-core/src/events/ingest/nft_logger.rs`);
    // preserved byte-for-byte across the binary rename so daemon ingest
    // is unaffected (`2026-05-01-udp-nft-loggers-design.md`
    // Resolution 5).
    let emitter = Arc::new(EventEmitter::open(&args.event_path, "deny-logger")?);
    let rate_cap = Arc::new(RateCap::new(
        args.rate_cap,
        Arc::clone(&emitter),
        chrono::Utc::now(),
    ));

    // Pin the kernel accept-queue backlog to a multiple of `conn_cap`.
    // `tcp::bind` takes `u32` and clamps to `i32::MAX` internally, so
    // `saturating_mul` is the only conversion the caller has to do.
    let tcp_backlog: u32 = args.conn_cap.saturating_mul(4);
    let tcp_listener = tcp::bind(args.bind_ip, args.tcp_port, tcp_backlog).await?;
    tracing::info!(
        port = args.tcp_port,
        backlog = tcp_backlog,
        "tcp listener bound"
    );

    // NFLOG subscriber for the UDP deny path. Hard fail if the netlink
    // socket cannot be opened or configured: without it the deny-logger
    // would silently miss every UDP deny, which is strictly worse than
    // going unhealthy and being restarted by Docker's HEALTHCHECK.
    let nflog_subscriber = nflog::NflogSubscriber::bind(args.nflog_group)
        .map_err(|e| std::io::Error::other(format!("nflog bind: {e}")))?;
    tracing::info!(
        group = args.nflog_group,
        "nflog subscriber bound (NETLINK_NETFILTER, NFNLGRP_NFLOG, CAP_NET_ADMIN)"
    );
    // Snapshot the netlink fd before moving the subscriber into
    // `spawn_blocking`. The SIGTERM handler below uses this fd to
    // call `nflog::shutdown_recv`, which causes the in-flight
    // `recv` to return cleanly. `RawFd` is `Copy` so this is a
    // value snapshot, not a borrow against `nflog_subscriber`'s
    // lifetime.
    let nflog_fd = nflog_subscriber.as_raw_fd();
    let shutdown = Arc::new(AtomicBool::new(false));

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

    // The NFLOG receive loop is a synchronous netlink `recv` per
    // CLAUDE.md's blocking-syscall convention: place it on a dedicated
    // `spawn_blocking` thread so it cannot starve a tokio worker. It
    // runs forever; we surface its `JoinHandle` to tokio's `select!`
    // below so a panic / unexpected exit takes the process down (same
    // posture as the listener tasks). The kernel is the bursting
    // sender, the consumer is one task; blocking is the simplest
    // correct shape.
    //
    // SIGTERM clean-exit contract: the shutdown atomic is shared
    // between this loop and the signal handler. When SIGTERM fires
    // the handler sets the flag and `shutdown_recv`s the fd; the
    // loop observes either path and returns `Ok(())` within ~1
    // second instead of relying on the gateway entrypoint's 10-second
    // SIGKILL escalation.
    let nflog_emitter = Arc::clone(&emitter);
    let nflog_rate_cap = Arc::clone(&rate_cap);
    let nflog_shutdown = Arc::clone(&shutdown);
    let mut nflog_task = tokio::task::spawn_blocking(move || {
        if let Err(err) = nflog::run_blocking(
            nflog_subscriber,
            nflog_emitter,
            nflog_rate_cap,
            nflog_shutdown,
        ) {
            tracing::error!(error = %err, "nflog receiver exited with error");
        }
    });

    let health_emitter = Arc::clone(&emitter);
    let health_task = tokio::spawn(async move {
        // The deny-logger's `/health` body shape preserves the legacy
        // field names (`tcp_listener`, `nflog_socket`,
        // `events_emitted_60s`) across the binary rename per
        // `2026-05-01-udp-nft-loggers-design.md` Resolution 5, and
        // adds the parser audit counters (`nflog_emitted`,
        // `nflog_parse_errors`) so operators get a numeric audit
        // signal without scraping logs. The closure threads the
        // crate-local `nflog::emitted` / `nflog::parse_errors`
        // statics into the lib's stock body builder.
        let body_builder = |emitter: &EventEmitter| -> String {
            health::deny_logger_body(
                emitter.events_emitted_60s(),
                nflog::emitted(),
                nflog::parse_errors(),
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
        res = tcp_task => res.map_err(|e| std::io::Error::other(e.to_string())),
        res = &mut nflog_task => res.map_err(|e| std::io::Error::other(e.to_string())),
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

    // Signal the NFLOG blocking loop to exit cleanly. Setting the
    // flag covers the "between-recvs" race; the `shutdown_recv`
    // syscall handles the "in-flight recv" race. With both, the
    // loop observes the shutdown within one syscall round-trip and
    // returns `Ok(())` so tokio's blocking-pool thread is freed
    // before the runtime drop. We then wait briefly on the join
    // handle to confirm clean exit; on timeout we fall through to
    // the runtime drop, which detaches the blocking thread (the
    // kernel reaps the fd at process exit).
    shutdown.store(true, Ordering::Release);
    nflog::shutdown_recv(nflog_fd);
    if !nflog_task.is_finished() {
        // 1s budget — well below the gateway entrypoint's 10s
        // SIGKILL escalation. If the recv loop hasn't observed the
        // shutdown by then, something is wrong with the kernel-side
        // socket state; drop through and let the runtime detach.
        let join_outcome = tokio::time::timeout(Duration::from_secs(1), nflog_task).await;
        if let Err(_elapsed) = join_outcome {
            tracing::warn!(
                "nflog receiver did not exit within 1s of SIGTERM; \
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

#[cfg(test)]
mod tests {
    //! Wiring-level tests for the nft-deny-logger's process-liveness
    //! contract. Mirrors the previous deny-logger test shape — the
    //! NFLOG receive loop is a `spawn_blocking` task, so the same
    //! `JoinHandle` panic-propagation contract applies.

    #[tokio::test]
    async fn flush_ticker_panic_resolves_select_arm_via_mut_borrow() {
        let mut ticker: tokio::task::JoinHandle<()> = tokio::spawn(async {
            tokio::task::yield_now().await;
            panic!("simulated flush_ticker panic");
        });

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
        ticker.abort();
    }

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
