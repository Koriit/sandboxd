//! Cross-cutting infrastructure for the gateway container's nft-layer
//! loggers.
//!
//! Spec reference: `2026-05-01-udp-nft-loggers-design.md`, Decision 5
//! (Shared lib crate `sandbox-event-emitter`).
//!
//! This crate owns the pieces both `sandbox-nft-deny-logger` and
//! `sandbox-nft-allow-logger` need to share:
//!
//! - [`EventEmitter`] — append-mode JSONL writer with a byte-for-byte
//!   stable wire shape. Records are flat JSON objects with a `timestamp`,
//!   a `layer` tag, an `event` discriminator (`deny` / `allow` /
//!   `rate_limited`), and the per-event payload flattened on top.
//! - [`DenyRecord`] / [`AllowRecord`] / [`Protocol`] — payload types.
//!   `DenyRecord` and `AllowRecord` wire shapes are load-bearing for
//!   daemon-side ingest (`sandbox-core/src/events/ingest/nft_logger.rs`);
//!   never rename a field without a coordinated update on the consumer
//!   side.
//! - [`RateCap`] + [`spawn_flush_ticker`] — per-process rolling rate cap
//!   and the 1-second ticker that flushes a `rate_limited` summary on
//!   window rollover.
//! - [`health::bind`] / [`health::run`] — the `/health` HTTP endpoint
//!   (response shape preserved across the M12-S2 binary rename per
//!   Resolution 5).
//!
//! Binary crates compose these primitives; this lib does not contain
//! data-plane code (UDP / TCP listeners, NFLOG / NFCT subscribers).

pub mod event;
pub mod health;
pub mod limits;

pub use event::{AllowRecord, DenyRecord, EventEmitter, Protocol};
pub use limits::{Admit, RateCap, WINDOW, spawn_flush_ticker};
