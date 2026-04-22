//! JSONL ingest pipeline — the sandboxd-side consumer of structured event
//! files written by the three policy-enforcing subcomponents inside the
//! gateway container.
//!
//! Spec reference: `.tasks/specs/2026-04-21-port-explicit-policies-presets-
//! observability-design.md`, Part 3 "Envoy access log", "CoreDNS structured
//! emission", "mitmproxy structured emission", and the session-ID stamping
//! paragraph in "Event shape" ("session-ID attribution is sandboxd's job,
//! not each component's"). Phase 7 of the M10-S2 plan.
//!
//! # Shape
//!
//! `create_gateway` bind-mounts a per-session host directory
//! [`crate::events::session_events_host_dir`] into
//! [`crate::events::EVENTS_DIR_IN_CONTAINER`]. The three producers inside
//! the container — Envoy (access log as JSON), the CoreDNS plugin
//! (`EventWriter`), the mitmproxy addon (`EventEmitter`) — append one
//! JSON record per line to `envoy.jsonl`, `coredns.jsonl`, and
//! `mitmproxy.jsonl` respectively. Subsequent commits in this pipeline add
//! a per-layer parser (`envoy`, `coredns`, `mitmproxy`) and a
//! directory-watching driver (`watcher`) that owns one
//! [`jsonl_reader::JsonlTailer`] per file and forwards parsed records to
//! the shared [`crate::events::EventBus`].

pub mod jsonl_reader;
