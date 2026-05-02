# M10-S6 measurement-driven defaults

**Goal.** Record the values chosen for four event/observability knobs
introduced in M10-S2..S4 and the rationale behind each. Per the
2026-04-21 spec's "Known gaps / deferred decisions" bullet on
measurement defaults, M10-S6 is the session where these are pinned.

## Knobs and chosen values

| Knob | Value | Location | Rationale |
|---|---|---|---|
| `events.ring_buffer_size` | 10 000 | `sandboxd/sandbox-core/src/events/bus.rs` (`DEFAULT_RING_BUFFER_SIZE`) | Covers ~10 min of sustained ~15 events/s traffic. Memory cost bounded at ~10 MB/session (1 KB/event upper bound). |
| `events.persist_retention_days` | 14 | `sandboxd/sandboxd/src/main.rs` (`Args::events_persist_retention_days`) | Two sprint cycles of post-incident review; ~170 MB/session on-disk at the modeled event rate. |
| nft-deny-logger `rate_cap` (per session) | 1 000 events/s | `sandboxd/sandbox-nft-deny-logger/src/main.rs` (`Args::rate_cap`) | Spec Part 3 / "Hardening rules" § 5 suggested value. Breach path produces summary events, not drops. |
| nft-deny-logger `conn_cap` (per session TCP) | 256 | `sandboxd/sandbox-nft-deny-logger/src/main.rs` (`Args::conn_cap`) | Spec Part 3 / "Hardening rules" § 6 suggested value. Each concurrent deny costs ~4 KB of socket state; cap fits inside a 10 MB container budget. |

## Methodology

This section is honest: a proper measurement pass would involve a
representative workload (for example, an agent session running
`npm install` + `git clone` of a small repo + a `curl` loop for a
minute) with metrics capture. That measurement has not been
performed — the project ships without production traffic of that
shape. The values above are **spec-suggested defaults**, chosen so
that:

- **`ring_buffer_size = 10 000`** covers ~10 minutes at ~15 events/s
  sustained. A reconnecting SSE consumer (future work) sees a useful
  replay without the buffer capping the signal. The cost is ~10 MB
  of memory per session at the upper bound of event size (~1 KB).
- **`persist_retention_days = 14`** covers roughly two sprint cycles
  of traffic for post-incident review. A session producing the
  10-events/s average shape fills roughly 12 MB of JSONL per day
  (uncompressed), so 14 days is ~170 MB/session — well inside
  reasonable on-disk overhead for the typical development host.
- **`rate_cap = 1 000 events/s per session`** is the spec's
  suggested ceiling and matches what the pipeline can flush without
  back-pressuring nft-deny-logger's NFLOG / TCP-listener inputs.
  Breaches produce periodic summary events, not drops.
- **`conn_cap = 256 per-session TCP`** matches the spec suggestion
  and is calibrated for nft-deny-logger's non-`recv`ing RST-close
  pattern on the TCP-deny path (each concurrent deny costs ~4 KB of
  socket state; 256 fits well inside a 10 MB container memory
  budget).

When a real-world measurement pass is run, the `rate_cap` and
`conn_cap` are the two most likely to shift (rate depends on
workload profile; `conn_cap` depends on how many parallel TCP denies
a single agent session generates). The ring buffer and retention
are sized conservatively and are less sensitive.

## Revision policy

These values are CLI-tunable (clap `--arg` and env var):

- `--events-persist-retention-days` / `SANDBOX_EVENTS_PERSIST_RETENTION_DAYS`
- `--rate-cap` / `SANDBOX_DENY_LOGGER_RATE_CAP`
- `--conn-cap` / `SANDBOX_DENY_LOGGER_CONN_CAP`
- `ring_buffer_size` is a field on `EventBusConfig` (per-session,
  not currently CLI-exposed on sandboxd, but tunable from code).

A future measurement-driven tuning pass can update the defaults
without a schema change. The spec does not gate a release on the
measurement.
