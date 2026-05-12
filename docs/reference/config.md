---
title: Daemon config reference
description: Every flag, environment variable, and default path that controls how sandboxd and the sandbox CLI find each other and persist state.
---

This page enumerates the full configuration surface of `sandboxd` (the daemon) and `sandbox` (the CLI). Neither binary reads a config file — everything is controlled via CLI flags and a small number of environment variables.

For the HTTP endpoints served by the daemon, see the [HTTP API reference](/reference/http-api/). For the CLI subcommands, see the [CLI reference](/reference/cli/).

## `sandboxd` flags

```
sandboxd [--socket <path>] [--base-dir <path>] [--log-file <path>]
         [--events-persist] [--events-persist-retention-days <n>]
```

| Flag | Default | Description |
|---|---|---|
| `--socket <path>` | `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock`, falling back to `~/.local/share/sandboxd/sandboxd.sock` | Path to the Unix socket the daemon listens on. Overridden by `SANDBOX_SOCKET` when the flag is not passed. |
| `--base-dir <path>` | `$XDG_DATA_HOME/sandboxd`, falling back to `~/.local/share/sandboxd` | Base directory for daemon state: `sessions.db` (SQLite) and per-session CA material. |
| `--log-file <path>` | unset | Append tracing output to this file instead of stderr. When set, stderr logging is disabled to avoid duplicate lines under init systems that capture stderr. Fails fast on startup if the file cannot be opened. |
| `--events-persist` | off | Enable the persistent JSONL event sink. When set, every event published on the in-memory bus is also written to `{base_dir}/sessions/{session_id}/events/{layer}-YYYY-MM-DD.jsonl`, rotated daily in UTC. Off by default — operators opt in per deployment. See [Event persistence](#event-persistence) below for the sink's overflow behavior. |
| `--events-persist-retention-days <n>` | `14` | How many days of persisted JSONL event files to retain. Only meaningful when `--events-persist` is set. An hourly pruner removes any file whose filename-embedded `YYYY-MM-DD` date is strictly older than `today - n` (UTC). A file dated exactly `today - n` survives; `today - n - 1` is removed. |

Flags always take precedence over environment variables.

## `sandbox` (CLI) flags

Global flags apply to every subcommand:

| Flag | Default | Description |
|---|---|---|
| `--socket <path>` | same resolution as the daemon | Unix socket to connect to. Overridden by `SANDBOX_SOCKET` when the flag is not passed. |
| `--yes`, `-y` | off | Assume yes to interactive prompts; use defaults without prompting. |

See the [CLI reference](/reference/cli/) for the subcommand-specific flags.

## Environment variables

### `SANDBOX_SOCKET`

Overrides the default socket path for both the daemon and the CLI. Honored when no explicit `--socket` flag is passed.

```bash
export SANDBOX_SOCKET=/tmp/sandboxd.sock
sandboxd &
sandbox ps
```

### `XDG_RUNTIME_DIR`

Consulted when neither `--socket` nor `SANDBOX_SOCKET` is set. The daemon and CLI use `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock` when this is defined.

### `XDG_DATA_HOME`

Consulted by the daemon when `--base-dir` is not set. Falls back to `$HOME/.local/share` when unset.

### `HOME`

Used as a last-resort fallback when both XDG variables are unset. Falls back to `/tmp` if `HOME` is somehow also unset.

### `RUST_LOG`

Controls the tracing log level for `sandboxd`. Parsed by `tracing_subscriber::EnvFilter`. Defaults to `info`. Examples:

```bash
RUST_LOG=debug sandboxd
RUST_LOG=sandboxd=trace,sandbox_core=info sandboxd
```

See [Daemon logging](/concepts/logging/) for how log output is routed.

### QEMU wrapper environment

The daemon passes a small set of environment variables to the QEMU wrapper script that Lima runs. You do not normally set these yourself — the daemon sets them based on `SessionConfig` and the per-session network plan. They are listed here so nothing looks mysterious in `ps`:

| Variable | Purpose |
|---|---|
| `SANDBOX_QEMU_HARDENED` | `1` enables the hardened QEMU command line (device lockdown). |
| `SANDBOX_QEMU_MEMORY_MB` | Memory cap for the cgroup wrapping QEMU. |
| `SANDBOX_QEMU_CPUS` | CPU quota for the cgroup wrapping QEMU. |
| `SANDBOX_DOCKER_BRIDGE` | Docker bridge name to attach the VM's data NIC to. |
| `SANDBOX_VM_MAC` | Deterministic MAC address for the VM's data NIC (derived from the session ID). |

`SANDBOX_BRIDGE_HELPER` and `SANDBOX_RLKIT_PID` were removed; the QEMU wrapper no longer uses a helper-path indirection.

## Path resolution

Both the daemon and the CLI use the same socket-resolution order:

1. `--socket` flag (explicit; highest priority).
2. `SANDBOX_SOCKET` env var.
3. `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock`.
4. `$HOME/.local/share/sandboxd/sandboxd.sock`.

The daemon's base-dir order:

1. `--base-dir` flag.
2. `$XDG_DATA_HOME/sandboxd`.
3. `$HOME/.local/share/sandboxd`.

## On-disk layout

Under the base dir, the daemon creates:

```
{base_dir}/
├── sessions.db           # SQLite: sessions, network info, policies
├── ca/
│   └── <session-id>/     # per-session CA material
├── sessions/
│   └── <session-id>/
│       └── events/
│           └── <layer>-YYYY-MM-DD.jsonl   # only when --events-persist is set
└── ...
```

`sessions.db` persists the full session state machine — see [Sessions](/concepts/sessions/) for what survives a daemon restart and the compatibility rules for evolving the schema.

The `sessions/<id>/events/` tree is populated only when `--events-persist` is set; see the next section for what lives there.

## Event persistence

When `--events-persist` is set, the daemon spawns a persistent sink alongside the in-memory event bus that backs [`GET /sessions/{id}/events`](/reference/http-api/#get-sessionsidevents--replay-or-stream-events). Every event published on the bus is also forwarded to a JSONL file on disk, keyed by `(session_id, layer, UTC date)`:

```
{base_dir}/sessions/<session-id>/events/<layer>-YYYY-MM-DD.jsonl
```

Layer names match the [HTTP API filter values](/reference/http-api/#get-sessionsidevents--replay-or-stream-events): `dns`, `envoy`, `mitmproxy`, `deny-logger`, `lifecycle`. Each line is the same JSON shape that the HTTP endpoint emits. Files rotate at UTC midnight — the day boundary is the `YYYY-MM-DD` segment of the filename, not a timer.

The sink is **best-effort and never backpressures the bus.** Internally, the relay between the broadcast channel and the writer task is a bounded mpsc channel with a 100 000-event capacity. When the writer falls behind (disk slow, filesystem issue, or a burst that outruns `write(2)`), events are dropped at the relay rather than stalling producers. Each drop is logged at `warn!` with a running total (`dropped_total=N`) so operators can see the signal in the tracing stream. The in-memory ring buffer served by `/sessions/{id}/events` is unaffected — it always reflects the live bus.

The **pruner** runs hourly and removes JSONL files whose filename-embedded date is strictly older than `today - events_persist_retention_days` (UTC). With the default of `14`, a file dated 14 days ago survives; a file dated 15 days ago is removed. Unparseable filenames (a stray `README.txt`, a half-written `.jsonl.tmp`) are left alone.

The sink is disabled by default because most operator workflows rely on the in-memory replay window plus a separate `sandbox events --follow > file.jsonl` capture. Enable it when you need longer retention than the in-memory ring holds, or when `sandboxd` itself may be restarted and you want event history to survive the restart.

## Minimal examples

Run the daemon in the foreground with everything at defaults:

```bash
sandboxd
```

Run it on a custom socket with debug logging to a file:

```bash
RUST_LOG=debug sandboxd \
    --socket /tmp/sandboxd.sock \
    --log-file /tmp/sandboxd.log
```

Point the CLI at a non-default daemon:

```bash
SANDBOX_SOCKET=/tmp/sandboxd.sock sandbox ps
# or
sandbox --socket /tmp/sandboxd.sock ps
```

Enable the persistent event sink with a 30-day retention window:

```bash
sandboxd --events-persist --events-persist-retention-days 30
```

## See also

- [Daemon logging](/concepts/logging/) — where tracing output goes and how to run under systemd / launchd.
- [HTTP API reference](/reference/http-api/) — what the socket actually serves.
- [CLI reference](/reference/cli/) — subcommands and their flags.
