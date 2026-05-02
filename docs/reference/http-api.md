---
title: HTTP API reference
description: Endpoints served by sandboxd over its Unix socket — request and response shapes, status codes, and error format.
---

`sandboxd` listens for HTTP/1.1 requests on a Unix domain socket. The default path is `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock`, falling back to `~/.local/share/sandboxd/sandboxd.sock`. The socket path is overridden by the `SANDBOX_SOCKET` environment variable or the `--socket` flag — see the [daemon config reference](/reference/config/).

The CLI is a thin wrapper over this API. Every endpoint accepts and returns JSON. All `{id}` path parameters accept either a full session ID, a unique session-ID prefix, or a session name.

## Calling the socket

With `curl`:

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock" \
    -H 'Content-Type: application/json' \
    http://localhost/sessions
```

The hostname in the URL is ignored by the daemon but required by HTTP/1.1. Pick any; `localhost` is conventional.

## Error format

Every error response carries a JSON body:

```json
{ "error": "session not found: abc123" }
```

Status-code mapping:

| Condition | Status |
|---|---|
| Session not found | `404 Not Found` |
| Invalid state transition | `400 Bad Request` |
| Invalid argument | `400 Bad Request` |
| Timed-out operation | `504 Gateway Timeout` |
| Internal failure (lima, gateway, CA, I/O, DB) | `500 Internal Server Error` |

Success status codes are documented per endpoint below.

## Sessions

### `POST /sessions` — create a session

Request body (all fields optional):

```json
{
  "name": "dev",
  "cpus": 2,
  "memory_mb": 4096,
  "disk_gb": 20,
  "template": "/path/to/lima.yaml",
  "policy": { "version": "2.0.0", "rules": [] },
  "source_presets": ["npm:", "github-repo:repo=foo/bar"],
  "repo": "https://github.com/example/app.git",
  "boot_cmd": "make setup",
  "workspace": "shared:/home/you/project",
  "hardened": true,
  "no_cache": false,
  "backend": "lima",
  "force_rootless_docker": false
}
```

Semantics:

- `workspace` takes precedence over `repo` if both are set. Only `shared:<absolute-path>` is currently accepted.
- `policy`, when present, is applied immediately after the session boots. The matching `source_presets` array (the original CLI `--preset` invocation strings, in order) is stored as an audit trail on the `policy_applied` lifecycle event; the daemon does not re-expand presets server-side, so `policy` already carries the merged effective rules.
- `hardened` defaults to `true` (device lockdown + cgroup limits). Set `false` for debugging.
- `no_cache: true` skips the pre-baked base image and forces the slow create path. Lima only — the daemon rejects `no_cache: true` with `400 Bad Request` on the container backend, which shares its lite image across concurrent sessions; use `POST /rebuild-image` with `backend=container` for operator-driven lite-image rebuilds.
- `cpus` accepts a fractional value (one-decimal grid; the daemon rounds at parse time so `0.81` lands as `0.8`) on the container backend. Lima sessions reject a fractional value with `400 Bad Request` — QEMU's `-smp` flag pins integer cores.
- `backend` selects which runtime hosts the session: `"lima"` (Lima/QEMU VM) or `"container"` (Docker container — "lite" mode). Omitted means daemon-resolved default.
- `force_rootless_docker: true` is the operator opt-in that allows session-create on a rootless Docker host. Container backend only — combining it with a Lima-resolved backend is a misuse error (`400 Bad Request`).

Success: `200 OK` with a `SessionDto` body (see below).

### `GET /sessions` — list sessions

No request body.

Success: `200 OK` with a JSON array of `SessionDto` objects. The list endpoint deliberately omits the `policy` field to keep the response cheap; use `GET /sessions/{id}` for that.

### `GET /sessions/{id}` — describe one session

No request body.

Success: `200 OK` with a single `SessionDto` object, including `policy` if one is applied.

### `DELETE /sessions/{id}` — remove a session

No request body. Stops the VM (if running), tears down networking, removes the CA, and deletes the session row.

Success: `204 No Content`.

### `POST /sessions/{id}/start` — start a stopped session

No request body. Session must be in `stopped` state.

Success: `200 OK` with the refreshed `SessionDto`.

### `POST /sessions/{id}/stop` — stop a running session

No request body. Session must be in `running` state. Tears down gateway + Docker network + TAP, halts the VM. Preserves the session row, subnet allocation, and applied policy.

Success: `200 OK` with the refreshed `SessionDto`.

### `POST /sessions/{id}/exec` — run a command in the session

Request body:

```json
{
  "command": "uname",
  "args": ["-a"]
}
```

Session must be `running`. The daemon forwards the request to the guest agent over the TCP-over-SSH channel.

Success: `200 OK` with:

```json
{
  "exit_code": 0,
  "stdout": "Linux ...\n",
  "stderr": ""
}
```

### File transfer

The daemon does not expose HTTP endpoints for file transfer. The CLI's
`sandbox cp` and `sandbox sync` commands dispatch directly to the
backend's native copy tool (`limactl cp` / `docker cp`) or to host
`rsync` over the backend's native shell — see the [CLI
reference](/reference/cli/#sandbox-cp).

### `GET /sessions/{id}/health` — detailed health

No request body. Returns a per-component health object — VM status, guest agent reachability, gateway component health (Envoy, mitmproxy, CoreDNS), and network health (bridge/tap).

Success: `200 OK` with:

```json
{
  "session_id": "a1b2c3d4e5f6",
  "vm_status": "running",
  "guest_agent": "connected",
  "gateway": {
    "container_status": "running",
    "envoy": "healthy",
    "mitmproxy": "healthy",
    "coredns": "healthy"
  },
  "network": {
    "bridge_exists": true,
    "tap_exists": true
  }
}
```

### `GET /sessions/{id}/events` — replay or stream events

Returns the session's event stream as newline-delimited JSON (one event per line). Every per-request and per-connection decision made by the gateway's DNS / Envoy / mitmproxy / deny-logger layers, plus the session's lifecycle events, flows through this endpoint. The corresponding CLI wrapper is [`sandbox events`](/reference/cli/#sandbox-events).

Query parameters (all optional):

| Parameter | Repeatable | Values | Description |
|---|---|---|---|
| `follow` | no | `true`, `false` (default `false`) | When `true`, the response stays open and streams new events as they arrive. When `false` (or omitted), the current ring-buffer snapshot is replayed and the response closes. |
| `layer` | yes | `dns`, `envoy`, `mitmproxy`, `deny-logger`, `lifecycle` | Include only events emitted by these layers. Repeat the key (`?layer=dns&layer=deny-logger`) to union multiple values. |
| `event` | yes | snake_case event name (e.g. `query_denied`, `connection_allowed`, `deny`, `rate_limited`, `policy_applied`, `gateway_ready`) | Include only events with these names. |
| `decision` | yes | `allow`, `deny` | Include only traffic events whose verdict matches. Events that carry no decision (all lifecycle events, plus the deny-logger `rate_limited` summary) never match a non-empty `decision` filter. |
| `since` | no | RFC 3339 timestamp (e.g. `2026-04-22T12:00:00Z`) | Events older than this timestamp are excluded. Both second-precision and fractional forms are accepted. The comparison is inclusive (`t >= since`). |

Filters combine with AND across axes and OR within an axis. A request with no filter parameters matches every event.

Unknown values on any enumerated axis fail loud with `400 Bad Request`; for example `?decision=reset` or `?layer=quic` returns an error naming the offending value rather than silently matching nothing. A malformed `since` value fails the same way.

Response:

- `Content-Type: application/jsonl`.
- `200 OK` with a body of zero or more `\n`-terminated JSON lines. A session that exists but has no matching events returns an empty body.
- With `follow=true`, the body uses HTTP/1.1 chunked transfer encoding and stays open until the client disconnects or the session is unregistered. Clients should consume it line by line.

The session is resolved name-or-id, same as every other `/sessions/{id}/…` endpoint. A missing session returns `404 Not Found`. An unregistered-but-stored session (e.g. created but never started) returns `200 OK` with an empty body in non-follow mode; with `follow=true` the body stays open but never produces any lines until the session is started.

Each event line is a flat JSON object with a common envelope plus layer-specific fields:

```json
{"timestamp":"2026-04-22T12:34:56.789Z","session":"a1b2c3d4e5f6","layer":"dns","event":"query_denied","query":"blocked.example.com","qtype":"AAAA","reason":"policy_deny"}
```

- `timestamp` is RFC 3339 with millisecond precision and a `Z` suffix.
- `session` is the 12-character hex session id, or an empty string for pre-session lifecycle events.
- `layer` is one of the values enumerated in the filter table above.
- `event` is a snake_case discriminator whose remaining fields are layer-specific; see the lifecycle, DNS, Envoy, mitmproxy, and deny-logger source modules in `sandbox-core` for the exhaustive per-event schema.

#### The `lifecycle.ring_buffer_lag` synthetic line

When a `follow=true` consumer falls behind the in-memory broadcast channel, the handler emits a stream-local synthetic line so the gap is visible inline rather than being silently dropped:

```json
{"layer":"lifecycle","event":"ring_buffer_lag","skipped":42,"timestamp":"2026-04-22T12:35:01.004Z"}
```

This line is not a real bus event: it is never persisted and is not emitted to other subscribers or to the non-follow replay path. `skipped` is the number of live events the broadcast dropped since the previous receive.

#### Example

```bash
# Replay every deny decision accumulated in the ring buffer.
curl --unix-socket "$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock" \
    "http://localhost/sessions/dev/events?decision=deny"

# Stream DNS and deny-logger events live, starting from a specific wall-clock time.
curl --no-buffer --unix-socket "$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock" \
    "http://localhost/sessions/dev/events?follow=true&layer=dns&layer=deny-logger&since=2026-04-22T12:00:00Z"
```

`--no-buffer` is useful when following a stream so `curl` flushes each line to stdout as it arrives.

## Policy

### `POST /sessions/{id}/policy` — apply or update policy

Request body is a policy document (the `Policy` shape flattened at the top level):

```json
{
  "version": "2.0.0",
  "rules": [
    {
      "host": "github.com",
      "port": 443,
      "protocol": "tcp",
      "level": "tls",
      "reason": "source fetch"
    }
  ]
}
```

Session must be `running`. The daemon compiles the policy, distributes it to the gateway's Envoy/mitmproxy/CoreDNS configs, persists it in the session store, and starts the DNS propagation loop.

Success: `200 OK` with `{ "status": "ok", "message": "policy applied successfully" }`.

For the full policy schema (assurance levels, HTTP filters, destinations, protocols) see the [policy model](/concepts/policy-model/).

### `DELETE /sessions/{id}/policy` — clear policy

No request body. Idempotent. Compiles an empty policy, pushes it to the gateway (empty CoreDNS allow-list, deny-all mitmproxy + Envoy, empty Envoy L3 filter chains), deletes the persisted row, and cancels the DNS propagation loop. Session must be `running`.

Success: `200 OK` with `{ "status": "ok", "message": "policy cleared; session is now fail-closed" }`.

### `GET /sessions/{id}/policy/propagation-status` — propagation snapshot

No request body. Reports whether the most recent policy-apply has reconciled across every enforcement layer (CoreDNS, the nftables `policy_allow_{tcp,udp}` sets, and Envoy's L3 filter chains).

Backs the [`sandbox policy status`](/reference/cli/#sandbox-policy-status) command and the E2E suite's `wait_for_policy` helper.

Success: `200 OK` with:

```json
{
  "expected_hash": "9f8e7d6c5b4a...",
  "propagated_hash": "9f8e7d6c5b4a...",
  "propagated": true,
  "seconds_since_apply": 0.34
}
```

- `expected_hash` is the SHA-256 hex digest of the canonical JSON form of the most recently *applied* policy.
- `propagated_hash` is the digest of the policy that has *propagated* across all three layers (`null` until the first reconciliation completes).
- `propagated` is `true` when the two hashes match.
- `seconds_since_apply` is wall-clock seconds since the last policy-apply on this session.

The "never applied" case (no policy on the session) returns all-`null` hashes with `propagated: false` and `seconds_since_apply: 0`. The CLI's `--wait` loop treats that as "keep polling, an apply may be mid-flight", and shorts to `propagated: true` once the first applied hash propagates.

## Base image

### `POST /rebuild-image` — rebuild the pre-baked base image

No request body. Rebuilds the golden base VM image from scratch. Holds a lock so concurrent `POST /sessions` requests wait for the rebuild.

Success: `200 OK` with the literal body `base image rebuilt`.

### `GET /base-image-status` — check the base image

No request body.

Success: `200 OK` with one of:

```json
{ "status": "missing" }
{ "status": "fresh" }
{ "status": "stale", "age_days": 14, "hash_mismatch": false }
```

## Daemon health

### `GET /health` — global health

No request body. Summarises gateway status for every running session.

Success: `200 OK` with:

```json
{
  "status": "ok",
  "running_sessions": 2,
  "gateways": [
    { "session_id": "a1b2c3d4e5f6", "name": "dev", "gateway_status": "healthy" }
  ]
}
```

## Backends

### `GET /backends` — backend capability matrix

No request body. Returns the per-backend capability matrix the daemon advertises — the read-only counterpart to `sandbox describe -v`. Backs the CLI's `Capabilities` block.

Success: `200 OK` with:

```json
{
  "backends": [
    {
      "kind": "lima",
      "available": true,
      "capabilities": {
        "supports_no_cache": true,
        "supports_workspace_modes": ["shared", "clone"],
        "fractional_cpus": false,
        "isolation_grade": "vm"
      }
    },
    {
      "kind": "container",
      "available": true,
      "capabilities": {
        "supports_no_cache": false,
        "supports_workspace_modes": ["shared", "clone"],
        "fractional_cpus": true,
        "isolation_grade": "container"
      }
    }
  ]
}
```

Field names and shapes evolve with the capability schema; consult the `sandbox-core::Capabilities` source for the authoritative DTO.

## Response shapes

### `SessionDto`

```json
{
  "id": "a1b2c3d4e5f6",
  "name": "dev",
  "state": "running",
  "created_at": "2026-04-18T10:00:00Z",
  "updated_at": "2026-04-18T10:05:00Z",
  "config": {
    "cpus": 2,
    "memory_mb": 4096,
    "disk_gb": 20,
    "workspace_mode": "shared:/home/you/project",
    "hardened": true,
    "repo": null,
    "boot_cmd": null,
    "template": null
  },
  "guest_agent_status": "connected",
  "gateway_status": "running",
  "backend": "lima",
  "network": {
    "session_ip": "10.209.0.3",
    "gateway_ip": "10.209.0.2",
    "subnet_cidr": "10.209.0.0/28",
    "bridge_name": "sb-a1b2c3d4e5f6"
  },
  "mounts": {
    "workspace_in_session": "/home/agent/workspace",
    "workspace_host_source": "/home/you/project",
    "ca_bundle_in_session": null,
    "home_volume": null
  },
  "rootless": null,
  "policy": { "version": "2.0.0", "rules": [] }
}
```

Notes:

- `state` is one of `creating`, `running`, `stopped`, `error`.
- `workspace_mode` is a rendered string: `shared:<absolute host path>` or `clone:<repo url>`, or omitted if none was set.
- `guest_agent_status` / `gateway_status` are omitted when the session is not running.
- `policy` is only populated by `GET /sessions/{id}`; the list endpoint omits it.
- Optional fields (`name`, `repo`, `boot_cmd`, `template`) are omitted when null.
- `backend` is `"lima"` or `"container"`. Older records that predate the container backend default to `"lima"` on read.
- `network`, `mounts`, and `rootless` are populated by the single-session endpoint when applicable; they are omitted from list responses or when the underlying state is absent. `rootless` is populated only on container sessions where the rootless-Docker probe ran (`{detected, forced}` pair); Lima sessions omit it.
- `warnings` (omitted when empty) carries operator-facing notices, currently the container backend's first-use lite-image build notice.

## See also

- [CLI reference](/reference/cli/) — the user-facing wrapper over every endpoint above.
- [Config reference](/reference/config/) — socket path, base dir, and log-file flags.
- [Sessions](/concepts/sessions/) — lifecycle and persistence model.
- [Policy model](/concepts/policy-model/) — what each assurance level does.
