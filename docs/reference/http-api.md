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
  "policy": { "version": "1.0.0", "rules": [] },
  "repo": "https://github.com/example/app.git",
  "boot_cmd": "make setup",
  "workspace": "shared:/home/you/project",
  "hardened": true,
  "no_cache": false
}
```

Semantics:

- `workspace` takes precedence over `repo` if both are set. Only `shared:<absolute-path>` is currently accepted.
- `policy`, when present, is applied immediately after the session boots.
- `hardened` defaults to `true` (device lockdown + cgroup limits). Set `false` for debugging.
- `no_cache: true` skips the pre-baked base image and forces the slow create path.

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

### `POST /sessions/{id}/upload` — upload a file into the session

Request body:

```json
{
  "path": "/home/agent/note.txt",
  "data": "aGVsbG8K",
  "mode": 420
}
```

`data` is base64-encoded file contents. `mode` is an optional Unix permission bitset (e.g. `420` = `0o644`). Session must be `running`.

Success: `200 OK` with `{ "status": "ok", "message": "file uploaded to <path>" }`.

### `POST /sessions/{id}/download` — download a file out of the session

Request body:

```json
{ "path": "/home/agent/note.txt" }
```

Session must be `running`.

Success: `200 OK` with `{ "data": "<base64>" }`.

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

## Policy

### `POST /sessions/{id}/policy` — apply or update policy

Request body is a policy document (the `Policy` shape flattened at the top level):

```json
{
  "version": "1.0.0",
  "rules": [
    {
      "destination": "github.com",
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

No request body. Idempotent. Compiles an empty policy, pushes it to the gateway (empty CoreDNS allow-list, deny-all mitmproxy + Envoy), flushes L3 DNAT rules, deletes the persisted row, and cancels the DNS propagation loop. Session must be `running`.

Success: `200 OK` with `{ "status": "ok", "message": "policy cleared; session is now fail-closed" }`.

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
  "policy": { "version": "1.0.0", "rules": [] }
}
```

Notes:

- `state` is one of `creating`, `running`, `stopped`, `error`.
- `workspace_mode` is a rendered string: `shared:<absolute host path>` or `clone:<repo url>`, or omitted if none was set.
- `guest_agent_status` / `gateway_status` are omitted when the session is not running.
- `policy` is only populated by `GET /sessions/{id}`; the list endpoint omits it.
- Optional fields (`name`, `repo`, `boot_cmd`, `template`) are omitted when null.

## See also

- [CLI reference](/reference/cli/) — the user-facing wrapper over every endpoint above.
- [Config reference](/reference/config/) — socket path, base dir, and log-file flags.
- [Sessions](/concepts/sessions/) — lifecycle and persistence model.
- [Policy model](/concepts/policy-model/) — what each assurance level does.
