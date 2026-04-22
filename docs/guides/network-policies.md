---
title: Write and apply network policies
description: Author a policy file, apply it to a session, verify it, and troubleshoot denials.
---

This guide walks you through writing a policy file, attaching it to a session, updating it live, and diagnosing the denial messages you will see when something does not match. For the underlying model — assurance levels, rule fields, validation rules — see [policy model](/concepts/policy-model/).

## Before you start

- A running `sandboxd` daemon.
- The `sandbox` CLI on your `PATH`.
- A text editor for writing JSON.

## Write a policy file

A policy is a JSON file with a `version` and a `rules` array. Every rule names a `host`, a `port`, and an L4 `protocol` (`tcp` or `udp`). Create `policy.json`:

```json
{
  "version": "2.0.0",
  "rules": [
    {
      "host": "github.com",
      "port": 443,
      "protocol": "tcp",
      "level": "transport",
      "reason": "GitHub web and git"
    },
    {
      "host": "*.github.com",
      "port": 443,
      "protocol": "tcp",
      "level": "transport",
      "reason": "GitHub API and subdomains"
    },
    {
      "host": "registry.npmjs.org",
      "port": 443,
      "protocol": "tcp",
      "level": "transport",
      "reason": "npm package registry"
    }
  ]
}
```

Points to note:

- **Every rule must declare an explicit `port`** (1–65535) and `protocol` (`tcp` or `udp`). There are no defaults — the compiler rejects a rule that omits either field.
- **`"*.github.com"` does not match `"github.com"`** — the apex needs its own rule.
- **A bare `*` host is rejected.** To open a port broadly, pair it with a CIDR (for example `0.0.0.0/0`) and be explicit that you are doing so.
- **Use `transport` for pinned-certificate hosts** (GitHub, npm, PyPI, container registries). HTTPS inspection breaks pinning.
- **Every `http` rule needs an `http_filters` array** — see below.
- **Rule identity is the `(host, port)` pair.** Two rules with the same host and port but different levels are a contradiction and are rejected.

### An HTTP-filter rule

When you want to restrict which methods and paths the agent can call, use level `http`:

```json
{
  "host": "api.internal.example.com",
  "port": 443,
  "protocol": "tcp",
  "level": "http",
  "http_filters": [
    {"method": "GET",  "path": "/api/v2/read/**"},
    {"method": "POST", "path": "/api/v2/write/**"}
  ],
  "reason": "Internal API — reads and scoped writes only"
}
```

Paths are matched per segment and are anchored (the whole request path must match):

- `**` matches any run of characters, including `/` — use it to match across path segments.
- `*` matches any run of non-`/` characters — it stays inside a single segment.
- `?` matches exactly one non-`/` character.
- Literal characters match themselves.

A request is allowed if any filter's method and path both match.

### A broader research policy

TLS-verified passthrough for sites where you want hostname verification but do not need HTTP inspection:

```json
{
  "version": "2.0.0",
  "rules": [
    {"host": "*.wikipedia.org",     "port": 443, "protocol": "tcp", "level": "tls"},
    {"host": "*.stackoverflow.com", "port": 443, "protocol": "tcp", "level": "tls"},
    {"host": "*.readthedocs.io",    "port": 443, "protocol": "tcp", "level": "tls"},
    {"host": "github.com",          "port": 443, "protocol": "tcp", "level": "transport"},
    {"host": "*.github.com",        "port": 443, "protocol": "tcp", "level": "transport"}
  ]
}
```

## Apply a policy at session creation

Pass `--policy` when creating the session. The policy is validated and compiled before the session reaches `Running`; an invalid policy aborts creation.

```bash
sandbox create --name dev --policy ./policy.json
```

To combine with a repository clone:

```bash
sandbox create --name dev \
    --policy ./policy.json \
    --repo https://github.com/myorg/app.git
```

## Update a running session

The `policy update` subcommand swaps the policy on a live session. The new policy fully replaces the old one — no merging. All four enforcement components (CoreDNS, nftables, Envoy, mitmproxy) are re-compiled and hot-reloaded; the session stays `Running`.

```bash
sandbox policy update dev --policy ./new-policy.json
```

The session argument accepts a name or ID:

```bash
sandbox policy update a1b2c3d4e5f6 --policy ./new-policy.json
```

## Create a session with no policy

Without a policy, everything is denied. That is sometimes what you want — an air-gapped sandbox for running untrusted code on data you have already copied in with `sandbox cp`. Just omit `--policy`:

```bash
sandbox create --name air-gapped
```

## Clear the policy on a running session

To drop the current policy from a running session and return it to full deny, use `--clear`:

```bash
sandbox policy update dev --clear
```

`--clear` is idempotent — applying it to a session that already has no policy is a successful no-op. The session's DNS returns `NXDOMAIN` for every query and the gateway drops every outbound packet, exactly like a session created without `--policy`.

## How quickly a policy change takes effect

`sandbox policy update` re-compiles and hot-reloads all four enforcement components without dropping in-flight connections, but a few milliseconds to a few hundred milliseconds may elapse before a given destination behaves per the new policy:

- **CoreDNS, mitmproxy, Envoy static config** — swapped atomically on reload. The old answer set / filter set is replaced as soon as the new config lands.
- **Envoy L3 filter chains (level `http` destinations)** — driven by DNS. Envoy only knows which IPs belong to an L3-inspected domain after CoreDNS resolves that domain and sandboxd rewrites the listener file. For a brand-new L3 rule, the first request races the propagation loop: if the client's TLS handshake begins before Envoy picks up the rewritten listener (typically sub-second), Envoy finds no matching filter chain and drops the connection. Retrying or warming DNS with a prior `getent hosts` / `nslookup` closes the race.
- **nftables allow rules** — follow the same DNS-driven path. An IP literal dialed before CoreDNS has answered for its name is dropped.

The behavior is deliberately fail-closed: an unknown destination is denied, never silently passed through. See [networking → Fail-closed propagation](/concepts/networking/#fail-closed-propagation-for-level-3) for the mechanism.

## L3 limitations

Level `http` (HTTPS inspection) has a few constraints worth calling out:

- **TCP only.** mitmproxy's forward-proxy mode inspects HTTP/HTTPS over TCP. Non-TCP protocols (QUIC/HTTP/3, raw UDP) cannot be inspected at this level. QUIC is blocked by the deny-all firewall since no rule opens UDP/443.
- **Destinations must resolve via the intercepted DNS path.** L3 filter chains are keyed on IPs learned from CoreDNS (or explicit CIDR literals in the policy). A destination that is never resolved through CoreDNS will have no L3 chain and will fail closed. Pre-populating CIDRs in the policy works around this for known IP ranges.
- **Inspection is done with the per-session CA.** The client inside the VM sees the mitmproxy-issued certificate, not the real server's. Applications that pin the real certificate cannot use level `http`; drop them to `tls` or `transport`. See [TLS certificate errors](#tls-certificate-errors) below.
- **No `CONNECT` from the guest.** The mitmproxy forward proxy is bound to loopback inside the gateway container and is not reachable from the VM. The only way to reach it is through the Envoy L3 filter chain's internal CONNECT tunnel. This is deliberate — it keeps the inspection path off the VM's attack surface.

## Verify what is active

`sandbox describe` prints a human-readable summary, including each rule's level, filters, and reason:

```bash
sandbox describe dev
```

`sandbox inspect` returns the full JSON — pipe through `jq` to extract just the policy:

```bash
sandbox inspect dev | jq '.[0].policy'
```

If nothing is applied, `describe` shows `Policy: none` and the `policy` field is absent from `inspect` output.

## Troubleshoot denials

### `NXDOMAIN` on a domain you expect to work

CoreDNS is refusing to resolve it. Either the domain is not in the policy, or the policy does not cover the apex.

Confirm by tailing the CoreDNS logs:

```bash
sandbox logs dev --component coredns
```

Fix by adding the missing domain and updating the policy:

```bash
sandbox policy update dev --policy ./policy.json
```

Remember: `"*.example.com"` does not match `"example.com"` itself.

### `Connection refused` or timeout on a resolved IP

DNS worked, but nftables is dropping the packet. Either the IP has not yet been learned from DNS (race), or the destination is not covered by any rule.

```bash
sandbox health dev
sandbox logs dev --component envoy
```

If you are using a hardcoded IP, list it explicitly as a CIDR rule.

### 599 response from mitmproxy

The request reached mitmproxy (level `http`) but no filter matched. The response body names the reason:

- `"host not in policy"` — no rule covers the request host.
- `"no filter matched <METHOD> <PATH>"` — a rule covers the host but no `http_filters` entry matched.

Inspect the details:

```bash
sandbox logs dev --component mitmproxy
```

Adjust the `http_filters` array and hot-reload with `sandbox policy update`.

### TLS certificate errors

The client is rejecting the per-session CA — typically because the application pins certificates. Drop to `tls` or `transport` for that destination:

```json
{"host": "pinned.example.com", "port": 443, "protocol": "tcp", "level": "tls"}
```

Then update:

```bash
sandbox policy update dev --policy ./policy.json
```

### Inspect the live state

To see exactly which IPs nftables is allowing right now:

```bash
docker exec "sandbox-gw-$(sandbox inspect dev | jq -r '.[0].id')" \
    nft list ruleset
```

## Related reading

- [Policy model](/concepts/policy-model/) — assurance levels and rule shape.
- [Networking](/concepts/networking/) — the enforcement pipeline your policy feeds.
- [Troubleshooting](/guides/troubleshooting/) — broader session-level diagnostics.
- [CLI reference](/reference/cli/) — full flag surface for `create`, `policy update`, `describe`, `inspect`.
