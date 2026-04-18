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

A policy is a JSON file with a `version` and a `rules` array. Create `policy.json`:

```json
{
  "version": "1.0.0",
  "rules": [
    {
      "destination": "github.com",
      "level": "transport",
      "protocol": "https",
      "reason": "GitHub web and git"
    },
    {
      "destination": "*.github.com",
      "level": "transport",
      "protocol": "https",
      "reason": "GitHub API and subdomains"
    },
    {
      "destination": "registry.npmjs.org",
      "level": "transport",
      "protocol": "https",
      "reason": "npm package registry"
    }
  ]
}
```

Points to note:

- **`"*.github.com"` does not match `"github.com"`** — the apex needs its own rule.
- **Use `transport` for pinned-certificate hosts** (GitHub, npm, PyPI, container registries). HTTPS inspection breaks pinning.
- **Every `http` rule needs an `http_filters` array** — see below.

### An HTTP-filter rule

When you want to restrict which methods and paths the agent can call, use level `http`:

```json
{
  "destination": "api.internal.example.com",
  "level": "http",
  "protocol": "https",
  "http_filters": [
    {"method": "GET",  "path": "/api/v2/read/*"},
    {"method": "POST", "path": "/api/v2/write/*"}
  ],
  "reason": "Internal API — reads and scoped writes only"
}
```

Paths are fnmatch globs: `*` matches any run of characters, `?` matches a single character. A request is allowed if any filter's method and path both match.

### A broader research policy

TLS-verified passthrough for sites where you want hostname verification but do not need HTTP inspection:

```json
{
  "version": "1.0.0",
  "rules": [
    {"destination": "*.wikipedia.org",   "level": "tls", "protocol": "https"},
    {"destination": "*.stackoverflow.com","level": "tls", "protocol": "https"},
    {"destination": "*.readthedocs.io",  "level": "tls", "protocol": "https"},
    {"destination": "github.com",        "level": "transport", "protocol": "https"},
    {"destination": "*.github.com",      "level": "transport", "protocol": "https"}
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
sandbox policy update dev ./new-policy.json
```

The session argument accepts a name or ID:

```bash
sandbox policy update a1b2c3d4e5f6 ./new-policy.json
```

## Create a session with no policy

Without a policy, everything is denied. That is sometimes what you want — an air-gapped sandbox for running untrusted code on data you have already copied in with `sandbox cp`. Just omit `--policy`:

```bash
sandbox create --name air-gapped
```

## Drop all restrictions for debugging

`--unrestricted` creates a session with no policy engine at all — raw outbound connectivity. Use only for diagnosis, never for real workloads.

```bash
sandbox create --name debug --unrestricted
```

To drop the current policy from a running session (returning it to full deny), apply an empty rule set:

```bash
cat > /tmp/empty-policy.json <<'EOF'
{"version": "1.0.0", "rules": []}
EOF
sandbox policy update dev /tmp/empty-policy.json
```

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
sandbox policy update dev ./policy.json
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
{"destination": "pinned.example.com", "level": "tls", "protocol": "https"}
```

Then update:

```bash
sandbox policy update dev ./policy.json
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
