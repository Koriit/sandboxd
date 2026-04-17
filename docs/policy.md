# Policy

This guide explains how to write and apply network policies in claude-sandbox. A policy defines which network destinations a sandbox session can reach, and at what level of inspection.

## Overview

By default, sandbox sessions have no outbound network access -- all traffic is denied. A policy opens up specific destinations by declaring rules that match domains or IP ranges and assign an **assurance level** to each. Anything not explicitly allowed remains blocked.

Policies are enforced by four components working together:

- **CoreDNS** resolves only the domains listed in the policy. Everything else returns NXDOMAIN.
- **nftables** blocks traffic to IPs not covered by the policy.
- **Envoy** routes allowed connections according to their assurance level.
- **mitmproxy** inspects traffic at the highest assurance level, enforcing per-request `(method, path)` filter pairs.

## Assurance levels

Each rule in a policy specifies an assurance level that determines how much visibility and control the sandbox has over the traffic.

### Level 0 -- deny

Traffic is blocked entirely. The destination cannot be reached. This is the default for any destination not covered by a rule, so you rarely need to write explicit deny rules. Useful when you want to override a broader rule (e.g., deny a specific subdomain that a wildcard would otherwise allow).

**Use case:** Blocking a destination that would otherwise be allowed by a wildcard or CIDR rule.

### Level 1 -- transport

Opaque TCP/UDP passthrough. The sandbox allows the connection but does not inspect it. Traffic passes through Envoy as a raw TCP stream to the original destination.

**Use case:** Services that use certificate pinning, non-HTTP protocols, or any destination where inspection is unnecessary. This is the most common level for package registries and source control.

### Level 2 -- tls

TLS-verified passthrough. Envoy extracts the SNI (Server Name Indication) from the TLS ClientHello to verify the destination matches the policy, then forwards the connection directly. No MITM -- the real server certificate is preserved end-to-end.

**Use case:** Destinations where you want to verify the agent is connecting to the expected hostname, but do not need to inspect HTTP request content. Good for APIs with certificate pinning that still need hostname verification.

### Level 3 -- http

Full HTTPS inspection through mitmproxy. The sandbox terminates TLS using a per-session CA certificate, inspects the HTTP request (method, path, headers, body), and enforces fine-grained filter rules. The request is then re-encrypted and forwarded to the destination.

**Use case:** APIs where you want to restrict which HTTP methods or URL paths the agent can access. For example, allowing `GET` on a read-only API but blocking `DELETE`.

At this level the rule must carry `http_filters`: an ordered list of `(method, path)` pairs. A request is allowed only if at least one filter's method **and** path both match the request. Methods are uppercase HTTP verbs (`GET`, `POST`, ...) or the wildcard `ANY`; paths are `fnmatch`-style globs (`*`, `?`, `[...]`). Because the method and path of a filter must both match together, `http_filters` express mixed-pair rules precisely (e.g. "`GET /repos/*` and `POST /user/*`" — not the cartesian product of `{GET, POST} x {/repos/*, /user/*}`).

## Policy file format

A policy is a JSON file with two fields: a `version` string and a `rules` array.

```json
{
  "version": "1.0.0",
  "rules": [
    {
      "destination": "api.example.com",
      "level": "tls",
      "protocol": "https",
      "reason": "Example API access"
    }
  ]
}
```

### Fields

#### `version` (required)

Schema version string in semver format. The current version is `"1.0.0"`. The major version must match -- a policy with version `"2.0.0"` will be rejected by a sandbox that expects `"1.x.x"`.

#### `rules` (required)

An ordered array of rule objects. Each rule has:

| Field | Required | Description |
|-------|----------|-------------|
| `destination` | yes | Domain name, wildcard domain, IP address, or CIDR block |
| `level` | yes | Assurance level: `"deny"`, `"transport"`, `"tls"`, or `"http"` |
| `protocol` | no | Protocol constraint: `"tcp"`, `"udp"`, `"http"`, `"https"`, or `"any"` (default: `"any"`) |
| `http_filters` | conditional | Array of `{method, path}` filter pairs -- required when `level` is `"http"`; not permitted for other levels |
| `reason` | no | Human-readable explanation for the rule |

#### Destinations

Destinations are parsed from plain strings:

- **Domain:** `"github.com"` -- matches the exact domain.
- **Wildcard domain:** `"*.github.com"` -- matches any subdomain of `github.com` (but not `github.com` itself).
- **IP address:** `"140.82.112.4"` -- matches a single IP.
- **CIDR block:** `"140.82.112.0/20"` -- matches an IP range.

Domain names follow standard DNS label rules (alphanumeric and hyphens, no label longer than 63 characters). Wildcards are only supported as the `*.` prefix.

#### HTTP filters

The `http_filters` array is valid -- and required -- only at level `"http"` with an HTTP-capable protocol (`"http"`, `"https"`, or `"any"`). Each element is a single `(method, path)` pair:

- **`method`** -- uppercase HTTP method (`"GET"`, `"POST"`, `"PUT"`, `"DELETE"`, `"PATCH"`, `"HEAD"`, `"OPTIONS"`, `"TRACE"`, `"CONNECT"`) or the wildcard `"ANY"`.
- **`path`** -- an `fnmatch`-style glob such as `"/api/v1/*"`, `"/repos/?/commits"`, or `"/*"`. Use `"/*"` to match any path.

A request is allowed when at least one filter's method and path both match. Because the two fields are paired inside a single filter object, policies can express mixed combinations that independent method/path lists cannot (for example, `GET /read/*` together with `POST /write/*` but nothing else). The `http_filters` array must be non-empty -- an empty list is rejected at compile time because it would make the rule unreachable.

```json
{
  "destination": "api.example.com",
  "level": "http",
  "protocol": "https",
  "http_filters": [
    {"method": "GET", "path": "/api/v1/*"},
    {"method": "POST", "path": "/api/v1/write/*"}
  ],
  "reason": "Read-only API v1 plus scoped POSTs to /write/*"
}
```

### Validation rules

The policy compiler checks these conditions and rejects invalid policies:

- The `version` major version must match the supported schema version.
- `http_filters` can only appear on rules with level `"http"`; other levels must omit the field.
- Level `"http"` rules require a non-empty `http_filters` array and an HTTP-capable protocol (`"http"`, `"https"`, or `"any"`).
- Level `"http"` is not compatible with protocol `"udp"`.
- CIDR blocks must be syntactically valid IPv4 addresses with optional prefix length (0-32).
- Domain names must follow DNS label rules.
- Two rules for the same destination cannot have different assurance levels (this is treated as a contradiction).

## Examples

### GitHub development

Allow GitHub, npm, and PyPI for a typical development workflow. Uses transport-level passthrough since these services use certificate pinning.

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
      "reason": "GitHub API, uploads, codespaces"
    },
    {
      "destination": "*.githubusercontent.com",
      "level": "transport",
      "protocol": "https",
      "reason": "GitHub raw content and assets"
    },
    {
      "destination": "registry.npmjs.org",
      "level": "transport",
      "protocol": "https",
      "reason": "npm package registry"
    },
    {
      "destination": "*.npmjs.org",
      "level": "transport",
      "protocol": "https",
      "reason": "npm registry CDN"
    },
    {
      "destination": "pypi.org",
      "level": "transport",
      "protocol": "https",
      "reason": "Python package index"
    },
    {
      "destination": "files.pythonhosted.org",
      "level": "transport",
      "protocol": "https",
      "reason": "PyPI package downloads"
    }
  ]
}
```

### Locked down

Only allow a specific internal API with method and path restrictions. HTTP-level inspection ensures the agent cannot call dangerous endpoints.

```json
{
  "version": "1.0.0",
  "rules": [
    {
      "destination": "api.internal.example.com",
      "level": "http",
      "protocol": "https",
      "http_filters": [
        {"method": "GET",  "path": "/api/v2/read/*"},
        {"method": "POST", "path": "/api/v2/write/*"}
      ],
      "reason": "Internal API -- GETs to /read/*, POSTs to /write/*"
    },
    {
      "destination": "auth.internal.example.com",
      "level": "http",
      "protocol": "https",
      "http_filters": [
        {"method": "POST", "path": "/oauth/token"}
      ],
      "reason": "Auth server -- token endpoint only"
    }
  ]
}
```

### Research

Broad web access with TLS verification. The sandbox verifies hostnames via SNI but does not inspect HTTP content. Suitable for agents that need to browse documentation or fetch data from many sources.

```json
{
  "version": "1.0.0",
  "rules": [
    {
      "destination": "*.google.com",
      "level": "tls",
      "protocol": "https",
      "reason": "Google search and APIs"
    },
    {
      "destination": "*.stackoverflow.com",
      "level": "tls",
      "protocol": "https",
      "reason": "Stack Overflow"
    },
    {
      "destination": "*.readthedocs.io",
      "level": "tls",
      "protocol": "https",
      "reason": "Documentation sites"
    },
    {
      "destination": "*.docs.rs",
      "level": "tls",
      "protocol": "https",
      "reason": "Rust documentation"
    },
    {
      "destination": "*.wikipedia.org",
      "level": "tls",
      "protocol": "https",
      "reason": "Wikipedia"
    },
    {
      "destination": "github.com",
      "level": "transport",
      "protocol": "https",
      "reason": "GitHub (transport for cert pinning)"
    },
    {
      "destination": "*.github.com",
      "level": "transport",
      "protocol": "https",
      "reason": "GitHub subdomains"
    }
  ]
}
```

## Presets

The sandbox ships with built-in preset rule sets that cover common scenarios. These can be used as starting points for custom policies.

### allow-github

Allows access to GitHub and its subdomains at transport level (opaque passthrough). Includes:

| Domain | Level | Reason |
|--------|-------|--------|
| `github.com` | transport | GitHub web and API |
| `*.github.com` | transport | GitHub subdomains (API, uploads, etc.) |
| `*.githubusercontent.com` | transport | GitHub raw content and assets |

### allow-npm

Allows access to the npm registry and its CDN at transport level. Includes:

| Domain | Level | Reason |
|--------|-------|--------|
| `registry.npmjs.org` | transport | npm package registry |
| `*.npmjs.org` | transport | npm registry CDN |
| `*.npmjs.com` | transport | npm website and API |

## Applying policies

### At session creation

Pass a policy file when creating a new session:

```bash
sandbox create --policy policy.json
```

The policy is validated, compiled, and applied as part of session setup. If the policy is invalid, the session is not created.

```bash
# Create a named session with a custom policy
sandbox create --name my-agent --policy github-dev.json
```

### Updating a running session

Apply a new policy to a session that is already running:

```bash
sandbox policy update <session> new-policy.json
```

The `<session>` argument accepts either the session ID or name. The new policy completely replaces the previous one -- there is no merging. The sandbox re-compiles all component configurations (CoreDNS, nftables, Envoy, mitmproxy) and hot-reloads them without restarting the session.

```bash
# Update by session name
sandbox policy update my-agent locked-down.json

# Update by session ID
sandbox policy update a1b2c3d4-5678-... research.json
```

### Inspecting the currently applied policy

To confirm which policy is active on a running session, use `sandbox describe` for a human-readable summary or `sandbox inspect` for the full JSON representation:

```bash
# Human-readable rule listing, including http_filters and reasons
sandbox describe my-agent

# Full JSON including the policy object — pipe into jq for further processing
sandbox inspect my-agent | jq '.[0].policy'
```

When no policy has been applied, `sandbox describe` shows `Policy: none` and the `policy` field is omitted from `sandbox inspect` output. See [cli-reference.md § sandbox inspect](cli-reference.md#sandbox-inspect) and [§ sandbox describe](cli-reference.md#sandbox-describe) for the full output layout.

## How it works

When a policy is applied, the sandbox compiles it into four separate configurations -- one for each enforcement component. Here is what happens at each layer:

### 1. CoreDNS -- DNS filtering

CoreDNS receives a list of allowed domains extracted from the policy. When the agent resolves a domain name:

- **Allowed domain:** CoreDNS forwards the query to upstream resolvers and returns the real answer. The resolved IP addresses are reported to sandboxd for nftables rule injection.
- **Unlisted domain:** CoreDNS responds with NXDOMAIN. The agent sees the domain as non-existent.

### 2. nftables -- IP-level firewall

nftables rules are generated from the policy's CIDR destinations and from IP addresses resolved by CoreDNS at runtime. The firewall operates with a default-deny posture:

- **Allowed IPs:** Traffic is forwarded to Envoy for routing.
- **Everything else:** Dropped or rejected at the network level.

### 3. Envoy -- connection routing

Envoy receives all TCP connections that pass through the firewall and routes them based on the assurance level:

- **Level 1 (transport):** TCP passthrough to the original destination. No inspection.
- **Level 2 (tls):** Envoy extracts the SNI from the TLS ClientHello, verifies it matches a policy rule, and forwards the connection to the original destination.
- **Level 3 (http):** Envoy forwards the connection to mitmproxy for HTTP inspection.

### 4. mitmproxy -- HTTP inspection

mitmproxy handles only level 3 (http) traffic. It terminates TLS using the per-session CA certificate, inspects the HTTP request, and enforces the rule's `http_filters`:

- **Filter match:** The request method and path are compared against each `(method, path)` filter in any rule matching the request host. A filter matches when its method equals the request method (or is `ANY`) **and** its path-glob matches the request path.
- **Pass:** If at least one filter matches, the request is forwarded to the real destination.
- **Reject:** If no filter matches -- or the host is not covered by any rule -- the request is rejected with a 599 response whose body names the reason (`"host not in policy"` or `"no filter matched <METHOD> <PATH>"`).

## Troubleshooting

### "Connection refused" or timeout

The destination is not in the policy, or the firewall is blocking the IP.

**What to check:**
1. Verify the domain is listed in your policy file.
2. If using a CIDR rule, confirm the destination IP falls within the specified range.
3. Check that the policy was applied successfully:
   ```bash
   sandbox health <session>
   ```

### "NXDOMAIN" when resolving a domain

CoreDNS is blocking DNS resolution because the domain is not in the policy.

**What to check:**
1. Verify the exact domain is in your policy. Note that `"*.github.com"` does **not** match `"github.com"` itself -- you need both if you want to allow both the apex domain and subdomains.
2. Check CoreDNS logs to confirm the query is being denied:
   ```bash
   sandbox logs <session> --component coredns
   ```

### 599 response from mitmproxy

The request reached mitmproxy (level 3) but no `http_filters` entry matched.

**What to check:**
1. Verify the rule's `http_filters` include a `(method, path)` pair that matches the request. Method must equal the request method exactly (or be `"ANY"`), and the glob in `path` must match the full request path (for example `"/api/v1/*"` matches `/api/v1/anything` but not `/api/v2/...`).
2. If the deny body says `"host not in policy"`, the request host is not covered by any rule. If it says `"no filter matched <METHOD> <PATH>"`, the host matched but no filter did -- adjust the filter list accordingly.
3. Check mitmproxy logs for the denial details:
   ```bash
   sandbox logs <session> --component mitmproxy
   ```

### TLS certificate errors

The application is rejecting the per-session CA certificate used by mitmproxy for level 3 inspection.

**What to check:**
1. If the application uses certificate pinning, switch the rule to level `"tls"` (level 2) or `"transport"` (level 1) to bypass inspection.
2. If the CA was not injected properly, check the session health and creation logs:
   ```bash
   sandbox health <session>
   ```

### Debugging what a policy allows

To understand what your policy permits, you can:

1. **Check gateway logs** to see which connections are allowed or denied:
   ```bash
   sandbox logs <session> --follow
   ```

2. **Check CoreDNS logs** to see which DNS queries are answered or blocked:
   ```bash
   sandbox logs <session> --component coredns
   ```

3. **Check Envoy logs** to see how connections are being routed:
   ```bash
   sandbox logs <session> --component envoy
   ```

4. **Inspect nftables rules** in the gateway to see which IPs are allowed:
   ```bash
   docker exec sandbox-gw-{session_id} nft list ruleset
   ```
