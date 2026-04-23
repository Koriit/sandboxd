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

If you need to block until the new policy is live (e.g. in a setup script that immediately dials an L3 destination), sandboxd emits a `policy_propagated` lifecycle event once CoreDNS, nftables, and Envoy have all reconciled to the latest policy hash:

```bash
# Block until the applied policy's hash has propagated, up to 10 seconds.
sandbox policy status <session> --wait --timeout 10s

# Or observe the event directly.
sandbox events <session> --event policy_propagated --follow
```

`sandbox policy status --wait` polls sandboxd until the session's currently-applied policy hash matches the last `policy_propagated` event — then exits 0. A `--timeout` expiry exits non-zero so scripts can fail loudly rather than race the loop.

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

The fastest way to see *what* got denied and *which layer* denied it is the unified event stream:

```bash
# Every deny from every layer (DNS, Envoy, mitmproxy, deny-logger), live.
sandbox events <session> --decision=deny --follow
```

Each event names the layer (`dns`, `envoy`, `mitmproxy`, `deny-logger`), the decision, and the reason — so you know at a glance whether a call was blocked by DNS allow-list filtering, by the firewall, by Envoy's SNI check, by an mitmproxy `http_filters` mismatch, or by never having matched any rule at all. See [`sandbox events`](/reference/cli/#sandbox-events) for filtering options; the subsections below cover each layer's failure modes in detail.

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

- `"host not in policy"` — no rule covers the request host at any port.
- `"host matched but port <PORT> not in policy"` — at least one rule covers the host, but none at the request's destination port. Add a rule for `(host, PORT)` or change the client to use the port the existing rule covers.
- `"no filter matched <METHOD> <PATH>"` — a rule covers the host and port but no `http_filters` entry matched.

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

## Presets

Presets are reusable host-list templates that expand to v2 policy rules inside the CLI. They encode the allow-lists for common ecosystems (npm, PyPI, cargo, GitHub, ...) so you do not have to spell out a dozen rules from scratch every time you want an agent to `npm install` or `git clone` from a single repo.

Preset expansion happens entirely client-side — the daemon receives the fully-expanded effective policy and never sees preset names or parameters beyond a `source_presets` audit trail attached to the `policy_applied` event. Presets apply on top of (or alongside) an optional `--policy` file; see [`sandbox create --preset`](/reference/cli/#preset-invocations) for the flag reference.

### Built-in catalog

Ten built-ins ship with every CLI release. Run `sandbox policy preset list` to see them, and `sandbox policy preset show <name>` for per-preset metadata.

Unparameterized ecosystem presets:

| Preset | Hosts |
|---|---|
| `npm:` | `registry.npmjs.org` |
| `pypi:` | `pypi.org`, `files.pythonhosted.org` |
| `cargo:` | `crates.io`, `index.crates.io`, `static.crates.io` |
| `goproxy:` | `proxy.golang.org`, `sum.golang.org` |
| `maven:` | `repo1.maven.org`, `repo.maven.apache.org` |
| `gradle:` | `plugins.gradle.org`, `services.gradle.org`, `downloads.gradle.org` |
| `dockerhub:` | `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` |

All of the above emit `http`-level rules with a `GET /**` + `HEAD /**` filter shape. Publishing (`npm publish`, `cargo publish`, ...) is out of scope for these presets — add a dedicated rule for the specific write endpoint if you need it.

GitHub family:

| Preset | Purpose |
|---|---|
| `github:` | Broad GitHub access: `github.com` and `api.github.com` with `ANY /**`, plus read-only access to the asset CDN hosts (`codeload.github.com`, `raw.githubusercontent.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`). |
| `github-repo:repo=OWNER/REPO` | One-repo scope. Required repeatable `repo=owner/name` param — each value contributes its path filters. Covers git-pack URLs, the repo's REST API subtree, archive downloads, and raw-content reads. |
| `github-pr:repo=OWNER/REPO,pr=N` | One-PR scope. Paired repeatable `repo=` / `pr=` params — both required, counts must match. Grants access to a single PR's metadata, comments, and files, nothing more (no git clone/fetch/push, no archive download). |

The authoritative host and filter lists live in the CLI source at `sandboxd/sandbox-cli/src/presets/builtin.rs`; the exact shape of each expansion is also visible on demand via `sandbox policy preset expand '<invocation>'`.

### Invocation syntax

A preset invocation is a single string:

```
<name>[:key=val[,key=val,...]]
```

- `<name>` is one of the preset names in `sandbox policy preset list`.
- Unparameterized presets take a trailing colon with nothing after it: `'npm:'`, `'pypi:'`.
- Parameters are `key=val` pairs separated by commas: `'github-repo:repo=foo/bar,repo=baz/qux'`.
- **Values may not contain raw `,`, `:`, or `=`.** There is no escape mechanism — a forbidden character in a value is a hard error (see [`--preset` errors](/reference/cli/#preset-invocations)). In practice no built-in preset param needs any of those characters; design user presets around param shapes that avoid them.
- Whitespace inside a value is preserved verbatim; no trimming.

Repeated keys stack in invocation order. For `github-repo`, each `repo=` value contributes its own path-filter block; for `github-pr`, `repo=` and `pr=` values are paired positionally (first `repo=` with first `pr=`, second with second, ...).

### User presets

User presets extend the catalog for workflows a built-in does not already cover (internal APIs, mirror hosts, per-environment scopes). Drop one JSON file per preset into the XDG presets directory and the CLI picks it up automatically on the next invocation.

**Directory:**

- `$XDG_CONFIG_HOME/sandboxd/presets/` when `XDG_CONFIG_HOME` is set.
- `$HOME/.config/sandboxd/presets/` otherwise.
- Missing directory is not an error — the CLI treats it as an empty user catalog.

**File format:** JSON only. YAML support is explicitly deferred. One preset per file; the preset's name comes from the `name` field, not the filename (but see the shadowing rule below).

Minimal example — `/home/alice/.config/sandboxd/presets/my-internal.json`:

```json
{
  "name": "my-internal",
  "description": "Internal API access for the billing service",
  "params": [
    {"name": "tenant", "type": "string", "required": true, "repeatable": false}
  ],
  "rules": [
    {
      "host": "${tenant}.api.internal.example.com",
      "port": 443,
      "protocol": "tcp",
      "level": "http",
      "http_filters": [{"method": "GET", "path": "/v1/**"}]
    }
  ]
}
```

Invoked as:

```bash
sandbox create --name dev --preset 'my-internal:tenant=acme'
```

**Templating:** `${param_name}` is substituted into string fields of rules (`host`, `http_filters[*].path`, `reason`). Only string substitution — no conditionals, no iteration. For a repeatable param, each value produces a copy of the enclosing rule with that value substituted.

**Validation rules (enforced at load time):**

- `name` must match `^[A-Za-z0-9_-]+$` — lowercase-only is a convention; dots, slashes, colons, commas, and equals signs are rejected.
- At most one `repeatable: true` param per preset. Multi-repeatable presets (like the built-in `github-pr` with paired `repo=`/`pr=`) are built-in-only — their pairing logic is hand-written CLI code, not a template.
- Param names are unique within a preset.
- `${param}` references in rule templates must name a declared param.

**Error handling:**

- **Malformed file** (invalid JSON, unknown fields, bad name, duplicate params) — warning to stderr, file skipped, sibling files still load.
- **Duplicate `name` across files** — hard error; the CLI refuses to run with both files on disk. Rename or delete one.
- **User preset shadows a built-in** — hard error at the point where the shadowed name is *invoked* (not at load time, so a latent file cannot break unrelated commands). User configs cannot override built-ins under any circumstance. If you ship a `npm.json` user preset, it will fail on use:

  ```
  Error: preset 'npm' is defined by both a built-in and a user file at
    /home/alice/.config/sandboxd/presets/npm.json
  user presets cannot shadow built-ins; rename or delete the user file.
  ```

  Rename the file (and its `name` field) to something that does not collide — e.g. `npm-internal.json` with `"name": "npm-internal"`.

### Host and port uniqueness

Every rule's identity is its `(host, port)` pair. Across the effective policy — the merged union of the `--policy` file and every `--preset` expansion — each `(host, port)` can appear **at most once**. Two rules at the same destination with different levels, filters, or reasons are a contradiction and are rejected.

When a collision is detected, the CLI exits non-zero and prints one block per collision, listing every contributing source with its invocation string (for presets) or file path (for policy files):

```
Error: policy validation failed: duplicate destination (registry.npmjs.org, 443)
  - declared by policy file /tmp/policy.json
  - declared by preset invocation 'npm:' (built-in 'npm')
```

N-way collisions list all N contributing sources, not just the first pair. Multiple distinct collisions in one invocation are reported as one error with several blocks separated by blank lines, so you can fix the whole set in a single pass.

Fixing a collision: either remove the overlapping rule from the policy file, drop one of the overlapping presets, or adjust the policy file's `(host, port)` to something that does not overlap.

### End-to-end workflow

```bash
# 1. Dry-run: see exactly what rules a preset will add to the effective policy.
sandbox policy preset expand 'npm:'

# 2. Apply presets at session creation.
sandbox create --name my-agent \
    --preset 'npm:' \
    --preset 'pypi:'

# 3. Or update an existing session's policy — presets merge on top of any --policy file.
sandbox policy update my-agent \
    --preset 'cargo:' \
    --preset 'github-repo:repo=rust-lang/rustlings'
```

For the full flag surface, see [CLI reference → `sandbox create --preset`](/reference/cli/#preset-invocations), [`sandbox policy update`](/reference/cli/#sandbox-policy-update), and [`sandbox policy preset`](/reference/cli/#sandbox-policy-preset).

## Related reading

- [Policy model](/concepts/policy-model/) — assurance levels and rule shape.
- [Networking](/concepts/networking/) — the enforcement pipeline your policy feeds.
- [Troubleshooting](/guides/troubleshooting/) — broader session-level diagnostics.
- [CLI reference](/reference/cli/) — full flag surface for `create`, `policy update`, `describe`, `inspect`, `policy preset`.
