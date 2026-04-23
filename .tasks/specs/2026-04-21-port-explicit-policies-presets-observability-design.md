# Port-explicit policies, preset expansion, and policy observability

## Summary

This spec revises the network policy model to make ports explicit, replaces
the `Policy::unrestricted()` escape hatch with a CLI-only preset system, and
introduces a unified events surface that covers both per-layer traffic
decisions and gateway lifecycle state. It builds on the now-landed L3 spec
(`2026-04-19-l3-envoy-mitmproxy-flow-design.md`, merged in M9-S18..S20) and
amends a small number of its implemented decisions — listed in one place at
the end of this doc.

Three deliverables, one document. Work-item decomposition is deferred; this
spec describes the target state and the component changes required, not the
implementation plan.

## Context

### Why this is needed

The current policy model conflates port and protocol. A rule declares a
`destination` (host, IP, or CIDR) and a `protocol` (`tcp`, `udp`, `http`,
`https`, `any`); the compiler then infers a port set from the protocol
(hardcoded `dport { 80, 443 }` in nftables for the HTTP-ish values). This
has four concrete problems:

1. **Non-standard ports are unreachable.** A rule cannot allow `:8080`,
   `:5432`, `:6379`, or anything outside the implicit `{80, 443}` set.
2. **Same host, different levels-per-port is inexpressible.** A workload
   that needs `redis:6379` at `transport` and `host:443` at `http` on the
   same host cannot state that.
3. **`protocol: any`, `http`, `https` are ports-masquerading-as-protocols.**
   Policy readers have to know the implicit expansion to audit a rule.
4. **The `*` wildcard host + `Policy::unrestricted()` are escape hatches.**
   They exist to paper over the first problem and to serve a discovery use
   case (what does my workload reach?) that is better served by structured
   deny events.

The L3 spec's "no port predicate on L3 chain" decision was a symptom of the
same model gap — the compiler had no port to predicate on.

### Why now

The L3 spec (CONNECT-tunneling from Envoy to mitmproxy) landed in M9-S18..S20.
That work touched the Envoy filter-chain compilation path and added structured
`access_log` emission on L3 `tcp_proxy` filters (commit `8cacf87`). Landing
port-explicit rules next keeps filter-chain compiler work on a single cadence
and avoids a port-agnostic L3 interim state lingering in production longer
than necessary.

The observability piece lands in the same spec because the deny-logger
component interacts with the same nftables pipeline that the port-explicit
rules touch, and because the L3 landing leaves a known gap (direct-IP denials
are silent) that the deny-logger closes. The spec also extends the now-
partial Envoy `access_log` (L3-only today) to cover L1 and L2 and wires
sandboxd-side ingestion on top.

### Operating constraints

Two constraints inherited from the L3 spec apply unchanged here.

**No external backwards compatibility required.** sandboxd has no
production users yet. The policy JSON schema bump (`1.0.0` → `2.0.0`) is a
hard break: old policy files do not parse against the new compiler. Running
sessions at upgrade time stop/start rather than migrating in place.

**Connection preservation during policy changes is required.** xDS-based
Envoy reconfiguration (from the L3 spec) continues to preserve in-flight
connections across policy updates. This spec does not regress that property;
filter-chain additions from the port predicate use the same LDS-over-
filesystem delivery mechanism.

## Target design

### Sequencing

The L3 spec has landed (M9-S18..S20). This spec builds on top of it in a
single daemon + gateway release that introduces:

- `v2.0.0` policy schema (hard break on parse)
- Port predicate added to all filter chains (L1, L2, L3 — the L3 chain
  gaining a port predicate is an amendment to the landed L3 implementation)
- `deny-logger` component in the gateway container
- Envoy `access_log` extended to L1 and L2 chains (L3 access_log already
  present per commit `8cacf87`); sandboxd-side ingestion, session tagging,
  and ring-buffer push added across all three chains
- Structured event emission from CoreDNS plugin and mitmproxy addon
- `sandbox events` CLI + HTTP endpoint
- `sandbox policy preset` CLI subcommand

No phased rollout within the spec. One release, one migration event (stop
and restart existing sessions).

---

## Part 1 — Port-explicit policy rules

### Rule shape

A policy is a JSON document with `version: "2.0.0"` and an ordered `rules`
array. Each rule is:

```json
{
  "host": "api.example.com",
  "port": 443,
  "protocol": "tcp",
  "level": "http",
  "http_filters": [{"method": "GET", "path": "/v1/*"}],
  "reason": "Example API access"
}
```

| Field | Required | Type | Values |
|---|---|---|---|
| `host` | yes | string | domain · `*.domain` subdomain wildcard · IPv4 · IPv4 CIDR |
| `port` | yes | integer | 1–65535, no ranges, no lists |
| `protocol` | yes | string | `tcp` · `udp` |
| `level` | yes | string | `deny` · `transport` · `tls` · `http` |
| `http_filters` | iff `level: http` | array | non-empty list of `{method, path}` pairs (unchanged shape) |
| `reason` | no | string | free-form |

**Removed from the v1 schema:**

- Bare-`*` host. Subdomain wildcards `*.example.com` remain valid.
- `protocol: any`, `protocol: http`, `protocol: https`. `protocol` is now
  strictly an L4 value.
- `Policy::unrestricted()` helper. The equivalent "MITM everything on 80
  and 443" posture is now expressed by writing two explicit `host: "*"`-less
  rules — which is not possible (no `*` host), so the posture is
  unreachable by design. Discovery workflows migrate to deny-log-driven
  iteration (see Part 3).

**Identity and uniqueness.** A rule's identity is the `(host, port)`
tuple. The *effective* policy (policy file rules plus preset expansions —
see Part 2) must contain at most one rule per `(host, port)`. Any duplicate
is a hard validation error, regardless of whether the duplicates differ on
`protocol`, `level`, or other fields.

**Error shape for duplicates:**

```
policy validation failed: duplicate destination (api.github.com, 443)
  - declared by preset 'github'
  - declared by policy file /path/to/policy.json
```

The error names each source (policy file path, preset invocation string,
or "built-in preset <name>") so the operator can identify and resolve the
collision.

**Validation additions beyond v1:**

- `port` must be an integer in `[1, 65535]`.
- `protocol` must be `tcp` or `udp` exactly; other values are rejected.
- `host` matching a bare `*` is rejected.
- Subdomain wildcards still follow DNS label rules.
- All v1 validation rules (CIDR syntax, `http_filters` required iff
  `level: http`, etc.) remain.

### Compiler consequences

**nftables** (`sandbox-core/src/policy.rs`, `sandbox-core/src/gateway.rs`,
`sandbox-core/src/dns_propagation.rs`):

- The hardcoded `dport { 80, 443 }` in `sandbox_policy` rule generation is
  removed. Each allow rule carries the explicit port from its policy rule.
- Per-destination rules use **nftables concat sets** keyed on
  `ipv4_addr . inet_service` (one set per L4 protocol —
  `policy_allow_tcp`, `policy_allow_udp`). The compiler emits set elements
  of the form `<ip> . <port>` per allowed destination. No rule explosion
  for multi-port allow lists.
- DNS→policy propagation propagates `(ip, port)` tuples into the relevant
  concat set. The DNS cache itself (CoreDNS `ReportEntry`) is unchanged —
  it stays a pure `(domain, ip, ttl)` stream. The `(ip, port)` join
  happens in sandboxd when it computes the effective nftables and Envoy
  state from `policy + ip_cache`.
- `compile_nftables` (`policy.rs:755-862`), `generate_dnat_ruleset`
  (`gateway.rs:982-1011`), `generate_domain_ip_rules`
  (`dns_propagation.rs`), and `policy_distributor` all change together.

**Envoy** (`sandbox-core/src/policy.rs`):

- Filter chains gain a `destination_port` predicate — the `UInt32Value`
  field on `FilterChainMatch` — matching the rule's port.
- L1, L2, L3 chains all grow this predicate. This is the **specific
  amendment to the L3 spec's "No port predicate on any L3 chain"
  decision.** L3 chains are still keyed on destination identity
  (prefix_ranges for resolved IPs or CIDR) **and** the rule's port.
- Policy-allowed destinations that a rule does not specify cannot be
  reached by a policy rule at all — not because of the port predicate, but
  because the rule shape requires a port.
- The bare-`*` `default_filter_chain` (used today when an L3 rule has
  `destination: "*"`) and the bare-`*` L1 catch-all chain become
  unreachable code once bare-`*` is rejected at validation. The compiler
  branches that generate them are removed. Unmatched connections are
  closed — consistent with the L3 spec's stated fail-closed posture for
  non-`*` traffic.

**CoreDNS plugin** (`networking/coredns-plugin/`):

- Unchanged at the query-handling level — DNS allow/deny is still keyed on
  hostname. The port is not a DNS concern.
- The plugin's IP-report stream to sandboxd still reports `(domain, ip,
  ttl)` tuples; the port attachment happens in sandboxd when it computes
  nftables and Envoy configs from the policy + IP cache.

**mitmproxy** (`networking/mitmproxy/`):

- Today `_check_request` in `policy_addon.py` matches only on `host`,
  `method`, and `path` — there is no port check. The rule shape read by
  the addon is `{host, filters: [{method, path}, ...]}` with no port
  field (`policy_addon.py:11-29, 161-196`).
- v2 adds a port dimension. `PolicyCompiler::compile_mitmproxy`
  (`policy.rs:1372-1393`) emits `port` in each `MitmproxyRule`; the addon
  consults `flow.request.port` (not the CONNECT authority parsed from
  `pretty_host`) and compares. This is a new match field, not a
  replacement of implicit 80/443 — that implicit match never existed in
  the addon.

**Path matcher semantics** (applies to `http_filters.path` across the
compiler and the mitmproxy addon):

- v1 today uses Python `fnmatch.fnmatchcase` (shell glob, `*` spans path
  separators). This is too loose for precise path-scoped presets like
  `github-pr` — a pattern like `/pulls/PR*` would match
  `/pulls/PR/attacker-crafted-subpath`.
- v2 switches to **per-segment glob with a `**` recursive wildcard**:
  - `*` matches any run of characters **within a single segment**
    (does not cross `/`).
  - `**` matches any run of characters including `/` (recursive; spans
    segments).
  - `?` matches a single character, not `/`.
  - All other characters are literal.
- Both the compiler's validation (`http_filters` shape) and the
  mitmproxy addon's matcher use the same semantics. The addon's
  `fnmatch.fnmatchcase` call is replaced by a small helper that
  implements the glob above; reference implementations in other projects
  (Express.js `path-to-regexp`, Go `path.Match`) are ample precedent.
- v1 patterns written with fnmatch semantics may be subtly different
  under v2 (e.g., `/api/*` in v1 matches `/api/v1/users`; in v2 it
  matches only one segment deeper — `/api/v1`). Operators migrating
  policies review `http_filters` paths as part of the v2 rewrite.
- Filter paths match against the request's URI path **excluding** the
  query string. `mitmproxy.http.Request.path` returns the full
  request-target (path + query), so the addon strips `?<query>` before
  matching. A filter like `/info/refs` therefore matches a request for
  `/info/refs?service=git-upload-pack` — the concrete case required by
  git's smart-HTTP clone. Preset authors write filter paths without
  query strings; logged events echo the full request path so operators
  still see the exact URL the client asked for.

### Schema bump and migration

Policy JSON `version` field changes from `"1.0.0"` to `"2.0.0"`.

- **Old policy files**: hard-reject on parse with a clear error message:

  ```
  policy file uses schema v1.0.0, which is no longer supported.
  v1 conflated port and protocol; v2 requires an explicit port per rule.
  See .tasks/specs/2026-04-21-port-explicit-policies-presets-observability-design.md
  for migration examples.
  ```

- **No auto-migration path.** v1 `protocol: https` could be migrated to v2
  `protocol: tcp, port: 443`, and `protocol: http` to `tcp, port: 80`, but
  this silent promotion hides the exact decision the v2 schema is trying to
  make explicit. Operators rewrite their policy files.

- **Session state**: policy is persisted in `sessions.db` in the
  normalized tables `session_policies`, `policy_rules`, and
  `policy_rule_http_filters` (migration V003). It is **not** a JSON blob
  in a `SessionConfig` column — the CLAUDE.md "JSON blob fields" rule
  doesn't apply to this path. The v2 release ships migration **V004**:

  1. Alter `policy_rules.protocol` to tighten its CHECK constraint to
     `CHECK (protocol IN ('tcp', 'udp'))`. (SQLite limitation: this is
     implemented via table-copy — create `policy_rules_new` with the new
     CHECK, copy migratable rows, drop old, rename.)
  2. Add `policy_rules.port INTEGER NOT NULL CHECK (port BETWEEN 1 AND
     65535)`. Also via table-copy.
  3. **v1-shaped rows (containing `http`/`https`/`any` protocols or no
     port) are deleted during the copy.** Affected sessions end up with
     no policy attached; the user re-applies via `sandbox policy update`.
     A `lifecycle` event `policy_reset_on_upgrade` is emitted on first
     access to each affected session, naming the session and the
     previous policy's rule count for audit.
  4. `protocol_from_column` in `sandbox-core/src/store.rs:750-763` is
     narrowed to reject `http`/`https`/`any` (dead code after V004 but
     defended).
  5. **`http_filters.path` semantic shift is moot under delete-all.**
     v1 `http_filters` lived only on `level: http` rules, and v1's
     `level: http` validator required `protocol ∈ {http, https, any}`;
     every such row is deleted in step 3. No v1-authored
     `http_filters.path` value survives V004, so the v1 → v2 matcher
     semantic shift (fnmatch full-path glob → per-segment glob with
     `**`) cannot silently change the meaning of an existing rule.
     Operators writing v2 policies from scratch follow Part 1 /
     "Path matcher semantics".

  No rollback. This is a one-way migration, consistent with the no-BC
  constraint.

- **Gateway config**: Envoy bootstrap + listener files are regenerated per
  session from scratch. No on-disk gateway migration.

### Discovery workflow (what replaces `unrestricted`)

The `Policy::unrestricted()` helper existed to answer "what does this
workload reach?". Its new replacement is deny-log-driven iteration (see
Part 3):

1. Start the session with an empty policy (or with stacked presets
   covering the ecosystems the operator already knows the workload needs).
2. Run the workload. Failed connection attempts produce events in the
   `dns`, `deny-logger`, `envoy`, and `mitmproxy` streams.
3. `sandbox events --session=<id> --decision=deny --follow` shows every
   denial in real time, naming the host, port, protocol, and layer.
4. Operator adds rules (or additional presets) for each denial they want
   to allow; applies the updated policy via `sandbox policy update`.
5. Repeat until the workload runs clean.

The final policy produced this way is the policy the operator ships. There
is no "wide open for discovery, tighten later" mode — the iteration is the
tightening.

---

## Part 2 — Preset expansion

### Semantics

Presets are **fully client-local macros** that expand to rules in the CLI
(`sandbox-cli`) before the policy is sent to the daemon. The daemon has
no awareness of presets — it receives effective rule sets over the
existing `POST /sessions` and `POST /sessions/{id}/policy` endpoints.
Preset definitions are either:

- **Built-in**: embedded in the `sandbox-cli` binary (compile-time Rust
  constants or an embedded JSON blob via `include_str!`). Changes ship
  with CLI releases.
- **User-configured**: loaded by the CLI at invocation time from
  `$XDG_CONFIG_HOME/sandboxd/presets/` (falls back to
  `$HOME/.config/sandboxd/presets/` per the XDG base-dir spec when
  `XDG_CONFIG_HOME` is unset).

Presets exist to reduce boilerplate when authoring ecosystem-standard
allow lists. They never persist on the daemon side as "presets"; the
daemon sees only concrete rules.

**Merge and validation** (all client-side):

1. CLI loads the policy file (may be empty, except for the schema
   header).
2. CLI loads built-in preset definitions (compiled in) and user preset
   definitions (from the XDG directory; missing directory is treated as
   empty with no error).
3. For each `--preset '<name>:<args>'` flag, CLI expands the invocation
   to a set of concrete v2 rules.
4. CLI unions the policy file rules and all expanded rules.
5. CLI validates uniqueness: one rule per `(host, port)` across the
   union. Duplicates error with source names (see Part 1 error shape).
6. CLI runs standard rule-level validation on each rule in the union.
7. CLI sends the validated effective policy plus a `source_presets:
   [string]` array (the list of original `--preset` invocation strings)
   to the daemon. The daemon stores the effective policy and records
   `source_presets` on the resulting `policy_applied` lifecycle event
   (see Part 3).

The daemon still re-validates the incoming policy (uniqueness, rule
shape) as a defensive check. It does not parse or expand presets.

### CLI shape

**Application of presets** — via flags on `sandbox start` and `sandbox
policy update`:

```bash
sandbox start --policy p.json \
  --preset 'cargo:' \
  --preset 'pypi:' \
  --preset 'github-repo:repo=foo/bar,repo=baz/qux'

sandbox policy update <session-id> --policy p.json \
  --preset 'cargo:' \
  --preset 'github-pr:repo=foo/bar,pr=123'
```

- `--preset '<name>:<key>=<val>,<key>=<val>,...'` — repeatable flag.
- Each flag invocation represents one preset application; the same preset
  can be applied twice with different params.
- Params with no args use trailing colon: `'cargo:'`.
- Multi-value params use repeated `key=val` pairs with the same key:
  `'github-repo:repo=foo/bar,repo=baz/qux'`.
- Comma separates params; colon separates name from params. Values
  containing `,` or `:` or `=` must be avoided in preset params — preset
  design ensures simple values (repo names, scopes, package names).

**Discovery and inspection** — via `sandbox policy preset` subcommand.
**All read-only subcommands are client-local** — they do not touch the
daemon:

```bash
sandbox policy preset list              # list all presets (built-in + user-configured)
sandbox policy preset show <name>       # print a preset's metadata + param schema
sandbox policy preset expand '<name>:<args>'
                                        # print the rules a preset invocation would produce
                                        # (for debugging / review before apply)
```

`expand` is a pure dry-run: it reads built-in + user presets, expands the
given invocation, and prints the resulting JSON rules to stdout. No
network I/O, no daemon dependency.

**CLI-side preset loading errors:**

- A malformed user preset file produces a warning on stderr and the
  preset is skipped. Other presets continue to load.
- A `--preset` invocation naming an unknown preset is a hard error: the
  CLI exits non-zero before contacting the daemon.
- Missing XDG preset directory is treated as empty (no error). Unreadable
  directory metadata (EACCES/EIO) produces a warning on stderr and the
  user preset set is empty.

No daemon events fire for these cases — they are CLI-side and never
reach the daemon.

### Built-in presets

Each built-in preset is defined in the CLI source with an explicit
host/port/level list. Rules below are illustrative; the authoritative
definitions live in `sandbox-cli`. Changes to built-in presets require
a CLI release.

#### Unparameterized ecosystem presets

These cover the public surface of their ecosystem. They do not take
parameters.

| Preset | Hosts | Level | `http_filters` |
|---|---|---|---|
| `npm` | `registry.npmjs.org` | `http` | `GET /**`, `HEAD /**` |
| `pypi` | `pypi.org`, `files.pythonhosted.org` | `http` | `GET /**`, `HEAD /**` |
| `cargo` | `crates.io`, `static.crates.io`, `index.crates.io` *(verified against documented endpoints, Rust 1.70+ sparse index; see known gaps for fixture + drift-detection test)* | `http` | `GET /**`, `HEAD /**` |
| `goproxy` | `proxy.golang.org`, `sum.golang.org` | `http` | `GET /**`, `HEAD /**` |
| `maven` | `repo1.maven.org`, `repo.maven.apache.org` | `http` | `GET /**`, `HEAD /**` |
| `gradle` | `plugins.gradle.org`, `services.gradle.org`, `downloads.gradle.org` | `http` | `GET /**`, `HEAD /**` |
| `dockerhub` | `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | `http` | `GET /**`, `HEAD /**` |
| `github` | `github.com`, `api.github.com` | `http` | `ANY /**` |
| `github` | `codeload.github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com`, `release-assets.githubusercontent.com` | `http` | `GET /**`, `HEAD /**` |

All rules: `protocol: tcp`, `port: 443`.

**Why `http` (not `tls`).** `tls` terminates verification at SNI and
bypasses mitmproxy entirely — no per-request log, no method visibility.
`http` routes through mitmproxy with its per-session injected CA (that's
how L3 works today; non-pinning origins don't block interception), so
every request becomes a structured event in the observability stream
(see Part 3). Operators can audit "what did my agent actually do in this
session". Method-level filters are also available at `http` and not at
`tls`.

**Two method-filter postures** across the built-in presets:

- **Consume-only ecosystems** (`npm`, `pypi`, `cargo`, `goproxy`,
  `maven`, `gradle`, `dockerhub`) use `GET /**` + `HEAD /**`. The happy
  path is reading packages/images. Publishing from a sandbox is
  out-of-scope; operators who need it add an explicit rule for the
  specific write endpoint.
- **Interactive GitHub surfaces** (`github.com`, `api.github.com` on
  the `github` preset) use `ANY /**`. GitHub's legitimate workflows
  routinely include writes (POST to git-receive-pack for push, POST to
  REST API for issues/comments/PRs, POST to OAuth endpoints for
  `gh auth`, etc.). Enumerating every write path defeats the purpose of
  a broad preset — `github` is the "give my agent general GitHub
  access" preset; operators who want narrow scope use `github-repo` or
  `github-pr` (below). GitHub's asset CDN hosts
  (`codeload.github.com`, `*.githubusercontent.com`) stay GET/HEAD
  only: no legitimate workflow POSTs to a tarball CDN.

The tradeoff `ANY /**` accepts: no method-level enforcement on the
interactive hosts. What it *keeps*: every request — including every
POST, PUT, PATCH, DELETE — is logged by mitmproxy with full URL, method,
and response metadata. A compromised agent cannot hide its writes; the
audit trail names each one. If method-level enforcement is required,
`github-repo` / `github-pr` provide it with narrow path filters.

**Accepted tradeoff — mitmproxy in the large-blob path.** `http` level
routes traffic through mitmproxy, which buffers and re-emits HTTP
bodies. For Docker image layers, Gradle distributions, release assets,
and other multi-MB/GB blobs, this adds latency and memory footprint
compared to `tls` passthrough. The spec accepts that cost across the
board in exchange for uniform observability; if large-blob latency
becomes a real problem for a specific preset, that preset's blob-host
entry can be downgraded to `tls` individually.

No wildcard subdomains. Every host is explicit. If a tool needs a host
not in the list (e.g. a mirror), the operator adds it to the policy file
alongside the preset.

#### Parameterized github presets

`github-repo` and `github-pr` exist because GitHub's API and git protocol
surfaces are path-scoped per repo. They narrow an otherwise-wide
`github` preset to HTTP-level filtering on specific paths.

**`github-repo`** — params: `repo=owner/name` (repeatable, at least one).

Each `repo=` value is substituted as a whole into the path templates
(`${repo}` expands to `owner/name`). The preset emits rules whose union
covers the paths git and the GitHub API use for that repo. Illustrative
(exact shapes in the CLI source):

- `github.com:443` `tcp http` with `http_filters`:
  - `GET /${repo}.git/info/refs`, `HEAD /${repo}.git/info/refs`
  - `POST /${repo}.git/git-upload-pack` (git fetch/clone reads)
  - `POST /${repo}.git/git-receive-pack` (git push writes)
  - Also the no-`.git` URL form GitHub also serves: `GET /${repo}/info/refs`,
    `POST /${repo}/git-upload-pack`, `POST /${repo}/git-receive-pack`.
- `api.github.com:443` `tcp http` with `http_filters`:
  - `ANY /repos/${repo}/**`
  - `GET /user`, `GET /rate_limit` (always-needed probes).
- `codeload.github.com:443` `tcp http` with `GET /${repo}/**`,
  `HEAD /${repo}/**`.
- `objects.githubusercontent.com:443` `tcp tls` — release asset URLs
  are signed and opaque; `tls` is the tightest workable level.
- `release-assets.githubusercontent.com:443` `tcp tls` — same reasoning
  as `objects.githubusercontent.com` (signed, opaque release-asset
  URLs).
- `raw.githubusercontent.com:443` `tcp http` with `GET /${repo}/**`,
  `HEAD /${repo}/**`.

Multiple `repo=` params stack: each repo contributes its path filters to
the same per-host rule's `http_filters` array. The `(host, port)`
uniqueness rule still holds — one rule per host, with a combined filter
set.

**Path patterns use the per-segment glob with `**` recursive wildcard**
defined in Part 1 / "Path matcher semantics". `/repos/${repo}/**` after
substitution matches the whole repo subtree; a single `*` would only
match one segment deeper. The three-segment git paths like
`/${repo}.git/git-upload-pack` intentionally avoid `**`; the depth is
part of the allow-list.

**`github-pr`** — params: `repo=owner/name` and `pr=N` (paired; both
required; repeated together for multiple PRs — each `(repo, pr)` pair
contributes its own filter set).

Each pair substitutes both `${repo}` (owner/name) and `${pr}` (the PR
number) into the path templates. Stricter subset of `github-repo`;
filters target only the PR surface:

- `api.github.com:443` `tcp http` with `http_filters`:
  - `ANY /repos/${repo}/pulls/${pr}`
  - `ANY /repos/${repo}/pulls/${pr}/**` (PR sub-resources: `/files`,
    `/reviews`, `/commits`, `/requested_reviewers`)
  - `ANY /repos/${repo}/issues/${pr}` (PR comments live under the
    issues tree)
  - `ANY /repos/${repo}/issues/${pr}/**`
  - `GET /user`, `GET /rate_limit`.
- `github.com:443` `tcp http` with read-oriented filters for the PR UI
  paths (`GET /${repo}/pull/${pr}`, `GET /${repo}/pull/${pr}/**`).
- No git-pack rules — `github-pr` does not grant clone/fetch/push.
- No archive download; no unrestricted raw file access.

Intended use: granting an agent access to exactly one PR's metadata,
comments, and files, without broader repo or account access.

**Not covered by `github-repo` / `github-pr`**: **Git LFS**. LFS needs
additional rules for `lfs.github.com` (or
`github-cloud.githubusercontent.com`) plus the `/info/lfs/**` paths on
the main `github.com` host. Repos with LFS content will fail silently
during `git lfs smudge` if only `github-repo` is applied. This is a
known gap (see "Known gaps / deferred decisions"); a future `github-lfs`
preset or a `lfs=true` param on `github-repo` closes it.

### User-configured presets

Loaded by the CLI at invocation time from
`$XDG_CONFIG_HOME/sandboxd/presets/*.json` (or
`$HOME/.config/sandboxd/presets/*.json` when `XDG_CONFIG_HOME` is unset).
One file per preset. File schema:

```json
{
  "name": "my-internal-api",
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

**Templating:** `${param_name}` is substituted into string fields of
rules. Only string substitution; no conditionals, no iteration. For a
repeatable param, each occurrence of the param value produces a copy of
the enclosing rule with that value substituted.

**User presets may declare at most one repeatable param.** Multi-
repeatable presets (like the built-in `github-pr` with paired
`repo=`/`pr=`) are built-in-only: their pairing logic lives in the CLI's
Rust code, not in a template. If a user preset needs paired-repeatable
semantics, the use case is valuable feedback for a future built-in, not a
template extension. The CLI's preset loader rejects user files with
more than one repeatable param.

**Namespacing:** if a user-configured preset has the same name as a
built-in, the CLI refuses the invocation with a clear error naming both
sources. User configs cannot shadow built-ins. This is deliberately
stricter than "warn and pick one": a shadowed name is a silent
correctness bug — `--preset npm:` hitting a different rule set than the
operator expects because a user file happens to be named `npm.json` is
the exact class of error this spec's "explicit everything" theme exists
to prevent.

**Loading errors:** a malformed preset file produces a warning on stderr
and the preset is skipped. Other presets continue to load. No daemon
event fires — these are CLI-side only.

### Preset versioning

Preset definitions have no version field. Changes to a built-in preset
ship with CLI releases; changes to a user-configured preset are effective
on the next CLI invocation. Running sessions are unaffected — preset
expansion happens in the CLI at apply time, and the session carries only
the expanded rules on the daemon side.

---

## Part 3 — Policy observability

### Event surface

The observability surface is a unified event stream across all layers
that make policy decisions, plus gateway lifecycle state. Events are
JSON objects, one per decision or state change, emitted by the layer
that made the decision and collected by sandboxd.

**No cross-layer correlation.** Each event stands on its own,
describing its layer's verdict on its own terms. A single connection
attempt produces a chain of events across layers; the operator reads the
chain chronologically. This is a deliberate choice over a per-connection
aggregated record — correlating four async sources by (session, 4-tuple,
time-window) was evaluated and judged to be ~40 hours of implementation
+ ongoing fragility, for modest value over the per-layer raw stream.

### Event shape

Every event shares a common envelope:

```json
{
  "timestamp": "2026-04-21T12:34:56.789Z",
  "session": "<session-id>",
  "layer": "<layer-name>",
  "event": "<event-name>",
  ...layer-specific fields...
}
```

- `timestamp`: RFC 3339 timestamp with millisecond precision (UTC).
- `session`: session ID. Lifecycle events that precede session creation
  (daemon boot, config load) use the empty string.
- `layer`: one of `dns`, `deny-logger`, `envoy`, `mitmproxy`,
  `lifecycle`.
- `event`: the specific event type within the layer.
- Layer-specific fields as documented below.

**Session-ID attribution is sandboxd's job, not each component's.** The
four traffic-layer components emit raw events carrying either a 5-tuple
or a source IP address, without a session field. sandboxd's event
ingestion layer maintains a `vm_ip → session-id` map derived at
ingestion-layer startup from the per-session `NetworkInfo.vm_ip` records
in `sessions.db` (see `sandbox-core/src/network.rs`). The map is updated
when sessions are created and on session stop. It stamps the `session`
field at ingestion time.

Note: the IP visible to the ingestion layer in access-log records is the
**VM's IP on the bridge**, not the bridge/gateway IP — this is why the
map is keyed on `NetworkInfo.vm_ip`. This is a new in-memory structure
introduced by this spec; no equivalent reverse map exists in the code
today.

### Event categories

Two categories, filterable at the CLI and HTTP endpoint:

#### Traffic events

Per-request or per-connection decisions by the components that enforce
policy.

| Layer | Source | Event types | Key fields |
|---|---|---|---|
| `dns` | CoreDNS plugin (structured emission, replaces `log.Infof`) | `query_allowed`, `query_denied` | `query` (domain), `qtype` (A/AAAA/...), `resolved_ips` (on allow), `reason` (on deny) |
| `deny-logger` | New component (see below) | `deny` | `orig_dst_ip`, `orig_dst_port`, `protocol` (`tcp`/`udp`), `src_ip`, `src_port` |
| `envoy` | Envoy `access_log` block (L3 block already present per commit `8cacf87`; L1/L2 blocks added + format harmonized — see "Envoy access log") | `connection_allowed`, `connection_denied` | `src_ip`, `src_port`, `dst_ip`, `dst_port`, `matched_chain` (filter chain name), `cluster` (upstream), `close_reason` (on deny) |
| `mitmproxy` | Addon emits structured events (replaces unstructured `logger.info` in `policy_addon.py` / `passthrough_addon.py`) | `request_allowed`, `request_denied` | `host`, `port`, `method`, `path`, `reason` (on deny — e.g. `no_matching_filter`) |

#### Lifecycle events

Gateway and daemon control-plane state changes. All under `layer:
"lifecycle"`.

| Event | Key fields | When |
|---|---|---|
| `gateway_booting` | — | Gateway container starting (sandboxd initiated) |
| `gateway_ready` | — | Gateway passed startup checks (CoreDNS, Envoy, mitmproxy, deny-logger all responding) |
| `policy_applied` | `policy` (full effective policy object), `source_presets` (array of `--preset` invocation strings sent by the CLI, empty if none), `status` (`ok` / `error`), `error` (on error) | Initial `sandbox start --policy ...` |
| `policy_updated` | same shape as `policy_applied`, plus `previous_policy_hash` for diff attribution | Subsequent `sandbox policy update ...` |
| `policy_reset_on_upgrade` | `session`, `previous_rule_count` | Emitted once per session on first access after V004 migration removed its v1-shaped rules (see Part 1 schema bump) |
| `health_degraded` | `component` (which subcomponent failed: `deny-logger`, `envoy`, `mitmproxy`, `coredns`), `reason` | Healthcheck failed |
| `health_restored` | `component` | Healthcheck passed after being degraded |
| `gateway_shutdown` | `reason` (`session_stopped`, `daemon_shutdown`, `error`), `error` (on error) | Gateway container stopping |

There is **no separate `audit` category**. Because presets are
client-local (Part 2), the daemon never sees preset invocations as a
first-class concept; there is nothing to audit-log that isn't already
captured by `policy_applied` / `policy_updated` and their
`source_presets` field.

### Deny-logger component

A new component deployed in the gateway container alongside Envoy,
CoreDNS, and mitmproxy. Its sole job is to catch TCP/UDP connection
attempts from the VM to destinations not covered by any policy rule, log
them, and close.

#### Placement in the nftables pipeline

The current `sandbox_dnat` chain DNATs all VM TCP (except port 53) to
Envoy:10000 unconditionally. The current `sandbox_policy` chain then
`reject`s packets whose `ct original ip daddr` is not in the policy
allow set (`policy.rs:838-862` — `policy drop` plus an explicit
`reject`, producing ICMP admin-prohibited for UDP or TCP RST for TCP —
visible to the VM as an immediate rejection, but unobservable as a
structured event). This is the gap deny-logger closes.

**Amendment to the landed L3 implementation:** replace the VM-egress
`sandbox_policy` reject with conditional DNAT in `sandbox_dnat`, using
per-L4-protocol concat sets:

```nft
# Two concat sets populated by the DNS/policy compiler
set policy_allow_tcp { type ipv4_addr . inet_service; flags interval; }
set policy_allow_udp { type ipv4_addr . inet_service; flags interval; }

chain prerouting {
    type nat hook prerouting priority dstnat;
    # DNS (port 53) is handled first — unchanged, goes to CoreDNS
    ip saddr $vm_subnet udp dport 53 dnat to $gw:53
    ip saddr $vm_subnet tcp dport 53 dnat to $gw:53

    # Allowed destinations — DNAT to Envoy
    ip saddr $vm_subnet meta l4proto tcp ip daddr . tcp dport @policy_allow_tcp dnat to $gw:10000
    ip saddr $vm_subnet meta l4proto udp ip daddr . udp dport @policy_allow_udp dnat to $gw:10000

    # Everything else — DNAT to deny-logger per L4
    ip saddr $vm_subnet meta l4proto tcp dnat to $gw:10001
    ip saddr $vm_subnet meta l4proto udp dnat to $gw:10002
}
```

Shape choice: **two sets keyed `ipv4_addr . inet_service`, one per L4
protocol** (not a single tri-selector with an `inet_proto` third
field). Two sets match nftables' natural `meta l4proto <proto>` match
in the preceding rule, avoid tri-selector syntactic awkwardness, and
scale linearly to number of `(ip, port)` destinations per protocol. See
[nftables concat sets](https://wiki.nftables.org/wiki-nftables/index.php/Concatenations)
and [Multiple NATs using nftables maps](https://wiki.nftables.org/wiki-nftables/index.php/Multiple_NATs_using_nftables_maps).

**This is a cross-table restructure, not an in-place edit.** `sandbox_dnat`
(nat hook) absorbs the filtering decision previously held by
`sandbox_policy`'s VM-egress filter chain. `sandbox_policy` survives
with only its Envoy-egress allow rules (the rules that let the gateway
container open outbound connections to policy IPs for L1/L2 passthrough
and mitmproxy outbound). `compile_nftables` (`policy.rs:755-862`),
`generate_dnat_ruleset` (`gateway.rs:982-1011`), `policy_distributor`,
and `dns_propagation` all change as part of this work. Atomic ruleset
application uses `nft -f` over a multi-table transaction; the
policy-distributor injector is extended to target `sandbox_dnat`
alongside `sandbox_policy`.

Envoy still handles only TCP today. UDP hitting `$gw:10000` would be
silently dropped by Envoy — the `policy_allow_udp` set stays effectively
empty until we have a UDP use case (future-proofed, not load-bearing).

#### Listener design

**Bind address.** All three listeners bind on the gateway container's
bridge IP (`NetworkInfo.gateway_ip`), not `127.0.0.1`. PREROUTING DNAT to
`127.0.0.1` is dropped by the kernel as a martian destination unless
`net.ipv4.conf.<bridge-iface>.route_localnet=1` is enabled on the ingress
interface
([ip-sysctl.rst](https://github.com/torvalds/linux/blob/master/Documentation/networking/ip-sysctl.rst)),
which the gateway container does not enable today (`gateway.rs:281-286`
sets only `ip_forward=1` + disables IPv6 forwarding). Binding on the
gateway IP avoids the sysctl entirely and matches the existing pattern
for Envoy (`gateway_ip:10000`).

- **TCP listener** on `<gateway_ip>:10001`:
  - `accept`, then `getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, ...)` to
    read the pre-DNAT destination.
  - Emit one `deny` event with the 5-tuple and protocol.
  - `close` with `SO_LINGER {onoff=1, linger=0}` → kernel sends RST and
    frees buffers immediately.
  - **Never call `read` or `recv` on the accepted socket.** Payload
    bytes are attacker-controlled and do not contribute to the event.

- **UDP listener** on `<gateway_ip>:10002`:
  - Bound with `setsockopt(IP_RECVORIGDSTADDR, 1)`.
  - `recvmsg` with a fixed small buffer (sized for headers only, not
    payload; full datagram is received but discarded).
  - Read `IP_ORIGDSTADDR` from the cmsg.
  - Emit one `deny` event per received datagram.
  - No response sent.

- **Healthcheck listener** on `<gateway_ip>:10003`:
  - Minimal HTTP server. `GET /health` returns `200 OK` with
    `{"tcp_listener": "ok", "udp_listener": "ok", "events_emitted_60s":
    N}`.
  - **Not in the nftables DNAT set** — no VM traffic routes to this
    port. Reachable from inside the gateway container (Docker
    `HEALTHCHECK` and sandboxd's health probe via `docker exec` or the
    container's published port if any). VM reachability on `:10003` is
    a function of container isolation, not of a DNAT rule.

#### Hardening rules

These are invariants of the deny-logger implementation. Violations are
security bugs.

1. **No peer-controlled bytes in event fields.** Event field values come
   from: kernel socket options (`SO_ORIGINAL_DST`, `IP_ORIGDSTADDR`,
   `getpeername`), the system clock, and the listener's own
   configuration. Nothing from `recv` buffers.
2. **Fixed-size buffers.** No per-connection heap allocation. Bounded
   memory footprint per listener regardless of incoming connection rate.
3. **TCP close is RST, not FIN.** `SO_LINGER {1, 0}` applied before
   close.
4. **UDP datagram body is discarded.** Only the cmsg is read.
5. **Per-session event rate cap.** Configurable (default TBD; suggest
   1000 events/second per session). Excess events are counted into a
   `rate_limited_count` field on a periodic summary event, not
   individually emitted.
6. **Per-session concurrent-connection cap on the TCP listener.**
   Configurable (default TBD; suggest 256). Connections beyond the cap
   are refused at accept (listener backlog + explicit cap); the refusal
   itself is emitted as a rate-limited summary event.

#### Liveness posture

The deny-logger is treated as a hard gateway invariant. No
degraded-observability mode.

- **Startup:** the gateway container's `HEALTHCHECK` probes
  `http://<gateway_ip>:10003/health`. The probe runs *inside* the
  container, but it still has to target the bridge IP — the listener
  binds on `<gateway_ip>` (see "Listener design / Bind address" above),
  and `127.0.0.1:10003` is not reachable because `route_localnet` is
  not enabled and the listener is not bound to loopback. The script
  therefore rediscovers the bridge IP the same way the entrypoint does
  (`$(hostname -i | awk '{print $1}')`) so both scripts stay consistent.
  The container is not `healthy` (and sandboxd refuses to route VM
  traffic to it) until the healthcheck passes.
- **Runtime:** if the healthcheck begins failing, Docker marks the
  container unhealthy. sandboxd's existing gateway health polling
  observes this and restarts the gateway container. Existing VM
  connections through Envoy are reset as part of the restart. This is
  intentional: observability of denials is a hard requirement, and a
  logger outage degrades that.
- **Logged:** the lifecycle events `health_degraded` and
  `health_restored` are emitted around such events, giving the operator
  a chronological record of the outage and recovery.

### Envoy access log

Envoy's L3 `tcp_proxy` filters already emit an `access_log` as of
commit `8cacf87` (M9-S20), using `text_format_source.inline_string` —
single-line space-separated `key=value` records written to a file sink
inside the gateway container (`policy.rs:1280-1292`). This spec does
two things on top:

1. **Flip the access log format from text to JSON across all three
   chains.** The L3 block migrates from `text_format_source` to
   `json_format_options`; L1 and L2 gain matching `access_log` blocks
   in the same JSON format. One harmonized format per line, machine-
   parseable without custom tokenization, consumable by sandboxd's
   ingestion layer without per-layer text parsers.
2. **Add sandboxd-side ingestion.** Today the L3 access_log lands in a
   file and is not consumed by anything; this spec wires it into the
   event ring buffer.

**Consequences of the format change (in scope for this spec):**

- `sandbox-core/src/policy.rs` L3 access_log generator is rewritten
  from `text_format_source.inline_string` to `json_format_options` with
  an explicit field map.
- L1 and L2 `tcp_proxy` filters gain `access_log` blocks with the same
  field map as L3, modulo fields that don't apply (e.g.
  tunnel-specific metadata is L3-only).
- E2E test assertions in `tests/e2e/test_m4_policy.py` that currently
  parse the `key=value` tokens are rewritten to JSON parsing.

**Fields (harmonized JSON shape):** connection 5-tuple (downstream
src/dst, upstream dst), matched filter chain name, cluster name,
response flags, start time, duration. L3-specific fields (e.g. CONNECT
authority) appear only on the L3 block.

**sandboxd ingestion (new):** the access_log file currently lives at
`/var/log/gateway/envoy_access.log` inside the gateway container, which
is mounted `--tmpfs /var/log:rw,noexec,nosuid` (`gateway.rs:229-240`) —
volatile and not reachable from the host. To make it ingestible:

- Replace the `/var/log` tmpfs mount with a **per-session host-directory
  bind mount** (template: the listener-dir bind at `gateway.rs:241-252`).
  sandboxd on the host watches this directory with `inotify` and
  streams the access_log file into the event ring buffer.
- Alternative paths considered and rejected as defaults:
  `docker logs --follow` (requires rewiring `networking/gateway/entrypoint.sh`
  to stream all components' logs to stdout instead of file sinks —
  invasive to CoreDNS and mitmproxy, which also write to files);
  `envoy.access_loggers.grpc` (solves Envoy only, leaves mitmproxy +
  CoreDNS needing a separate mechanism).

Events are parsed, re-tagged with session ID (via the `vm_ip →
session-id` map; `vm_ip` appears in the downstream-src field of the
access_log record), and pushed to the per-session event ring buffer.
- **Event types emitted:** `connection_allowed` (matched a chain and
  succeeded) and `connection_denied` (closed with `no_matching_chain` or
  similar response flag). The mapping from Envoy response flags to
  event types is spelled out in the compiler code.

### CoreDNS structured emission

The existing `handler.go` writes unstructured log lines
(`log.Infof("query %s %s -> denied/allowed (policy)", ...)` —
`networking/coredns-plugin/handler.go:41, 51, 61, 79`). This spec adds
structured event emission as a second output path (the existing
unstructured logs remain for operator debugging).

- Structured events are written as JSONL to a file in the same
  per-session host-directory bind mount used for Envoy access_log (see
  Envoy section). One file per component.
- `query_allowed` event carries the domain, query type, and resolved IPs
  (same data the current IP-report stream already produces per domain).
- `query_denied` event carries the domain and query type.
- The existing IP-report stream (domain → IPs for nftables population,
  at `/etc/coredns/resolved.json` — `networking/gateway/Corefile:15`) is
  **separate** from the event stream and is not affected.

### mitmproxy structured emission

The existing `policy_addon.py` and `passthrough_addon.py` write
unstructured `logger.info` lines
(`networking/mitmproxy/policy_addon.py:109, 114, 116`,
`networking/mitmproxy/passthrough_addon.py:18, 26`). This spec adds
structured event emission as a second output path, via the same
per-session bind-mount JSONL mechanism as CoreDNS.

- `request_allowed` event: host, port, method, path.
- `request_denied` event: host, port, method, path, reason (e.g.
  `no_matching_filter`, `method_not_allowed`).

### Access surface

The event stream is exposed over HTTP, with a CLI client over it.

#### HTTP endpoint

On sandboxd's existing Unix-socket HTTP API:

```
GET /sessions/{session_id}/events?follow=true&layer=<name>&decision=<allow|deny>&event=<name>&since=<ts>
```

- `follow` (default `false`): when `true`, the response is an SSE or
  chunked JSONL stream. When `false`, a bounded JSONL response replays
  events currently in the ring buffer.
- `layer`, `decision`, `event`: repeatable filter params (URL-encoded).
- `since`: RFC 3339 timestamp; events with `t >= since` only.

Response headers:

- `Content-Type: application/jsonl` (non-follow) or
  `Content-Type: text/event-stream` (follow, SSE) or
  `Content-Type: application/jsonl` with `Transfer-Encoding: chunked`
  (follow, streaming JSONL — simpler client).

The decision between SSE and chunked JSONL for streaming is an
implementation detail; chunked JSONL is simpler and the CLI client can
consume it with `io.BufReader` line-by-line. SSE is better if we expect
browser-based consumers, which we do not.

#### CLI

```bash
sandbox events --session=<id> [--follow] [--layer=<name>]... [--decision=<allow|deny>] [--event=<name>]... [--since=<duration-or-ts>] [--json | --table]
```

- Thin client over the HTTP endpoint. `--follow` opens a stream; without
  it, prints current ring-buffer contents and exits.
- `--json` (default) emits JSONL to stdout. `--table` formats as a
  human-readable table with fixed columns and color-coded decisions.
- Shell redirection is the intended lightweight persistence path:
  `sandbox events --session=X --follow > session.jsonl`.

### Retention

**In-memory ring buffer (default):**

- Per-session ring buffer in sandboxd. Size is a config knob
  (`events.ring_buffer_size`, default TBD; suggest 10000 events).
- `--follow` on a fresh client replays the buffer contents, then
  subscribes to new events.
- Session end → buffer discarded.
- Bounded memory per session: `ring_buffer_size * typical_event_size`.

**Optional persistent sink:**

- Enabled via daemon config (`events.persist: true`). Off by default.
- Per-session per-layer JSONL files at:

  ```
  {base_dir}/sessions/{session_id}/events/{layer}-YYYY-MM-DD.jsonl
  ```

  `YYYY-MM-DD` is the UTC date; a new file opens at each UTC midnight.
- Retention window is a config knob (`events.persist_retention_days`,
  default TBD; suggest 14 days). sandboxd prunes rotated files older
  than the window on a periodic sweep.
- Writes are append-only, one line per event.
- No compression in this spec (additive future enhancement).
- Existing SQLite-backed `sessions.db` is **not** used for events;
  events are a volume/append workload that would bloat the DB without
  benefit.

**CLI-side persistence:** `sandbox events --follow > file.jsonl` is the
debug capture path. It captures events from the moment of invocation
plus whatever is in the ring buffer at connect time. Gaps on CLI
crash/disconnect are explicit and documented.

---

## Out of scope

- **nftables packet logging in `sandbox_policy`'s Envoy-egress chain.**
  Envoy-egress denials are a gateway internal (they mean Envoy itself is
  trying to reach an IP not allow-listed — a bug, not a user-facing
  signal) and are not worth wiring into the event stream.
- **Cross-layer event correlation.** Explicitly chose per-layer streams
  over per-connection aggregation (see Event surface section for the
  rationale).
- **Supervised restart of deny-logger process.** The spec picks
  hard-gateway-restart on logger failure. A finer-grained supervisor
  that restarts only the logger process (keeping Envoy and its active
  connections alive) is a future optimization, not day-one. Entry point
  for the future work: `networking/gateway/entrypoint.sh:113-220`.
- **Compression / archival of rotated event files.** Future additive.
- **SSE support for event streams.** Chunked JSONL is the default
  streaming format; SSE was considered and set aside as unnecessary for
  non-browser consumers.
- **Port ranges or port lists in a single rule.** One port per rule. Range
  support is an additive future extension if real use cases appear.
- **Auto-migration from v1 policy JSON.** Hard break; operators rewrite.
- **Changing the access-log sink transport** (file vs. gRPC streaming
  access-log service vs. stdout) for CoreDNS / mitmproxy / deny-logger.
  The spec commits to per-session bind-mount JSONL as the default;
  alternate transports may be revisited if operational experience shows
  the filesystem path to be limiting.
- **LFS support in `github-repo` / `github-pr` presets** (see Known
  gaps).
- **macOS-specific considerations.** The gateway image and component set
  are platform-agnostic; only the network attachment differs, which is
  unchanged by this spec.

## Known gaps / deferred decisions

- Exact `http_filters` path lists for `github-repo` and `github-pr`
  presets. The authoritative list lives in the CLI source; this spec
  describes their shape and intent, not the exact path globs. A later
  implementation work item will enumerate them with test coverage.
- **`cargo` preset: host set verified against documented endpoints
  for Rust 1.70+.** The frozen fixture at
  `sandboxd/sandbox-cli/tests/fixtures/cargo_fetch_trace.json` and the
  `cargo_preset_matches_frozen_trace` drift-detection test in
  `presets::builtin` lock the set to the three documented hosts:
  `index.crates.io` (sparse index, default since Rust 1.70),
  `crates.io` (registry API + the `/api/v1/crates/.../download`
  redirector), and `static.crates.io` (CDN that serves the 302'd
  tarballs). The fixture was built from cargo's published network
  documentation rather than a live pcap because booting a guest with
  full outbound network access for a single trace exceeded the M10-S5
  budget; a future milestone with cheaper guest-network capture should
  regenerate the fixture from an actual `cargo fetch` trace to catch
  any undocumented endpoints (e.g. telemetry).
- **Git LFS is not covered by `github-repo` / `github-pr`.** Repos with
  LFS content require additional rules for `lfs.github.com` (or
  `github-cloud.githubusercontent.com`) and the `/info/lfs/**` paths on
  the main `github.com` host. A future `github-lfs` preset, or a
  `lfs=true` param on `github-repo`, closes this if users hit it in
  practice. Today: LFS use needs hand-written rules in the policy file
  alongside the preset.
- Default values for the event rate cap, connection cap, ring buffer
  size, and persistence retention window. Noted as TBD; an implementation
  work item picks defaults backed by measurement of a typical workload.
- Whether user-configured preset definitions need a versioning scheme
  (they currently don't). Revisit if users accumulate nontrivial preset
  libraries.
- Lifecycle event coverage for daemon-level events (not session-scoped):
  daemon start, daemon shutdown, config reload. These live outside any
  session's event stream by construction; a separate `/events` endpoint
  (no session ID) is a minor extension if needed. Not included in the
  first cut.
- **Envoy listener `use_original_dst` at the filter-chain level.** The
  current listener uses the `original_dst` listener filter; adding
  `destination_port` to `FilterChainMatch` should work with this setup,
  but an empirical check on the pinned Envoy version is prudent before
  L3 port-predicate cutover.

## Amendments to the L3 spec and its landed implementation

The L3 spec has shipped. These amendments revise specific decisions it
made.

1. **L3 filter chains gain a `destination_port` predicate** (doc edit +
   implementation change). The L3 spec's "No port predicate on any L3
   chain" line is replaced with: "L3 filter chains match on destination
   identity (prefix_ranges from resolved IPs or CIDR) and destination
   port derived from the rule." The implementation change adds the
   `destination_port` (`UInt32Value` on `FilterChainMatch`) predicate to
   L3 chain generation in `sandbox-core/src/policy.rs` alongside the
   existing `prefix_ranges` match.
2. **VM-egress `sandbox_policy` reject is replaced with conditional DNAT
   in `sandbox_dnat` to the deny-logger** (doc edit + implementation
   change). The L3 spec's "kept unchanged: sandbox_policy" bullet is
   narrowed to "Envoy-egress rules in `sandbox_policy` are kept
   unchanged". The VM-egress filter side moves to nftables conditional
   DNAT over concat sets, as described in Part 3 / "Placement in the
   nftables pipeline".
3. **L3 access_log format flips from text `key=value` to JSON**
   (implementation change, code-only — no L3 doc edit needed; the L3
   doc does not pin the format). The access_log generator added in
   commit `8cacf87` uses `text_format_source.inline_string`. This spec
   rewrites it to `json_format_options`, adds matching JSON access_log
   blocks on L1 and L2 filters, and updates the E2E assertions in
   `tests/e2e/test_m4_policy.py` to JSON parsing. All three chains emit
   the same JSON shape.
4. **Removal of the L1 and L3 catch-all filter chains is a consequence
   of Part 1's schema change, not a separate edit.** Today the compiler
   emits a catch-all L1 chain (when a Transport rule uses
   `destination: "*"`) or a `default_filter_chain` on L3 (when an Http
   rule uses `destination: "*"`). Part 1 removes bare-`*` from the
   valid host values, so the compiler branches that generate these
   chains become unreachable and are deleted. No separate edit to the
   L3 doc is needed; the L3 spec's wildcard handling simply becomes
   moot under the v2 schema.

**Cleanup sites** (for work-item decomposition — none of these are
optional once the v2 schema forbids bare-`*` and presets move
client-local):

*Bare-`*` removal:*

- `sandbox-core/src/policy.rs:46-61` — `Policy::unrestricted()` helper
  deleted.
- `sandbox-core/src/policy.rs:71-87` — `Policy::is_unrestricted()`
  detector deleted.
- `sandbox-core/src/policy.rs:783-814` — nftables compiler bare-`*` arm
  deleted.
- `sandbox-core/src/policy.rs:1118-1137` — Envoy listener
  `default_filter_chain` arm deleted.
- `sandbox-core/src/policy.rs:1450-1452` — `validate_domain` rejects
  bare `*`.
- `sandbox-core/src/dns_propagation.rs:274-302` — DNS-driven nftables
  bare-`*` arm deleted.
- `sandbox-cli/src/main.rs` (approx. `:56, 205, 286-296, 411-432,
  904-925`) — `--unrestricted` CLI flag and its tests removed (user-
  visible breaking change; acceptable per no-BC).
- `sandboxd/sandboxd/src/main.rs:663` — comment reference updated.
- `docs/guides/network-policies.md:124-130` — user-facing
  `--unrestricted` docs removed; replaced by references to the
  deny-log-driven discovery workflow (Part 1) and the `sandbox policy
  preset` docs.

*Orphaned daemon-side preset helpers (presets are now client-local —
these functions have no caller after this spec):*

- `sandbox-core/src/policy.rs:391-411` — `preset_allow_github` deleted.
- `sandbox-core/src/policy.rs:413-436` — `preset_allow_npm` deleted.
- Any call sites or test fixtures that reference these helpers are
  removed in the same pass. The equivalent rule sets are reimplemented
  in `sandbox-cli` as built-in presets (see Part 2).

The doc edits under (1) and (2) should be applied to the L3 spec once
this spec is accepted. The implementation changes in all four points
are part of this spec's release.
