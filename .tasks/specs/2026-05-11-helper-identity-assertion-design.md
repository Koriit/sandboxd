# Helper Identity Assertion — Design

**Date:** 2026-05-11
**Status:** Approved
**Scope:** Route-helper pair-membership identity check, daemon-side `SO_PEERCRED` plumbing, `users.conf` `_schema_version` convention, and the content of config migration **V001**.

---

## 0 · Sequence context

This spec is **Spec 1 of a five-spec arc** that prepares `sandboxd` for an end-user
install / uninstall / update story. The arc:

1. **Spec 1 (this one)** — Helper identity assertion, `users.conf` convention, V001
2. **Spec 2** — API session isolation + guest version compatibility
3. **Spec 3** — Daemon productionization (dedicated `sandbox` system user, systemd unit,
   state at `/var/lib/sandbox/`, file modes, `sandbox doctor`, version pinning)
4. **Spec 4** — Release & install infrastructure (signed builds, install/uninstall
   scripts on GH Pages, Lima test harness)
5. **Spec 5** — Update infrastructure (`sandbox update` CLI, config migration framework,
   backups, lock file)

Dependency graph: Specs 1 and 2 are parallel; Spec 3 depends on Spec 1; Spec 4 depends
on Spec 3; Spec 5 depends on Spec 4. Spec 1 is the **security model that makes Spec 3
safe** — without the pair-check, moving the daemon to a dedicated `sandbox` user breaks
per-user CIDR pool isolation.

What this spec **does not** cover: the migration framework itself (Spec 5), the dedicated
`sandbox` system user and file-mode tightening (Spec 3), API-layer session ownership
(Spec 2), and install infrastructure (Specs 4/5). See § 10 for the explicit out-of-scope
list.

## 1 · Motivation

Today the route helper authorizes a network operation by checking only **one** identity —
the caller's effective UID, inherited on `fork`+`exec`:

```rust
// sandboxd/sandbox-route-helper/src/main.rs:120-150
let caller_uid = Uid::current();
…
let subnet = config.find_subnet_by_gateway_ip(gateway_ip)?;
if !subnet.allows_uid(caller_uid.as_raw()) {
    return Err(format!(
        "uid {} ({}) not in allow_users for subnet {}/{}", …
    ));
}
```

Per-user CIDR pool isolation works because the daemon currently runs as the operator
(say, `alice`). `users.conf` lists `allow_users: ["alice"]`; the helper, forked by the
daemon, inherits `getuid() == alice` and validates alice in the pool. The on-disk
`UsersConfig` struct (`sandboxd/sandbox-core/src/users_conf.rs:284-311`) is read straight
through to `find_subnet_by_uid` / `allows_uid` (lines 338-379).

**Spec 3** will move the daemon process to a dedicated `sandbox` system user.
The rationale there is defense-in-depth: a daemon compromise should no longer mean an
operator-account compromise. But that change *breaks* today's helper check — the helper
would see `getuid() == sandbox` for every invocation, regardless of which operator's
session triggered it. Either every pool would have to list `sandbox` (and every operator
could then drive helper actions against every other operator's pool — eliminating
isolation), or no pool would list it (and the daemon would lose the ability to call the
helper at all).

**Spec 1 is the security model that resolves this.** The helper validates *two*
identities:

1. its own runtime `getuid()` — the caller (the daemon, post-Spec-3 as `sandbox`; the
   operator today and in dev mode);
2. an asserted `--for-user <operator>` flag — the operator that the daemon learned by
   reading peer credentials from the accepted Unix-socket connection.

A pool authorizes a request iff **both** names appear in `allow_users`. The convention
that goes with this is that every pool lists `"sandbox"` *and* the operator
(`["sandbox", "alice"]`). The dedicated `sandbox` user has the static authority to act
on behalf of any operator listed alongside it — which is exactly the daemon's existing
authority. No new authority is created, but the asserted operator's identity must now
travel with each helper call.

The change also independently improves defense-in-depth **today** (pre-Spec-3): a
direct CLI invocation of the helper by alice cannot elevate beyond alice's own pools,
because `--for-user=bob` is now checkable against the pool's `allow_users` rather than
trusting `getuid()` alone.

## 2 · Threat model

Four scenarios. Each was validated in the design brainstorm; the table below names them,
then prose walkthroughs follow. In every scenario, the route helper has
`cap_net_admin,cap_sys_admin=eip` file caps and is being invoked unprivileged.

| # | Scenario | What the attacker controls | Outcome |
|---|---|---|---|
| 1 | **Operator compromise** | alice's account (uid=alice) | Refused — pair-check requires both alice and bob in the pool. |
| 2 | **Daemon compromise (Spec 3)** | `sandbox` user; arbitrary `--for-user` argv | Bounded — attacker can only act as operators already listed alongside `sandbox`, i.e. within pre-existing daemon authority. No elevation. |
| 3 | **Cross-user disruption** | alice's account; bob's CIDR target | Refused — alice not in bob's pool. |
| 4 | **Filesystem bypass** | operators in the `sandbox` group (Spec 3) | Out of scope here; addressed by Spec 3's `0600 sandbox:sandbox` mode on state files. Cited as the complementary control. |

### 2.1 · Operator compromise (alice)

Alice's account is compromised. The attacker runs the cap'd helper directly:

```
$ /usr/local/libexec/sandboxd/sandbox-route-helper --for-user=bob 1234 10.210.0.2
```

The helper reads `getuid()` → `alice`, parses `--for-user=bob`. The pool whose CIDR
contains `10.210.0.2` is bob's (`["sandbox", "bob"]`). Pair-check requires `alice ∈
allow_users` **and** `bob ∈ allow_users`. Alice isn't there. **Refused.** The attacker
can act only within pools that list alice — which is bob's pool not, so they can only
do what alice could already do.

### 2.2 · Daemon compromise (post Spec 3)

The `sandbox` daemon process is compromised. The attacker has full control of how the
daemon constructs helper argv. They invoke:

```
sandbox-route-helper --for-user=alice <pid> <gateway-ip>
sandbox-route-helper --for-user=bob   <pid> <gateway-ip>
…
```

The helper sees `getuid() == sandbox` and the asserted operator. Pair-check requires
both `sandbox` and `<for-user>` in the pool. Pools tagged `["sandbox", "alice"]`,
`["sandbox", "bob"]`, etc. pass for the respective operators — exactly the authority a
healthy daemon would have. The attacker cannot synthesize a `sandbox + carol` pool
without write access to root-owned `/etc/sandboxd/users.conf` (rejected upstream by
`validate_canonical_users_conf_security` —
`sandboxd/sandbox-core/src/users_conf.rs:510-562`: root-owned, mode `0o644`,
non-symlink).

**No elevation beyond pre-existing daemon scope.**

### 2.3 · Cross-user disruption

Alice tries to disrupt bob's session via the helper. She invokes (or finds a way to make
the daemon invoke) the helper with bob's gateway IP.

- Direct invocation: `getuid() == alice`, `--for-user` defaults to `alice` (see § 3),
  bob's pool requires `["sandbox", "bob"]`. Alice not in it. **Refused.**
- Indirect via daemon (today, daemon runs as alice): the daemon resolves the connecting
  client's UID via `SO_PEERCRED` (see § 6). Alice's CLI connects, peer-cred is `alice`,
  helper is called with `--for-user=alice`. Pool lookup is keyed by `gateway_ip` (existing
  logic, `users_conf.rs:320-324`); if the gateway IP belongs to bob's CIDR, the lookup
  hits bob's pool, alice is not in `allow_users`, **refused**.

### 2.4 · Filesystem bypass

This spec **does not** address direct filesystem reads of session state. Spec 3 will
move state to `/var/lib/sandbox/` with mode `0600 sandbox:sandbox`, so operators in the
`sandbox` supplementary group cannot read peers' session metadata. Cite Spec 3 as the
complementary control here; do not propose any file-mode changes in Spec 1.

## 3 · The pair-membership rule

> The helper validates that **both** `name(getuid())` and the asserted `--for-user`
> value are members of the chosen pool's `allow_users`. If `--for-user` is omitted, it
> defaults to `name(getuid())`, so direct-CLI invocation continues to behave as today.

### 3.1 · Algorithm

In pseudo-Rust, slotted between step 1 (caller identity) and step 3 (load users.conf) of
the existing eight-step flow documented in
`sandboxd/sandbox-route-helper/src/main.rs:25-44`:

```rust
// Step 1 — caller identity (existing, but now also resolve username strictly).
let caller_uid  = Uid::current();
let caller_name = User::from_uid(caller_uid)
    .map_err(|e| format!("getpwuid_r failed for caller uid {}: {e}", caller_uid.as_raw()))?
    .ok_or_else(|| format!("caller uid {} does not resolve to a username", caller_uid.as_raw()))?
    .name;

// Step 2 — argv (now parsed with --for-user).
let (container_pid, gateway_ip, for_user_arg) = parse_argv(&args)?;
let for_user = for_user_arg.unwrap_or_else(|| caller_name.clone());

// Step 3 — load users.conf and find the pool by gateway IP (existing).
let config  = load_users_config_route_helper()?;
let subnet  = config.find_subnet_by_gateway_ip(gateway_ip)
    .ok_or_else(|| format!("gateway ip {gateway_ip} not in any subnet"))?;

// Step 4 — PAIR-CHECK. Both names must be in allow_users.
let caller_in = subnet.allow_users.iter().any(|n| n == &caller_name);
let for_in    = subnet.allow_users.iter().any(|n| n == &for_user);
if !(caller_in && for_in) {
    audit::denied(&caller_name, &for_user, subnet);
    return Err(format!(
        "pair-check failed: caller={} for-user={} pool={}/{}",
        caller_name,
        for_user,
        subnet.cidr.base(),
        subnet.cidr.prefix_len(),
    ));
}

audit::allowed(&caller_name, &for_user, subnet);
```

### 3.2 · Numeric vs. name comparison

Today's `SubnetEntry::allows_uid` (`sandboxd/sandbox-core/src/users_conf.rs:355-379`)
resolves each name in `allow_users` to a numeric uid via `getpwnam_r` and compares
**numerically** — admin renames via `usermod` take effect immediately. The pair-check
preserves this ground-truth: both `caller_name` and `for_user` are themselves resolved
to uids before comparison, so the rule reads as:

> Both `caller_uid` AND `getpwnam_r(for_user).uid` must appear in
> `{ getpwnam_r(n).uid : n ∈ allow_users }`.

In practice the implementation reuses the existing `SubnetEntry::allows_uid(uid)` helper
twice — once for the caller's uid (already in scope), once for the for-user's uid
(resolved at argv-parse time via `User::from_name`). Names that do not resolve are
treated as a deny path with a clear error (see § 3.4); we do not fall back to string
comparison.

### 3.3 · Exit code, stderr, and audit log

| Surface | Format | Notes |
|---|---|---|
| **Exit code on deny** | `1` (existing `DENY_EXIT`, `sandbox-route-helper/src/main.rs:101`) | All pre-existing deny branches already use `1`. The pair-check is an additional deny condition that joins this set; introducing a new code would force every scripted consumer to learn step numbering, which the existing crate docstring (lines 96-101) explicitly rejects. The **stderr text** carries the load-bearing signal. |
| **Stderr on deny** | `sandbox-route-helper: pair-check failed: caller=<name> for-user=<name> pool=<cidr>` | Must include **both** identities for forensic clarity. Substring `pair-check failed` is the assertion anchor for integration tests. |
| **Audit log on every invocation** | one JSON line per call, on every allowed-and-denied path, to a daemon-owned file | See § 3.5 for shape and destination. |

### 3.4 · Username resolution failure

`getpwuid_r(getuid())` and `getpwnam_r(for_user)` both must succeed and return a record.

- **Resolution fails outright** (`Err`): refuse with `username resolution failed for
  <uid|name>: <errno>` and exit `1`.
- **Resolution succeeds with no match** (`Ok(None)`): refuse with `caller uid <n> does
  not resolve to a username` or `--for-user <name> does not resolve to a uid`. Exit `1`.

Today's helper has a softer policy at line 125 — `caller_user` is `ok().flatten()` and
used only for stderr clarity. The new policy is **strict**: the pair-check needs both
identities reliably, so an unresolvable identity must deny. This is a behavior change;
it lands with the helper changes in this spec. See § 9.1 for the CI implications of the
strict policy (a deliberate regression that adopters in container-CI environments
without a populated `/etc/passwd` for the test uid must account for).

### 3.5 · Audit log destination and shape

Audit records are written on every invocation, allowed or denied, in JSON-Lines. The
file lives at:

```
$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log    (today; daemon runs as operator)
/var/lib/sandbox/route-helper-audit.log              (post-Spec-3; daemon runs as sandbox)
```

Spec 1 ships with the today-mode path; Spec 3 will swing the canonical location when it
introduces `/var/lib/sandbox/`. Path resolution mirrors the daemon's socket-path
resolution (`SANDBOX_SOCKET` env override, default `$XDG_RUNTIME_DIR/sandboxd/...`,
fallback `~/.local/share/sandboxd/...`) — see the path-resolution discussion in
`CLAUDE.md` § "Key conventions".

One record per invocation, written before exit:

```json
{"ts":"2026-05-11T14:23:09.123Z","decision":"allowed","caller":"alice","for_user":"alice","pool":"10.209.0.0/20","gateway_ip":"10.209.0.2","pid":12345}
{"ts":"2026-05-11T14:23:11.477Z","decision":"denied","reason":"pair-check failed","caller":"alice","for_user":"bob","pool":"10.210.0.0/20","gateway_ip":"10.210.0.2","pid":12346}
```

Fields:

| Field | Meaning |
|---|---|
| `ts` | RFC 3339 UTC timestamp |
| `decision` | `"allowed"` or `"denied"` |
| `reason` | Present on denies only; short tag (`"pair-check failed"`, `"gateway-ip not in any subnet"`, …) |
| `caller` | `name(getuid())` of the helper process |
| `for_user` | Asserted operator name; equals `caller` when `--for-user` omitted |
| `pool` | Subnet CIDR string (e.g. `"10.210.0.0/20"`); absent on `gateway-ip not in any subnet` |
| `gateway_ip` | The `<gateway_ip>` positional argv value |
| `pid` | The `<container_pid>` positional argv value |

Append-only writes via `OpenOptions::new().append(true).create(true).open(path)`. If the
log open or write fails, the helper's response **depends on which path the decision
took** — the routing-path-availability and forensic-record-availability invariants
diverge here:

- **Allow path** — write failure logs a structured stderr line and the helper
  **continues with the allow** (installs the route, exits `0`). An audit-log
  infrastructure failure (disk full, ENOSPC on the log directory, etc.) must not
  become a denial of service to session creation — the unreachable log is less
  harmful than an unconditionally-failed network setup.
- **Deny path** — write failure logs the same structured stderr line and the
  helper **still exits with `DENY_EXIT` (1)**. The deny itself was never in doubt
  (it happens before and independently of the log write); the escalation here is
  about the **forensic record**. Silently swallowing a "alice tried to mess with
  bob's pool" record is the worst case for security audit: the deny goes through,
  but the operator's investigation trail evaporates. Exiting non-zero with a
  loud stderr line surfaces the missing-record condition to the daemon (which
  already maps non-zero helper exits to a structured lifecycle event) and to any
  human running the helper directly.

In pseudo-Rust, the asymmetry at the audit-write site:

```rust
// Decision already made; `decision` is "allowed" or "denied".
match write_audit_record(&record) {
    Ok(()) => { /* normal exit path */ }
    Err(e) => {
        eprintln!("sandbox-route-helper: audit log write failed: {e}");
        if decision == Decision::Denied {
            // Forensic-record-availability escalation: surface the
            // missing record even though the deny itself succeeded.
            std::process::exit(DENY_EXIT);
        }
        // Allow path: continue — routing-path availability wins.
    }
}
```

The **deny-path-availability** invariant is preserved either way: the deny occurs
regardless of whether the log write succeeded. The escalation only adds the
forensic signal; it never converts an allow into a deny.

## 4 · `users.conf` schema convention

The schema gains one new top-level field, `_schema_version`. Every pool's `allow_users`
gains a `"sandbox"` entry (post-V001).

### 4.1 · Before V001 (today)

```json
{
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["alice"] }
  ]
}
```

The struct definition lives at `sandboxd/sandbox-core/src/users_conf.rs:284-311`:

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsersConfig {
    pub subnets: Vec<SubnetEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetEntry {
    pub cidr: Cidr4,
    pub allow_users: Vec<String>,
    #[serde(default)]
    pub comment: Option<String>,
}
```

`SubnetEntry` already demonstrates the forward-compat pattern (`comment` is
`Option<String>` + `#[serde(default)]`) coexisting with `deny_unknown_fields` — see
`users_conf.rs:798-834` for the unit tests that pin this. The same pattern applies
unchanged to `_schema_version`.

### 4.2 · After V001

```json
{
  "_schema_version": 1,
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
  ]
}
```

`UsersConfig` gains:

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsersConfig {
    #[serde(default, rename = "_schema_version")]
    pub schema_version: Option<u32>,
    pub subnets: Vec<SubnetEntry>,
}
```

Notes:

- `_schema_version` is integer-valued. The underscore prefix is a convention that
  separates metadata from domain data. The Rust field name is `schema_version`
  (idiomatic) with `#[serde(rename)]` to bind it to the underscored key.
- It is `Option<u32>` + `#[serde(default)]`: a file with no `_schema_version` parses
  fine and yields `None`. The migration framework (Spec 5) treats `None` as version
  `0` and applies V001.
- `deny_unknown_fields` stays. Typos on unrelated fields keep being rejected (today's
  `typo_on_allow_users_field_rejected` test, `users_conf.rs:773-789`, still passes).

### 4.3 · Preserving operator-customized content

Operators can add fields to `users.conf` that aren't part of the struct (e.g. a
custom `priority` field on a subnet entry). Today the parser would reject them via
`deny_unknown_fields`. **This spec does not change that behavior** — `deny_unknown_fields`
stays on both `UsersConfig` and `SubnetEntry`. Operators who need free-form annotation
use the existing `comment` field.

The migration itself, however, must preserve operator-added content **outside of the
fields V001 touches**. Recommended implementation approach (pinned for Spec 5): read the
file via `serde_json::Value`, mutate only the keys V001 owns, then write back. The
operator-visible representation is unchanged for everything else — whitespace
normalization is acceptable, but field ordering and any user comments embedded as JSON
properties are preserved. (Trailing JSON-with-comments syntax, e.g. `// foo`, is not
supported — `users.conf` is strict JSON per the project's "config files are JSON"
convention in `CLAUDE.md`.)

For V001 specifically, the transform is small enough (a `Vec<String>` mutation per
entry plus a top-level integer add) that a `serde_json::Value` round-trip is the
cleanest approach. The typed-struct-plus-`#[serde(flatten)] extra: HashMap<...>`
alternative is overkill here.

## 5 · Migration V001 — content

V001 is a **content spec, not a framework spec.** Spec 5 will design the registry, the
"apply pending migrations" loop, the atomic-rename write mechanism, the lock file, the
backup folder, and the daemon-side schema-mismatch refusal. Here, V001 is described as
a pure transform: given the parsed `users.conf` value, produce the post-migration value.

### 5.1 · Inputs and outputs

| Input state | V001 action |
|---|---|
| `_schema_version` absent | Treat as `0`; apply V001. |
| `_schema_version == 0` | Apply V001. |
| `_schema_version == 1` | No-op (already at V001). |
| `_schema_version >= 2` | V001 never runs; framework chooses subsequent migrations. |

### 5.2 · Transform

For the input value (a `serde_json::Value::Object`):

1. **Insert `"_schema_version": 1`** at the top level. If it was absent, add it. If it
   was already present and equal to `1`, no-op (idempotency).
2. **For each entry in `subnets[]`:**
   - Read the `allow_users` array.
   - If it already contains `"sandbox"` (exact string match), leave it untouched.
   - Otherwise, **prepend** `"sandbox"` to the array. The result is `["sandbox",
     <existing entries…>]`. Order matters only for human readability — neither today's
     `allows_uid` nor the pair-check is order-sensitive — but prepending is the rule for
     consistency across migrations.
3. Write back. (The atomic-write mechanism is Spec 5's responsibility.)

### 5.3 · Idempotency contract

V001's transform is idempotent both at the per-pool and the per-file level:

- A pool with `["sandbox", "alice"]` already correct → unchanged.
- A pool with `["alice", "sandbox"]` (operator-added in a different order) → already
  contains `"sandbox"`, **no-op**. Operator's order is preserved.
- A file with `_schema_version: 1` already at the top level → V001 does nothing.

**Framework observability.** Per Spec 5's selection rule (see Spec 5 § 4.2 — "every
migration advances exactly one version"), the framework returns early when
`current == target` and never invokes V001's `apply` on a file already at version
`1`. The transform's "already at V001 → no-op" branch is therefore **unobservable
from the framework's apply loop** under normal operation. It remains valuable as
**defense in depth**: if some other code path (a test fixture, a future tool, an
ad-hoc `cargo run` of the transform, or a hand-written script) invokes
`migrate_v001` directly on an already-at-V001 input, the transform must not
corrupt the file. The contract documented here is the transform's invariant — not
a behavior the framework exercises.

The per-pool idempotency (operator hand-added `"sandbox"` in a different order, or
both names already present) **is** framework-observable: those inputs still read at
`_schema_version` absent / `0`, so V001 is invoked, and its per-pool no-op handling
must preserve operator order.

This matters for the framework (a re-applied migration on the per-pool branch must
be safe), for operators who hand-edited their file in advance of the upgrade, and
for the dev-mode path where a contributor's `users.conf` may already follow the
post-V001 convention by the time V001 ships.

### 5.4 · Output validation

After applying V001, the produced JSON must:

- Parse cleanly as `UsersConfig` with `_schema_version = Some(1)`.
- Each `subnets[i].allow_users` contains `"sandbox"` exactly once.
- All `cidr` values continue to round-trip through `Cidr4::parse` (existing invariant).
- No subnet entries are added or removed; no other fields are mutated.

The framework (Spec 5) will validate the produced value before atomic-rename and abort
on failure with the temp file left in place for forensic review.

### 5.5 · Examples

**Input A — pre-V001, single subnet:**

```json
{
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["alice"] }
  ]
}
```

**Output A:**

```json
{
  "_schema_version": 1,
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
  ]
}
```

**Input B — pre-V001, multiple subnets, one with an operator comment:**

```json
{
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["alice"], "comment": "alice prod" },
    { "cidr": "10.210.0.0/24", "allow_users": ["bob", "carol"] }
  ]
}
```

**Output B:**

```json
{
  "_schema_version": 1,
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"], "comment": "alice prod" },
    { "cidr": "10.210.0.0/24", "allow_users": ["sandbox", "bob", "carol"] }
  ]
}
```

**Input C — partially-migrated (operator added `sandbox` in a different order):**

```json
{
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["alice", "sandbox"] }
  ]
}
```

**Output C** — `sandbox` already present, no shuffle:

```json
{
  "_schema_version": 1,
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["alice", "sandbox"] }
  ]
}
```

**Input D — already at V001:**

```json
{
  "_schema_version": 1,
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
  ]
}
```

**Output D** — bit-for-bit equal to input.

## 6 · Daemon-side changes

The daemon must learn the operator's identity from the connecting socket and pass it
to every helper invocation.

### 6.1 · Peer-credential read

axum 0.8 serves over `tokio::net::UnixListener` (`sandboxd/sandboxd/src/main.rs:6496`).
The accepted side of each connection is a `tokio::net::UnixStream`; calling
`.peer_cred()` on it returns a `tokio::net::unix::UCred` with `uid()` / `gid()` / `pid()`
accessors backed by `getsockopt(SOL_SOCKET, SO_PEERCRED)`. This is a kernel-side check
on the connection itself, not a value the client can spoof.

To plumb the operator identity into request handlers, the daemon wraps the standard
`axum::serve(listener, app)` path with a connection acceptor that:

1. Calls `stream.peer_cred()` immediately after `accept`.
2. Resolves `ucred.uid()` to a username via `nix::unistd::User::from_uid` (a wrapper
   over `getpwuid_r`).
3. If resolution fails (`Err` or `Ok(None)`), refuses the connection: close the stream,
   log at `warn!` with the unresolved uid, and continue accepting. The client sees a
   connection reset and the CLI surfaces the daemon's general "cannot connect"
   message — Spec 2 will surface a structured 4xx for this case once API ownership
   lands; here we accept the bare-reset behavior because the failure mode is rare
   (host `/etc/passwd` corruption) and the alternative (parse it as JSON-API failure)
   requires reading the HTTP request first, which the layering doesn't support cleanly.
4. Attaches the resolved username (and uid, for completeness) to the request via
   `Request::extensions_mut().insert(OperatorIdentity { ... })`. This is the standard
   axum 0.8 connect-info pattern.

The crate dependency cost: `sandbox-core/Cargo.toml:13` and `sandboxd/Cargo.toml:49`
already pull `nix` with the `user` feature — `User::from_uid` is already in scope.
Adding the `socket` feature would also let us call `nix::sys::socket::getsockopt(fd,
PeerCredentials)` directly, but `tokio::net::UnixStream::peer_cred()` is simpler and
does the same thing — no new dependency surface is required.

### 6.2 · Threading operator identity to handlers

Handlers extract the identity through an axum `Extension` extractor:

```rust
pub struct OperatorIdentity {
    pub uid:  u32,
    pub name: String,
}

async fn create_session(
    State(state):       State<Arc<AppState>>,
    Extension(operator): Extension<OperatorIdentity>,
    Json(req):          Json<CreateSessionRequest>,
) -> impl IntoResponse { … }
```

The same extractor is added to every other handler that — directly or transitively —
leads to a helper invocation. From § 6.4 below, that is `create_session` and
`start_session`. Other handlers (`stop_session`, `remove_session`, the read-only
handlers, the events/policy/backends sub-routers) do not invoke the helper and so do
not require the extractor for *this* spec, though Spec 2 will add ownership checks
that need the same identity surface — Spec 2's design extends this extension, not
the SO_PEERCRED layer.

### 6.3 · Threading through to the helper invocation

`ContainerRuntime::start` (`sandbox-core/src/backend/container.rs:537-566`) is the
sole helper-invocation site. The signature change:

```rust
// Before
async fn invoke_route_helper(helper: &Path, pid: i32, gateway_ip: IpAddr)
    -> Result<(), SandboxError>;

// After
async fn invoke_route_helper(helper: &Path, pid: i32, gateway_ip: IpAddr, for_user: &str)
    -> Result<(), SandboxError>;
```

`for_user` rides down through `RuntimeStartArgs`:

```rust
pub struct RuntimeStartArgs {
    pub lima_bridge:  Option<String>,
    pub lima_mac:     Option<String>,
    pub lima_config:  Option<LimaConfig>,
    pub for_user:     Option<String>,  // None for Lima (helper not invoked);
                                       // Some(<operator name>) for container.
}
```

`for_user: None` is the dev/test path where no route-helper invocation is expected — the
container runtime continues to skip the helper when `route_helper_path` is `None`
(today's `else` arm at `container.rs:555-562`), regardless of `for_user`. When the
runtime *does* invoke the helper but `for_user` is `None`, the runtime errors out with
an internal-consistency message; this is a programming error (a handler dispatched
through `runtime.start` without the operator extension), not a user-facing failure.

### 6.4 · Helper invocation sites — concrete list

There is exactly one helper invocation function in the workspace:

| Site | Path | Caller | Operator identity available? |
|---|---|---|---|
| **S1** | `sandboxd/sandbox-core/src/backend/container.rs:554` — `invoke_route_helper(helper, pid, network.gateway_ip)` inside `ContainerRuntime::start` | Daemon, indirectly via `runtime.start()` | No today; threaded via `RuntimeStartArgs::for_user` (this spec). |

`invoke_route_helper` itself is the call site of `Command::new(&helper).arg(&pid_arg).arg(&gw_arg)` at `container.rs:986-987`; this spec adds two more `.arg("--for-user").arg(&for_user)` calls.

The daemon paths that reach S1 — and thus must populate `RuntimeStartArgs::for_user` — are:

| Daemon site | File:line | Path that reaches S1 |
|---|---|---|
| **D1** | `sandboxd/sandboxd/src/main.rs:1412` | `create_session` handler → `runtime.start()` for `BackendKind::Container`. |
| **D2** | `sandboxd/sandboxd/src/main.rs:2730` | `start_session` handler → `runtime.start()`, backend-dispatched (`session.backend`); reaches S1 when backend is Container. |

Two other `runtime.start()` sites exist but are Lima-only and never reach S1:

| Lima-only site | File:line | Notes |
|---|---|---|
| L1 | `sandboxd/sandboxd/src/main.rs:1969` | `create_session` Lima fast-path. `LimaRuntime::start` does not invoke the helper. |
| L2 | `sandboxd/sandboxd/src/main.rs:2011` | `create_session` Lima slow-path. Same. |

These sites still receive a `RuntimeStartArgs` (the trait signature is shared); they pass
`for_user: Some(<operator>)` for parity but the value is unused. Keeping the extractor
attached to the handlers (not threaded only to the Container branches) avoids a future
regression when a contributor adds a third backend or moves a `runtime.start()` site
across branches.

`restore_session_networking_lite` (`sandboxd/sandboxd/src/main.rs:4961-5068`) and
`reconcile_networking` (`5497`+) do *not* call `runtime.start()` — they restore the
gateway container only. They are not helper-invocation sites and need no changes.

### 6.5 · Wire snapshot — before / after

Today's daemon-emitted helper exec:

```
/usr/local/libexec/sandboxd/sandbox-route-helper 12345 10.209.0.2
```

Post-Spec-1:

```
/usr/local/libexec/sandboxd/sandbox-route-helper --for-user alice 12345 10.209.0.2
```

For direct CLI invocation (operator running `sudo` on the helper for debugging — a path
the helper supports), omitting `--for-user` is allowed and equivalent to `--for-user
$(id -un)`:

```
sudo sandbox-route-helper 12345 10.209.0.2          # for-user defaults to getuid()
sudo sandbox-route-helper --for-user alice 12345 10.209.0.2   # explicit, equivalent for alice
```

## 7 · Backward compatibility — dev mode

Developers who run `make setup-dev-env` (`CLAUDE.md` § "Build and test") run the daemon
as themselves. There is no dedicated `sandbox` system user. This spec must continue to
work for that audience.

### 7.1 · Dev-mode walkthrough

Alice runs the daemon as `alice`. After V001 applies, her `users.conf` reads:

```json
{
  "_schema_version": 1,
  "subnets": [
    { "cidr": "10.209.0.0/24", "allow_users": ["sandbox", "alice"] }
  ]
}
```

(Note: V001 added `sandbox` to every pool unconditionally, even though no `sandbox`
account yet exists on the host. That's fine — the helper resolves `allow_users` names
via `getpwnam_r` and treats `Ok(None)` as a non-match, per `users_conf.rs:363-367`. The
presence of an unresolvable name does **not** deny callers who appear elsewhere in the
list.)

Alice opens her CLI. The flow:

1. CLI does `UnixStream::connect(socket_path)` (`sandbox-cli/src/main.rs:1122`).
2. Daemon's acceptor reads `SO_PEERCRED` → `uid = alice's uid`.
3. `User::from_uid(alice's uid)` → `Some(User { name: "alice", ... })`.
4. `OperatorIdentity { uid, name: "alice" }` is attached to the request.
5. `create_session` runs `runtime.start(handle, RuntimeStartArgs { for_user:
   Some("alice"), ... })`.
6. `ContainerRuntime::start` runs `invoke_route_helper(helper, pid, gateway_ip,
   "alice")`.
7. Helper forks. `getuid()` is `alice` (the daemon's uid, inherited on `fork`+`exec`).
   `--for-user` is `"alice"`.
8. Pair-check: pool is `["sandbox", "alice"]`. `caller_name = "alice"` ∈ pool ✓.
   `for_user = "alice"` ∈ pool ✓. **Allowed.**

Each invariant holds independently:

| Invariant | Why it holds in dev mode |
|---|---|
| Pool contains `alice` | Operator-provided, preserved by V001. |
| Pool contains `sandbox` | Added by V001 (no-op'd on subsequent applies). Unresolvable but harmless. |
| `caller_name == "alice"` | Daemon runs as alice, fork-inherits to helper. |
| `for_user == "alice"` | Daemon reads peer cred of CLI socket, also alice. |
| Both in `allow_users` | Pair-check succeeds. |

### 7.2 · Pre-V001 deployments

A dev box with a `users.conf` that has not been migrated yet (no `_schema_version`, no
`sandbox` entry) continues to work pre-V001. Once V001 applies (whenever the framework
ships in Spec 5), it is *additive*: it adds `sandbox` to every pool but removes nothing.
Existing operator entries are preserved. The pair-check then validates as above —
`caller_name = "alice"` and `for_user = "alice"` are both alice's, both in `["sandbox",
"alice"]`, both pass.

### 7.3 · Direct CLI helper invocation

Operators occasionally invoke the helper directly (debugging, manual netns setup). With
`--for-user` omitted, it defaults to `name(getuid())`:

```
$ sudo sandbox-route-helper 12345 10.209.0.2
```

`getuid()` is `root` (because of `sudo`) — but `setcap` flow makes this a deny in the
existing helper unless root is in `allow_users`. The change here doesn't move that
behavior; pair-check is `(root, root)` against the pool, and root is rarely in
`allow_users`. This is the same status quo as today.

A non-root direct invocation:

```
$ /usr/local/libexec/sandboxd/sandbox-route-helper 12345 10.209.0.2
```

(The helper's file caps make `setuid` unnecessary — it picks up `cap_net_admin,
cap_sys_admin=eip` on exec.) `getuid()` is alice, `--for-user` defaults to alice;
pair-check is `(alice, alice)`; same behavior as today.

## 8 · Test plan

All Rust tests follow the project's hermetic-by-default convention; tests that need
out-of-process state (a real cap'd helper binary, real Docker, real netns) are named
with the `integration_*` prefix per CLAUDE.md § "Integration-test convention" and
selected by the `integration` nextest profile (`sandboxd/.config/nextest.toml`).

### 8.1 · Unit tests — pair-check function

A pure function, extractable for direct testing. Table-driven, one row per case:

| Test name | Pool `allow_users` | Caller name | `--for-user` | Expected outcome |
|---|---|---|---|---|
| `pair_check_allows_when_both_match` | `["sandbox","alice"]` | `alice` | `alice` | allowed |
| `pair_check_allows_when_caller_eq_for_user_post_v001` | `["sandbox","alice"]` | `alice` | (omitted) | allowed (defaults to caller) |
| `pair_check_denies_when_caller_missing` | `["sandbox","alice"]` | `mallory` | `alice` | denied |
| `pair_check_denies_when_for_user_missing` | `["sandbox","alice"]` | `alice` | `bob` | denied |
| `pair_check_denies_when_both_missing` | `["sandbox","alice"]` | `mallory` | `eve` | denied |
| `pair_check_denies_empty_pool_with_explicit_for_user` | `[]` | `alice` | `alice` | denied |
| `pair_check_denies_pool_with_only_sandbox` | `["sandbox"]` | `alice` | `alice` | denied (no human in the pool) |
| `pair_check_allows_when_pool_has_only_sandbox_and_caller_is_sandbox` | `["sandbox"]` | `sandbox` | `sandbox` | allowed (Spec-3 daemon path before any operator is provisioned) |

### 8.2 · Unit tests — V001 transform

| Test name | Behavior |
|---|---|
| `v001_adds_sandbox_to_single_user_pool` | Input A above; matches Output A. |
| `v001_adds_sandbox_to_multiple_pools_independently` | Input B; matches Output B. |
| `v001_noops_pool_already_containing_sandbox` | Input C; matches Output C (order preserved). |
| `v001_noops_when_schema_version_already_one` | Input D; bit-equal output. |
| `v001_preserves_comment_field` | Pool with `"comment": "X"` keeps it. |
| `v001_idempotent_when_run_twice` | Apply V001 then apply again; second pass is no-op. |
| `v001_preserves_existing_field_order_when_possible` | `serde_json::Value` preserves key order; we lean on that. |

The V001 implementation logically lives next to the existing `UsersConfig` struct
(`sandbox-core/src/users_conf.rs`) as a pure transform function — `pub fn
migrate_v001(value: serde_json::Value) -> serde_json::Value`. The file-IO wrapper is
Spec 5's job; this spec contributes the pure transform plus its tests.

### 8.3 · Unit tests — `_schema_version` schema field

| Test name | Behavior |
|---|---|
| `schema_version_absent_yields_none` | Today's `users.conf` (no field) parses cleanly with `schema_version = None`. |
| `schema_version_present_populates_option` | `{"_schema_version": 1, ...}` parses with `Some(1)`. |
| `schema_version_typo_rejected` | `"_schemaversion"` trips `deny_unknown_fields`. |

### 8.4 · Integration tests — helper binary

These run under the `integration` nextest profile; the test runner installs a cap'd
copy of the helper via `make install-route-helper-test-cap` per the existing
infrastructure (`sandbox-route-helper/tests/integration_route_helper.rs:43-47`).

| Test name | Behavior |
|---|---|
| `integration_route_helper_accepts_for_user_matching_caller` | Run helper with `--for-user=$RUNNER_USERNAME`; pool contains `[runner]`; expects exit 0, allowed audit line, route installed. |
| `integration_route_helper_denies_for_user_mismatch` | Run helper with `--for-user=bob`; pool contains `[runner]`; expects exit 1, stderr substring `pair-check failed`, denied audit line. |
| `integration_route_helper_defaults_for_user_to_caller_when_omitted` | Run helper *without* `--for-user`; pool contains `[runner]`; expects same outcome as `accepts_for_user_matching_caller`. |
| `integration_route_helper_denies_when_caller_not_in_pool_even_with_valid_for_user` | Pool contains `[bob]` but `--for-user=bob`; caller is runner ≠ bob; expects deny. |
| `integration_route_helper_denies_when_username_unresolvable` | `--for-user=definitely-not-a-real-user-9c3f` (the sentinel name reused from `users_conf.rs:1016-1031`); expects deny with substring `does not resolve to a uid`. |
| `integration_route_helper_denies_when_caller_uid_unresolvable` | Runs the helper from a uid that has been deliberately removed from `/etc/passwd` between fixture setup and helper exec — implemented via a chroot fixture that prepares a mutated `/etc/passwd` (no entry for the test uid), OR via a Lima VM smoke test that creates a temporary user, drops it mid-test via `userdel`, and invokes the helper as the now-stranded uid. Asserts: helper exits `DENY_EXIT` (1), stderr contains the substring `caller uid` and `unresolvable` (or the precise wording from § 3.4 — `caller uid <n> does not resolve to a username`), and the audit log either records a denied entry with `reason` naming the resolution failure or — if the audit write itself fails because the caller cannot be named — emits the stderr escalation per § 3.5. This plugs the coverage gap left by today's softer `ok().flatten()` policy at `sandbox-route-helper/src/main.rs:125`, which is unverified at the integration layer. |
| `integration_route_helper_writes_audit_log_on_allowed` | Verify a JSON line with `decision="allowed"` and both identities lands in the audit-log file. |
| `integration_route_helper_writes_audit_log_on_denied` | Verify a JSON line with `decision="denied"`, `reason` substring, and both identities. |

### 8.5 · Integration tests — daemon → helper propagation

These exercise the daemon-side `SO_PEERCRED` → `RuntimeStartArgs::for_user` → helper
argv path. Live under `sandboxd/sandboxd/tests/`:

| Test name | Behavior |
|---|---|
| `integration_route_helper_for_user_propagated` | Daemon, configured with a stub helper path that records its argv, accepts a `POST /sessions` for a container backend and dispatches `runtime.start`; assert the stub recorded `--for-user=<test-runner-username>` (the daemon-test fixture connects to the daemon as the runner). |
| `integration_route_helper_for_user_falls_through_lima` | Same fixture but Lima backend; `runtime.start` does not invoke the helper; the stub is untouched. |

The stub helper is a tiny binary that prints its argv to a file under `$XDG_RUNTIME_DIR`
then exits `0`. It is *not* cap'd (it does no netns work). The daemon's
`resolve_route_helper_path` already accepts an `SANDBOX_ROUTE_HELPER_PATH` env override
(`sandboxd/sandboxd/src/main.rs:369`), so the test fixture sets that to the stub —
however the resolver requires the cap xattr on the target file
(`sandboxd/sandboxd/src/main.rs:466-485` predicate). To keep the stub un-cap'd, the
fixture either:

- a) uses the existing cap'd test helper from
  `/usr/local/libexec/sandboxd-test/sandbox-route-helper` (built with
  `test-env-override`) and asserts the recorded argv from its stderr/stdout, or
- b) introduces a feature-gated path in `resolve_route_helper_path_from` that skips the
  cap check when a test-only `SANDBOX_ROUTE_HELPER_SKIP_CAP_CHECK=1` env var is set —
  used by *daemon* integration tests only, never by the helper itself.

Choice (a) is preferred because it composes with existing infrastructure and exercises
the production resolver path. The test helper records its `--for-user` argv to stderr
(it already emits a stderr line) — daemon test harnesses can grep that.

### 8.6 · Audit log assertions across tests

Tests in §§ 8.4 and 8.5 share a shape for asserting the audit-log line. Helper:

```rust
fn assert_audit_line(path: &Path, expected_decision: &str, expected_caller: &str,
                     expected_for_user: &str, expected_pool_substr: &str) { … }
```

The audit file is opened fresh per integration test (under `$XDG_RUNTIME_DIR` in
test isolation), the helper is invoked once, then the test reads the file and
verifies exactly one JSON line with the expected fields. The convention mirrors how
existing nft-allow / nft-deny loggers are asserted (`sandbox-event-emitter`-based
patterns).

## 9 · Risks and open questions

### 9.1 · Username resolution failure surface area

The pair-check requires `getpwuid_r(getuid())` and `getpwnam_r(for_user)` to both
return `Ok(Some(_))`. Today's helper softens the first call (`ok().flatten()` at
`sandbox-route-helper/src/main.rs:125`) and uses the result only for stderr. The new
policy is **strict**: an unresolvable identity is a deny. Three places are affected:

1. **Helper side** — strict, as designed; produces a clear stderr message.
2. **Daemon side** — when `SO_PEERCRED` returns a uid that does not resolve, refuse
   the connection (close the socket). This is rare but possible in containers without
   `/etc/passwd` entries for the host's uid range. The dev mode flow always runs as a
   valid local uid, so this won't fire in practice during development.
3. **Helper-side strictness regression** — if a Spec 3 system service user (`sandbox`)
   is provisioned but somehow `getpwnam("sandbox")` fails (e.g. nsswitch order
   misconfigured), the daemon side will fail resolution at startup; the operator
   sees a fast, clear failure on `systemctl status`. This is desired — silent
   degradation is worse.

**Deliberate behavior change — CI implications.** The strict policy is a deliberate
regression from today's softening at `sandbox-route-helper/src/main.rs:125`. The
trade is: today's policy quietly allows pair-checks to succeed for uids without a
`/etc/passwd` entry; the new policy refuses them. This matters most in **container-CI
environments** where the test-running uid is frequently not present in
`/etc/passwd` (minimal CI images, ephemeral runner uids in the host's namespace).
Adopters running integration tests in such environments must either (a) add a
`useradd` step early in the CI workflow so the test uid resolves, or (b) accept
the deny path in their tests and assert against it. The new integration test
`integration_route_helper_denies_when_caller_uid_unresolvable` (§ 8.4) pins the
deny shape so the CI-side fix is straightforward to verify. Spec 2 § 7.5 adds the
**daemon-side** counterpart for the same regression (a test that runs the daemon
in a uid-without-passwd environment and asserts the connection is closed cleanly);
the two tests together cover both sides of the strict-resolution policy.

### 9.2 · Corrupt `users.conf`

If `users.conf` does not parse (invalid JSON, invalid CIDR), today's helper refuses
with a `ParseFailed` / `InvalidCidr` error before reaching pair-check
(`users_conf.rs:101-149`). **This spec preserves that.** The pair-check is gated on
having a parsed config; a parse failure short-circuits as today.

If V001 is partially applied (e.g. the daemon crashed mid-write before atomic rename
— a Spec-5 risk, not Spec-1's), the file is either bit-for-bit pre-V001 (no
`_schema_version`, no `sandbox`) or bit-for-bit post-V001 (both present). Spec 5's
atomic-write spec is responsible for ensuring no intermediate state is observable;
this spec assumes it.

### 9.3 · Pool with only `["sandbox"]` (no operator)

A misconfigured pool listing only `"sandbox"` (operator removed by mistake, or admin
staged the entry before adding the operator name) refuses for any non-`sandbox`
caller. With the pair-check `(caller=alice, for_user=alice)` against `["sandbox"]`,
neither name is present, **deny.** This is the correct behavior — the alternative
(implicit "if `sandbox` is present, any caller is allowed") would defeat isolation.

The post-Spec-3 path where the daemon (running as `sandbox`) calls into an
operator-empty pool with `--for-user=sandbox` would succeed; that is fine because
`sandbox` is by definition the daemon and the action has no operator surface to
disrupt. The unit test in § 8.1 (`pair_check_allows_when_pool_has_only_sandbox_and_caller_is_sandbox`)
pins this.

### 9.4 · `--for-user` argument parsing strategy

Today's helper uses a tiny hand-written `parse_argv` (`sandbox-route-helper/src/main.rs:189-207`)
that demands exactly two positional args. Adding `--for-user` is straightforward (one
new option, then two positionals) but suggests we may want to pull in `clap` at some
point. Spec 1 keeps the hand-written parser — the change is small, and pulling in
`clap` would inflate the cap'd binary's TCB by several thousand lines of code that
needs to be reasoned about for the privilege story. The deliberate tradeoff: a
slightly less ergonomic parser surface in exchange for a smaller, easier-to-audit
helper.

### 9.5 · Atomicity of the audit-log write

The audit log is written after the decision but before the netns mutation runs (for
denied paths the netns mutation never happens; for allowed paths it follows the
audit write). If the helper crashes between the audit write and the `ip route
replace`, the log says "allowed" but no route was installed — the operator's session
will fail at the next network step, but no audit record is lost. This asymmetry is
acceptable: the log records *the decision*, not *the side effect*. Operators
investigating a session failure correlate against the daemon's lifecycle event for
"helper invocation failed", not the audit log alone.

A second asymmetry, between the allow and deny paths on **audit-log write failure**,
is **actively handled** rather than merely acknowledged. See § 3.5 for the
specification: an allow-path log-write failure logs to stderr and continues
(routing-path-availability wins); a deny-path log-write failure logs to stderr
**and exits `DENY_EXIT` (1)** to surface the missing forensic record. This trades
one bit of behavior — non-zero exit on the deny path even though the deny itself
already happened — for a load-bearing security-audit invariant: a forensic record of
"alice tried to mess with bob's pool" never disappears silently. The deny-path
availability is unchanged (the deny still occurs regardless of log state); only the
forensic-record-availability invariant gains explicit escalation.

### 9.6 · Race between caller `getuid()` and `--for-user` resolution

Both `getpwuid_r` and `getpwnam_r` consult `/etc/passwd` (or NSS). A simultaneous
`usermod` could in principle yield a `caller_name → uid` mapping that differs from
`for_user → uid` if `for_user` happened to be the same name. In practice the spec
treats this as a TOCTOU acceptable risk: `usermod` while a session is being created
is an admin-action conflict, and the worst outcome is a denied helper call (the
caller retries after the rename settles). No correctness invariant is at stake.

## 10 · Out of scope

The following are **not** in Spec 1:

- **Spec 5** — The config migration framework itself: the migration registry, the
  "apply pending migrations on startup" loop, the atomic-rename write mechanism, the
  lock file under `/run/sandbox/`, the backup folder, and the daemon's
  schema-mismatch refusal that triggers `sandbox update`. This spec describes V001's
  *content* only.
- **Spec 3** — File-mode tightening on `/var/lib/sandbox/`, the dedicated `sandbox`
  system user, the systemd unit, the `sandbox doctor` command, and version pinning.
  This spec assumes Spec 3 will land but does not depend on it for the security
  story — the pair-check is defense-in-depth-meaningful today, before Spec 3.
- **Spec 2** — API-layer session ownership (`owner_username` column, per-caller
  filter on `GET /sessions`, ownership enforcement on `POST /sessions/{id}/...`),
  guest binary version compatibility, and refresh-in-place. Spec 2 will use the same
  `OperatorIdentity` extension that Spec 1 introduces; it is the next consumer of
  the `SO_PEERCRED` plumbing.
- **Specs 4 / 5** — Any release, install, uninstall, or update infrastructure:
  signed builds, GitHub Pages-hosted scripts, the Lima test harness, the `sandbox
  update` CLI, the rollback mechanism. None of this affects Spec 1.
- **Adding `clap` or any new dependency to `sandbox-route-helper`.** See § 9.4.
- **IPv6 support in pair-check.** The helper is IPv4-only today
  (`sandbox-route-helper/src/main.rs:266-281`); this spec preserves that scope.

## 11 · Implementation notes (light)

A short bullet list of expected implementation touch points; not a plan, just a
sanity check that the spec's scope maps to a tractable change-set.

| Path | Kind of change |
|---|---|
| `sandboxd/sandbox-route-helper/src/main.rs` | Argv parser accepts optional `--for-user`. Step-1 caller-name resolution becomes strict. New pair-check function between steps 3 and 5. New `audit` module for JSON-Lines append-only writes. `DENY_EXIT` unchanged. |
| `sandboxd/sandbox-core/src/users_conf.rs` | Add `schema_version: Option<u32>` with `#[serde(default, rename = "_schema_version")]` to `UsersConfig`. Add pure transform `migrate_v001(serde_json::Value) -> serde_json::Value`. Add unit tests for both. |
| `sandboxd/sandboxd/src/main.rs` | Custom acceptor wrapping `UnixListener` accepts; reads `SO_PEERCRED`, resolves to `OperatorIdentity`, attaches via `Extension`. Refuses on unresolvable uid. |
| `sandboxd/sandboxd/src/main.rs` (handlers) | `create_session` (≈ line 899) and `start_session` (≈ line 2661) gain `Extension<OperatorIdentity>` arg; thread `for_user: Some(operator.name)` into `RuntimeStartArgs`. |
| `sandboxd/sandbox-core/src/backend/mod.rs` | `RuntimeStartArgs` gains `for_user: Option<String>`. |
| `sandboxd/sandbox-core/src/backend/container.rs` | `ContainerRuntime::start` reads `for_user` from `RuntimeStartArgs`, passes to `invoke_route_helper`. `invoke_route_helper` signature gains `for_user: &str` and adds `.arg("--for-user").arg(for_user)` to the `Command`. |
| `sandboxd/sandbox-core/src/backend/lima.rs` | Threads `for_user` through `RuntimeStartArgs` (no behavioral effect — Lima does not invoke the helper). |
| `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs` | New tests per § 8.4. The `run_helper` helper already exists and accepts an args slice; tests pass the new `--for-user` argv. |
| `sandboxd/sandboxd/tests/` | New file (e.g. `integration_route_helper_propagation.rs`) for the daemon-side propagation tests per § 8.5. |

V001's migration file (e.g. `migrations/users_conf/V001__add_sandbox_to_pools.rs` or
similar — naming TBD by Spec 5) is **not** created by Spec 1; the pure
`migrate_v001` transform function and its tests are what Spec 1 contributes. Spec 5
will wire the transform into the framework registry when it lands.

## 12 · Affected files — summary

| Path | Touch type |
|---|---|
| `sandboxd/sandbox-route-helper/src/main.rs` | Edit: argv, pair-check, audit log, strict username resolution |
| `sandboxd/sandbox-route-helper/Cargo.toml` | Edit: add `serde_json` for audit-log writes (if not already present) |
| `sandboxd/sandbox-core/src/users_conf.rs` | Edit: `_schema_version` field; `migrate_v001` transform; tests |
| `sandboxd/sandbox-core/src/backend/mod.rs` | Edit: `RuntimeStartArgs::for_user` |
| `sandboxd/sandbox-core/src/backend/container.rs` | Edit: helper invocation site, `invoke_route_helper` signature |
| `sandboxd/sandbox-core/src/backend/lima.rs` | Edit: `RuntimeStartArgs` plumbing (no behavior change) |
| `sandboxd/sandboxd/src/main.rs` | Edit: custom acceptor; `OperatorIdentity` extension; thread through `create_session` / `start_session` |
| `sandboxd/sandbox-route-helper/tests/integration_route_helper.rs` | Edit: new pair-check coverage |
| `sandboxd/sandboxd/tests/integration_route_helper_propagation.rs` | New: daemon → helper propagation tests |
| `docs/start/installation.md` | Edit: brief note about the `_schema_version` field and the `sandbox` convention (forward-compat for operators editing the file by hand) |
