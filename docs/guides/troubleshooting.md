---
title: Troubleshooting
description: Diagnose and fix common sandboxd issues — VM boot failures, gateway health, TLS errors, DNS, networking, and policy propagation.
---

Common issues and solutions for sandboxd operators. Each section lists the symptom, how to diagnose it, and how to fix it.

If you are just getting started, check [Installation](/start/installation/) for setup-time errors. For command reference, see the [CLI reference](/reference/cli/).

## Which layer denied my request?

Before diving into component-specific symptoms below, check the unified event stream — every policy-enforcing layer (CoreDNS, nft-deny-logger and nft-allow-logger, Envoy, mitmproxy) writes a per-decision event there, and sandboxd exposes the whole stream through `sandbox events`.

```bash
# Live deny-only stream, auto-tabular in a TTY:
sandbox events <session> --decision=deny --follow

# Only the nft-loggers (deny-logger plus allow-logger — both report under
# the `deny-logger` layer; allow events carry `event: "allow"`):
sandbox events <session> --layer=deny-logger --follow

# Just the per-flow UDP allow audit (allow-logger writes here):
sandbox events <session> --event=allow --follow
```

How to read the result:

- **`layer: dns`, decision `deny`** — CoreDNS refused the name (`NXDOMAIN`). The domain is not covered by the policy, or the wildcard does not match the apex. See [DNS resolution issues](#dns-resolution-issues).
- **`layer: deny-logger`, `event: "deny"`** — a packet reached the firewall but matched no `policy_allow_{tcp,udp}` entry. Either the destination is truly unauthorized, or DNS hadn't propagated for it yet. See [L3 destination fails on first request](#l3-destination-fails-on-first-request-after-policy-change) for the race and [Non-HTTP traffic to a level `http` destination](#non-http-traffic-to-a-level-http-destination) for non-TCP-over-port-443 misses. For UDP-specific deny diagnosis (silent drop, no ICMP unreachable), see [UDP traffic](#udp-traffic).
- **`layer: deny-logger`, `event: "allow"`** — a UDP flow was admitted (per-flow audit, not per-packet). The nft-allow-logger emits these by subscribing to the kernel's conntrack `NFCT_T_NEW` event stream; events ride the same `deny-logger` layer envelope as the deny path. Useful for confirming an allowed UDP exchange actually started; see [How do I read the allow event](#how-do-i-read-the-allow-event) and [the 30 s NFCT-rollover behaviour](#i-see-the-same-allow-event-twice-for-one-apparent-session). TCP allow-flow audit is provided by Envoy's access log instead.
- **`layer: envoy`, decision `deny`** — Envoy's listener / chain match rejected the connection (wrong SNI for a `tls` rule, no filter chain for the `(ip, port)` pair, etc.).
- **`layer: mitmproxy`, decision `deny`** — the request reached mitmproxy but no `http_filters` entry matched. The event's `reason` names the specific check that failed (host, port, method/path). Mitmproxy strips the query string from the path before matching, so a filter like `GET /api/v1/**` matches regardless of whatever the caller appended after `?`.

`sandbox events --event=policy_propagated --follow` is useful during policy churn: the event fires on each hash transition after all three enforcement layers reconcile, so you know the new rules are actually live rather than mid-propagation.

## VM won't boot

### KVM permissions

**Symptom:** `limactl start: KVM not available -- is /dev/kvm accessible?`

```bash
ls -la /dev/kvm           # Does the device exist?
groups | grep -w kvm      # Is your user in the kvm group?
```

Fix: `sudo usermod -aG kvm $USER` then log out and back in. If `/dev/kvm` does not exist, enable hardware virtualization in BIOS/UEFI. In cloud VMs, enable nested virtualization.

### Memory limits (OOM)

**Symptom:** QEMU is OOM-killed shortly after boot, or the VM never transitions from `Creating` to `Running`.

```bash
free -h                                   # Available memory
dmesg | grep -i oom | tail -20            # OOM kill events
systemctl --user status sandbox.slice     # Cgroup memory usage
```

The default VM uses 4096 MB. The host needs about 3.8 GB free per session. Fix: create sessions with less memory (`sandbox create --memory 2048`) or increase host RAM.

If `systemd-run` is not available, QEMU runs without cgroup limits and a memory-hungry guest can trigger the host OOM killer. Check with `command -v systemd-run`. Enable user sessions with `loginctl enable-linger $USER`.

## Gateway unhealthy

**Symptom:** `sandbox health` shows gateway components as unhealthy, or the container is in a crash loop.

```bash
sandbox health <session>

# Check individual components directly
docker exec sandbox-gw-<session_id> curl -sf http://127.0.0.1:9901/ready    # Envoy
docker exec sandbox-gw-<session_id> curl -sf http://127.0.0.1:8180/health   # CoreDNS
docker exec sandbox-gw-<session_id> pgrep -x mitmdump                       # mitmproxy

# Restart count and status
docker inspect --format '{{.RestartCount}} restarts, status={{.State.Status}}' \
    sandbox-gw-<session_id>

# Logs (CLI or Docker)
sandbox logs <session> --tail 50
docker logs --tail 50 sandbox-gw-<session_id>
```

Common causes:

- **Port conflict** — another process on the host is using a gateway port.
- **CA files missing** — the CA directory was deleted while the session was stopped.
- **Resource exhaustion** — host out of memory or file descriptors.

Fix: for missing CA files, `sandbox rm` and recreate the session. For resource issues, free host resources. Component-specific logs: `sandbox logs <session> --component envoy|mitmproxy|coredns`.

## TLS / certificate errors

### CA not trusted

**Symptom:** Applications inside the VM reject HTTPS connections.

```bash
# Inside the VM:
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>&1 \
    | grep "verify return"
ls /usr/local/share/ca-certificates/sandbox-ca.crt
echo $SSL_CERT_FILE $NODE_EXTRA_CA_CERTS
```

Fix: if the CA file exists, re-run `sudo update-ca-certificates` inside the VM. If missing, stop and start the session — CA injection is re-performed on every start.

### mitmproxy not running

**Symptom:** TLS connections fail immediately or hang.

```bash
sandbox health <session>                    # Check mitmproxy status
docker exec sandbox-gw-<session_id> ls -la /root/.mitmproxy/   # CA files present?
```

Expected files: `mitmproxy-ca.pem` and `mitmproxy-ca-cert.pem`. If missing, restart the session.

### SKI/AKI mismatch

**Symptom:** "unable to get local issuer certificate" even though the CA is in the trust store.

```bash
# Inside the VM: compare SKI on CA cert with AKI on intercepted cert
openssl x509 -in /usr/local/share/ca-certificates/sandbox-ca.crt \
    -text -noout | grep -A1 "Subject Key Identifier"
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>&1 \
    | openssl x509 -text -noout | grep -A1 "Authority Key Identifier"
```

The SKI and AKI must match. sandboxd uses SHA-1 of the raw public key (RFC 5280 method 1) to match mitmproxy's behavior. Fix: remove and recreate the session to regenerate the CA.

## DNS resolution issues

### CoreDNS not running

**Symptom:** All DNS queries fail.

```bash
sandbox health <session>
sandbox logs <session> --component coredns
docker exec sandbox-gw-<session_id> dig @127.0.0.1 example.com
```

Fix: restart the session to recreate the gateway with fresh components.

### Policy not allowing the domain

**Symptom:** Specific domains return `NXDOMAIN`.

Wildcard rules (`*.github.com`) do **not** match the apex domain (`github.com`). You need both rules. Check CoreDNS logs for denied queries:

```bash
sandbox logs <session> --component coredns --tail 200
```

Fix: update the policy — `sandbox policy update <session> corrected-policy.json`.

### Hardcoded DNS resolvers

Applications that hardcode resolvers (e.g., `8.8.8.8`) are still forced through CoreDNS. nftables DNAT rules redirect all DNS traffic (UDP/TCP port 53) regardless of the destination. This is expected behavior.

## Network connectivity

### TAP device missing

**Symptom:** Management SSH works, but no traffic flows through the gateway.

```bash
# Host: check TAP device
ip link show | grep tb-

# VM: check data interface and routes
ip addr show       # Look for .3 address
ip route           # Default route should go through .2 with metric 50
```

If the TAP is missing, the bridge/TAP setup via `qemu-bridge-helper` may have failed. Check: `journalctl -u sandboxd | grep -i "bridge\|tap\|qemu-bridge-helper"`. Fix: stop and start the session.

### Docker bridge missing

```bash
docker network ls --filter label=sandbox.session_id
docker network inspect sandbox-net-<session_id>
```

If missing, the session's networking was torn down. Fix: `sandbox start <session>`.

### nftables rules missing

**Symptom:** Gateway is healthy but VM traffic is rejected.

```bash
docker exec sandbox-gw-<session_id> nft list ruleset
```

Look for `table inet sandbox` (deny-all base) and `table inet sandbox_dnat` (DNAT routing). If `sandbox_dnat` is missing, restart the session:

```bash
sandbox stop <session> && sandbox start <session>
```

## UDP traffic

UDP behaves differently from TCP in the gateway: there is no userland proxy on the data path, the deny path is silent at the network level (no ICMP unreachable), and audit events arrive per-flow rather than per-packet. The entries below cover the most common UDP-specific symptoms.

### UDP traffic isn't working

**Symptom:** A UDP-using application inside the VM (NTP client, DNS-over-UDP for non-system resolvers, custom UDP service) doesn't receive responses, and `sandbox health` reports the gateway as healthy.

Check the unified event stream first — the answer is almost always there:

```bash
# UDP allow events for the session, live (allow-logger flows under
# the `deny-logger` layer; filter by event name).
sandbox events <session> --event=allow --follow

# UDP (and TCP) deny events for the session.
sandbox events <session> --layer=deny-logger --decision=deny --follow
```

Walk the checklist:

1. **Does any rule cover the destination?** A UDP rule must declare `protocol: "udp"` explicitly; a TCP rule does not implicitly cover UDP. Confirm with `sandbox describe <session>`. If the destination isn't named, add a `transport`-level UDP rule (see [the UDP destinations section](/guides/network-policies/#udp-destinations)) and `sandbox policy update`.
2. **Did DNS propagate the IP into `policy_allow_udp`?** For domain-based UDP rules (e.g. `ntp.ubuntu.com:123`), the rule's IPs land in nft only after CoreDNS resolves them and sandboxd injects them. A bare-IP UDP rule (CIDR literal) is in the set immediately. Check the live state:
   ```bash
   docker exec sandbox-gw-<session_id> nft list set inet sandbox_dnat policy_allow_udp
   ```
3. **Did NFLOG record a deny?** If the policy doesn't cover the destination, you'll see a JSONL `event: "deny"` record in the events stream with `protocol: "udp"` and the original 5-tuple. The VM-side socket sees only timeouts (no ICMP unreachable — see [Why don't I get ICMP unreachable](#why-dont-i-get-icmp-unreachable-on-a-denied-udp-send) below for the rationale).

If a rule covers the destination, the IP is in `policy_allow_udp`, and there is no deny event — but the VM still doesn't get a response — the upstream is not responding. UDP is connectionless; the gateway can confirm the request left, but it cannot tell you why a reply never arrived. Tcpdump on the bridge interface from the host side is the next step.

### How do I read the allow event?

`sandbox-nft-allow-logger` writes one JSONL line per new allowed UDP flow into the gateway's events directory. The file name is `nft-allow.jsonl` (mounted from the per-session events directory at `/var/log/gateway/events/<session-id>/nft-allow.jsonl`). Each line carries:

- `timestamp` — ISO 8601, when the logger observed the `NFCT_T_NEW` event (within milliseconds of the kernel creating the conntrack entry).
- `event` — always `"allow"`.
- `layer` — emitter tag. Allow-logger records ride the `deny-logger` layer envelope (the layer name reflects the legacy single-process design; both nft-loggers share that layer). Filter by `--event=allow` to isolate them.
- `protocol` — always `udp` for this file (the logger filters NFCT events for UDP at parse time).
- `src_ip`, `src_port` — the VM-side endpoint, original-direction tuple source.
- `orig_dst_ip`, `orig_dst_port` — the upstream destination the VM dialed (no DNAT on the UDP allow path, so this is the literal destination address).

You normally read these via the unified event stream rather than the file directly:

```bash
# Live stream of allow events only.
sandbox events <session> --event=allow --follow

# All events for the session, including allow + deny + DNS + Envoy + mitmproxy.
sandbox events <session> --follow
```

The granularity matters: this is **per conntrack flow, not per packet**. A long-lived UDP exchange (e.g. an NTP client sampling a server every 64 seconds) produces one allow record at the start of each flow, not one per datagram. See the next entry for what makes a "new flow."

### I see the same allow event twice for one apparent session

**Symptom:** A long-running UDP exchange to the same upstream `(IP, port)` produces two (or more) allow events spaced apart in time, even though from the application's point of view it's the same conversation.

This is the kernel's UDP conntrack rollover, not a bug. UDP is connectionless — there is no protocol-level way to tell when a "session" ends. The kernel approximates session lifetime with a timeout: if a tracked UDP flow sees no traffic for a configurable interval (`net.netfilter.nf_conntrack_udp_timeout`, default **30 seconds**), conntrack ages the entry out. The next packet on the same 5-tuple opens a new conntrack flow and fires a new `NFCT_T_NEW` event — `sandbox-nft-allow-logger` writes a new allow record.

So an NTP client polling every 64 seconds will produce one allow record per poll, an active 1-second-interval audio stream will produce a single record at the start (or roughly one per outage), and a chatty short-lived exchange may produce many records depending on idle gaps.

To inspect the kernel's view directly:

```bash
docker exec sandbox-gw-<session_id> sysctl net.netfilter.nf_conntrack_udp_timeout
docker exec sandbox-gw-<session_id> conntrack -L -p udp 2>/dev/null
```

The expected per-flow audit shape is documented in [policy model → UDP-specific caveats](/concepts/policy-model/#udp-specific-caveats) and the design rationale in the [UDP subsection of the networking design](/concepts/networking/#nftables).

### Why don't I get ICMP unreachable on a denied UDP send?

**Symptom:** A UDP datagram to a non-allowed destination doesn't trigger the application's "destination unreachable" error path. The application sees only a recv timeout.

This is intentional. Denied UDP is **silent dropped** at nft — there is no `nft reject with icmp port-unreachable` rule. Two reasons:

1. **Defence-in-depth against probing.** ICMP unreachables would let a sandboxed application enumerate the gateway's policy structure (which IPs are not in `policy_allow_udp`, which ports are unbound on which upstream hosts) by sending probe datagrams and observing the error responses. Silent drop closes that side channel.
2. **The audit log already attributes the deny.** The kernel emits an NFLOG group 1 message before the drop completes, and `sandbox-nft-deny-logger` writes a JSONL `event: "deny"` record carrying the original 5-tuple. Operator-side observability is preserved; only the in-VM probing surface is narrowed.

If you need to confirm a specific datagram was denied (rather than lost in transit or upstream-dropped), tail the deny stream:

```bash
sandbox events <session> --layer=deny-logger --decision=deny --follow
```

A matching `event: "deny"` record with `protocol: "udp"` and the 5-tuple your application sent confirms the gateway dropped it. No matching record means the datagram either wasn't dropped (so the upstream is the silent party) or was dropped further upstream than the gateway.

## Policy not taking effect

**Symptom:** Policy update was applied but behavior has not changed.

```bash
sandbox logs <session> --component coredns --tail 50
sandbox logs <session> --component envoy --tail 50
journalctl -u sandboxd --since "5 minutes ago" | grep -i "policy\|compile"
```

The policy must compile into all four component configs (CoreDNS, nftables, Envoy, mitmproxy). If any step fails, the previous policy remains active.

After a successful update, there is a brief reload window (under 1 second) where the old policy is still active. DNS TTL caching in the guest OS can also cause stale behavior — restart the application to force fresh resolution.

### L3 destination fails on first request after policy change

**Symptom:** A freshly added level `http` destination returns `Connection refused` or a TLS handshake timeout on the very first request, then succeeds on retry.

In normal operation this should not happen — the synchronous DNS-policy gate holds the DNS answer until sandboxd has injected the resolved IP into nft and Envoy has acked the new listener generation. If you are seeing this, the gate failed open at its deadline (default 1500 ms) and traffic that followed raced the steady-state reconciler. Look for a `dns_gate_timed_out` lifecycle event on the session's event stream — it confirms the fallback path fired and points at sandboxd-side latency (loaded host, slow Envoy LDS ack, etc.) as the underlying cause.

If a retry succeeds, the steady-state reconciler closed the gap. From the host, scripts that apply a policy and then dial it can block on the propagation event directly:

```bash
# Apply the policy, then block until every enforcement layer has reconciled.
sandbox policy update <session> --policy ./new-policy.json
sandbox policy status <session> --wait --timeout 10s
```

`sandbox policy status --wait` polls until the session's applied policy hash matches the most recent `policy_propagated` lifecycle event, then exits 0. Under the hood the same event is available on the unified stream as `sandbox events <session> --event policy_propagated --follow`.

See [networking → Synchronous DNS-policy gating](/concepts/networking/#synchronous-dns-policy-gating) for the design.

### Non-HTTP traffic to a level `http` destination

**Symptom:** A non-HTTP protocol (SSH, raw TCP, binary RPC) to a host covered by a level `http` rule connects, but the client then sees an immediate connection reset or a garbled protocol error.

mitmproxy expects HTTP/HTTPS on its forward-proxy port. The Envoy L3 filter chain will happily establish the CONNECT tunnel into mitmproxy — the TCP handshake works — but mitmproxy rejects the bytes once they fail HTTP parsing. The client sees whatever the application layer makes of a closed tunnel: usually a reset mid-handshake or a spurious HTTP error frame.

Fix: do not put non-HTTP destinations at level `http`. Drop them to `tls` (SNI-verified passthrough) or `transport` (opaque TCP):

```json
{"host": "git.example.com", "port": 443, "protocol": "tcp", "level": "transport"}
```

### Verify L3 inspection is actually happening

**Symptom:** You want to confirm a level `http` destination is being intercepted, not silently passed through.

The simplest indicator is the certificate: a level `http` destination must serve the per-session CA's certificate, not the real origin's. An intercepted response has an issuer of `Sandbox CA {session_id}`.

```bash
# Inside the VM — should print "Sandbox CA <12-hex>"
openssl s_client -connect api.example.com:443 -servername api.example.com </dev/null 2>/dev/null \
    | openssl x509 -noout -issuer

# Complementary check from the gateway — mitmproxy logs a
# `server connect <orig-ip>:<port>` line for each tunneled flow.
sandbox logs <session> --component mitmproxy --tail 50 \
    | grep -Ei 'server connect|\[ALLOW\]'
```

If the issuer is anything other than `Sandbox CA ...`, the destination is not being inspected. The two likely reasons are: the rule is at level `tls` or `transport` rather than `http`; or the destination does not have a resolved IP yet and the request was denied (see the propagation-window FAQ above).

## Preset errors

### Unknown preset

**Symptom:** `sandbox create --preset 'npm-internal:'` exits with `Error: unknown preset 'npm-internal'`.

Either the preset name is mistyped, or the JSON file under `$XDG_CONFIG_HOME/sandboxd/presets/` failed to load. Malformed user-preset files emit a warning to stderr on every invocation and are skipped — run the command with `RUST_LOG=info` to see the warning, or inspect the preset directory:

```bash
ls "${XDG_CONFIG_HOME:-$HOME/.config}/sandboxd/presets/"
sandbox policy preset list                              # what the CLI actually sees
```

Fix: correct the JSON (common culprits: unknown top-level fields, duplicate param names, `${param}` references to undeclared params, `name` containing `.` / `:` / `,` / `=`).

### User preset shadows a built-in

**Symptom:** `Error: preset 'npm' is defined by both a built-in and a user file at <path>; user presets cannot shadow built-ins; rename or delete the user file.`

Each user-preset file's `name` field must not collide with a built-in. Shadowing is rejected at invocation time (not at load time — a latent shadow file does not break unrelated commands).

Fix: rename the file and its `name` field to something that does not collide (for example, `npm-internal.json` with `"name": "npm-internal"`).

### `(host, port)` collision across preset and policy

**Symptom:** `Error: policy validation failed: duplicate destination (registry.npmjs.org, 443)` listing every contributing source (policy file path, preset invocation string).

Every `(host, port)` pair in the effective policy must be declared exactly once. Overlapping rules across a `--policy` file and one or more `--preset` flags — or across two presets — are contradictions and are rejected.

Fix: remove the overlapping rule from the policy file, drop one of the overlapping presets, or change the colliding `(host, port)` in the policy file to something that does not overlap.

## Event-attribution gotchas

### mitmproxy events do not carry the VM's bridge IP

**Symptom:** You filter `sandbox events` by source IP and get no mitmproxy rows, or the rows look wrong.

By the time a request reaches mitmproxy, the connection's peer is Envoy's loopback-connect source — not the VM. The mitmproxy ingestor therefore attributes its events to the per-session watcher that produced the record (one watcher per session, each tailing its own mitmproxy JSONL log), not via the `(vm_ip → session_id)` map used for the other layers. Sessions are still attributed correctly on the envelope; only the `client_ip` field, if you look at it, will not be a VM IP.

Fix: filter by `layer=mitmproxy` and the session ID, not by a VM bridge IP. The envelope's `session` field is authoritative for attribution.

### nft-deny-logger reports pre-DNAT 5-tuple

**Symptom:** A deny event on the deny-logger layer shows a destination IP that does not match what the application dialed.

`sandbox-nft-deny-logger` records the original 5-tuple from the kernel, before any DNAT could mutate it. The exact source depends on protocol: TCP-deny reads the pre-DNAT destination via `SO_ORIGINAL_DST` on the accepted (DNAT-redirected) socket; UDP-deny pulls the 5-tuple from the kernel-emitted NFLOG group 1 message (and there is no DNAT on the UDP-deny path, so the destination in the NFLOG payload is literally what the VM dialed). Either way the event names what the VM was trying to reach, not the gateway's listener address. See the [networking concept guide](/concepts/networking/) for the full datapath.

## File transfer failures

`sandbox cp` dispatches to the backend's native copy tool (`limactl cp` for Lima, `docker cp` for container sessions), so the symptoms you see come from those tools verbatim. The most common failure modes:

### Source file does not exist

**Symptom (Lima):** `lost connection` or `scp: <path>: No such file or directory`. **Symptom (container):** `Error response from daemon: Could not find the file <path> in container ...`.

Fix: double-check the path on the side reporting the error. Remember the syntax: `session:path` is the session side, plain paths are the host side.

### Session not running / not found

**Symptom (Lima):** `instance "sandbox-<id>" does not exist` or `instance "sandbox-<id>" is stopped, run `limactl start ...` to start it`. **Symptom (container):** `Error response from daemon: No such container: sandbox-<id>` (when the session was deleted) or — uniquely on the container backend — copy *succeeds* against a stopped container because `docker cp` reads/writes the storage layer directly.

Fix: `sandbox start <session>` first. The container-backend behavior of copying against a stopped container is intentional and matches `docker cp`'s native semantics.

### `limactl` or `docker` not on PATH

**Symptom:** `Error: failed to execute limactl: ...` or `Error: failed to execute docker: ...`.

Fix: install the missing dependency. The CLI no longer relays file content through the daemon, so the host running `sandbox cp` needs the same binary the daemon would use to manage the session.

### `sandbox sync` against a stopped session

**Symptom (Lima):** rsync's remote-shell exits before the protocol handshake; you'll see something like `instance "sandbox-<id>" is stopped, run \`limactl start ...\` to start it` from `limactl shell` followed by rsync's own `rsync error: unexplained error (code 255) at ...`. **Symptom (container):** `docker exec` exits with `Error response from daemon: Container <hash> is not running` and rsync wraps it in the same `unexplained error (code 255)` line.

`sandbox sync` uses `rsync -e "limactl shell"` (Lima) or `rsync -e "docker exec -i"` (container) as its remote-shell transport, and unlike `docker cp`, neither shell can attach to a stopped session — the directory protocol needs a live process on both sides.

Fix: `sandbox start <session>` first.

## Performance issues

### Cgroup limits

**Symptom:** Processes killed unexpectedly or throttled inside the VM.

```bash
systemctl --user status sandbox.slice
```

Fix: create sessions with more resources (`sandbox create --cpus 4 --memory 8192`).

### Disk I/O

Slow I/O causes: thin-provisioned disk growth, host disk contention, 9p overhead on shared mounts. For disk-intensive workloads, use clone mode (`--repo`) instead of shared mounts.

## Session create refused — route-helper denied

**Symptom:** `sandbox create` fails late in the create flow with an error mentioning the route helper, networking setup, or a per-session lifecycle event of the shape `route_helper_failed exit=1`. The daemon's journal shows the helper invocation that refused.

The route helper enforces a **pair-membership rule**: the operator invoking it (`getuid()` of the helper process, resolved to a username) and the operator the network is being installed for (`--for-user <name>`, defaulting to the caller) must both appear in the `allow_users` list of the subnet pool the route is being installed into (`/etc/sandboxd/users.conf`). Any mismatch is denied; the helper exits non-zero, the daemon surfaces the failure as the session-create lifecycle event, and the session is rolled back.

Every helper invocation — allowed or denied — writes one JSON-Lines record to the audit log. To diagnose a deny:

```bash
# Production (post-Spec-3 daemon runs as the `sandbox` user):
sudo -u sandbox tail -n 20 /var/lib/sandbox/route-helper-audit.log

# Today's-mode / dev-mode (daemon runs as the invoking operator):
tail -n 20 "$XDG_RUNTIME_DIR/sandboxd/route-helper-audit.log"
# Or, if XDG_RUNTIME_DIR is unset (rare): ~/.local/share/sandboxd/route-helper-audit.log
```

The last record corresponds to the failing create attempt. Each record has the shape:

```json
{"ts":"2026-05-11T14:23:11.477Z","decision":"denied","reason":"pair-check failed","caller":"alice","for_user":"bob","pool":"10.210.0.0/20","gateway_ip":"10.210.0.2","pid":12346}
```

The **`reason`** field carries a short tag for the deny class. Common values:

- `"pair-check failed"` — either `caller` or `for_user` (or both) is not in the target pool's `allow_users`. Edit `/etc/sandboxd/users.conf` to add the missing operator to the pool, then retry. The `sandbox` daemon user is added automatically by config migration V001; if it is missing for a pool, the file's `_schema_version` likely predates V001 (`sandbox update` migrates it forward).
- `"gateway-ip not in any subnet"` — the daemon asked for a gateway IP that does not fall into any configured pool's CIDR. This is a daemon-side or `users.conf` configuration drift, not an operator-permissions issue.
- `"username resolution failed"` — `getpwuid_r` could not resolve the helper's UID (e.g., the caller's `/etc/passwd` entry vanished). Restore the entry and retry.

If the audit log itself is missing or the deny path was hit with a write failure, `journalctl -u sandboxd` will show a non-zero helper exit even when no audit record was written — a write failure on the deny path is explicitly escalated (the helper still exits non-zero with a stderr line) so the missing-record case never silences the deny. In that case, check `df -h /var/lib/sandbox` (production) or `df -h $XDG_RUNTIME_DIR` (today's mode) for disk-pressure root causes.

## Session stuck in Creating

**Symptom:** Session stays in `Creating`, never reaches `Running`.

```bash
sandbox ps
journalctl -u sandboxd --since "10 minutes ago" | grep <session_id>
```

Common hang points: guest agent timeout (45s), Docker/gateway setup failure, component readiness timeout (45s).

Fix: remove and recreate:

```bash
sandbox rm <session>
sandbox create --name <name>
```

If persistent, check host prerequisites: `docker info`, `limactl list`, `ls /dev/kvm`.

## Diagnostic commands

Quick reference:

```bash
# Session state
sandbox ps                                    # List sessions
sandbox health <session>                      # Detailed health

# Gateway logs
sandbox logs <session>                        # All components
sandbox logs <session> --component envoy      # Envoy only
sandbox logs <session> --follow               # Stream live

# Docker
docker ps --filter label=sandbox.session_id   # Gateway containers
docker network ls --filter label=sandbox.session_id  # Session networks

# nftables
docker exec sandbox-gw-<session_id> nft list ruleset

# Inside the VM
ip addr show                                  # Interfaces
ip route                                      # Routes
systemctl status sandbox-guest                # Guest agent

# Host
ip link show | grep -E 'tb-|sb-'             # TAP/bridge devices
systemctl --user status sandbox.slice         # Cgroup usage
journalctl -u sandboxd --since "1 hour ago"  # Daemon logs
```
