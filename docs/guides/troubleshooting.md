---
title: Troubleshooting
description: Diagnose and fix common sandboxd issues — VM boot failures, gateway health, TLS errors, DNS, networking, and policy propagation.
---

Common issues and solutions for sandboxd operators. Each section lists the symptom, how to diagnose it, and how to fix it.

If you are just getting started, check [Installation](/start/installation/) for setup-time errors. For command reference, see the [CLI reference](/reference/cli/).

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

This is the fail-closed DNS-propagation window. Envoy's L3 filter chains match on the connection's original destination IP, and sandboxd can only populate those IPs after CoreDNS has resolved the name. Between the policy taking effect and the first DNS answer being propagated into Envoy's listener file, a connection to the unresolved IP hits no filter chain and is dropped — deliberately, not silently forwarded.

Fix: warm DNS before the first real request, or just retry. Either is harmless.

```bash
# Inside the VM:
getent hosts api.newdestination.example   # triggers CoreDNS -> propagation
curl -sSf https://api.newdestination.example/...
```

See [networking → Fail-closed propagation](/concepts/networking/#fail-closed-propagation-for-level-3) for why this is the designed behavior.

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

## File transfer failures

### Path validation

**Symptom:** `path must be within one of: /home/agent/, /root/, /tmp/`

The guest agent only allows file transfers to `/home/agent/`, `/root/`, and `/tmp/`. Paths with `..` traversal are rejected. Paths under `/proc`, `/sys`, `/dev`, `/etc` are always denied.

Fix: use an allowed path (`sandbox cp file.txt <session>:/home/agent/workspace/file.txt`). For system directories, use `sandbox exec` instead.

### Message size limit

**Symptom:** `message size exceeds maximum`

The protocol has a 1 MB limit. Files larger than about 750 KB (after base64 overhead) will fail.

Fix: use Lima's copy (`limactl copy file.tar.gz sandbox-<session_id>:/tmp/`) or shared workspace mode.

## Performance issues

### Cgroup limits

**Symptom:** Processes killed unexpectedly or throttled inside the VM.

```bash
systemctl --user status sandbox.slice
```

Fix: create sessions with more resources (`sandbox create --cpus 4 --memory 8192`).

### Disk I/O

Slow I/O causes: thin-provisioned disk growth, host disk contention, 9p overhead on shared mounts. For disk-intensive workloads, use clone mode (`--repo`) instead of shared mounts.

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
