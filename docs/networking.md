# Networking

This guide explains how networking works in claude-sandbox from an operator's perspective: what infrastructure is created for each session, how traffic flows from the VM to the internet, and how to diagnose issues.

## Overview

Every sandbox session gets an isolated network stack with:

- **Per-session network** -- a dedicated Docker bridge with a /28 subnet, ensuring sessions cannot communicate with each other.
- **Gateway container** -- a Docker container running the proxy pipeline (Envoy, mitmproxy, CoreDNS) that mediates all outbound traffic from the VM.
- **DNS interception** -- all DNS queries from the VM are redirected to a CoreDNS instance inside the gateway, regardless of what resolver the application tries to use.
- **TLS interception** -- a per-session CA certificate is generated at session creation time. mitmproxy uses it to inspect HTTPS traffic. The CA public certificate is injected into the VM's trust store so applications accept the intercepted connections transparently.
- **nftables firewall** -- deny-by-default rules in the gateway's network namespace block all traffic until the full pipeline is ready, then DNAT rules redirect traffic into the proxy pipeline.

The VM has no way to bypass this pipeline. Its single network interface routes through the gateway, and there are no alternate paths out.

## Architecture

```text
+------------------------------------------------------------------+
|  VM (Lima / QEMU+KVM)                                            |
|                                                                   |
|  Agent process / inner Docker containers                          |
|       |                                                           |
|  eth1 (virtio-net, data plane)     eth0 (management, Lima SSH)    |
+-------|-----------------------------------------------------------+
        |
        |  TAP device on host
        v
+------------------------------------------------------------------+
|  Docker bridge  (sandbox-net-{session_id})                        |
|  /28 subnet from 10.209.0.0/24                                   |
|  .1 = bridge gateway    .2 = gateway container    .3 = VM         |
+-------|-----------------------------------------------------------+
        |
        v
+------------------------------------------------------------------+
|  Gateway container  (sandbox-gw-{session_id})                     |
|                                                                   |
|  nftables (PREROUTING DNAT)                                       |
|    +-- DNS (port 53) --------> CoreDNS (:53)                      |
|    +-- TCP (all other) ------> Envoy (:10000)                     |
|                                   |                               |
|                                   +---> mitmproxy (:8080)         |
|                                   |       (HTTPS inspection)      |
|                                   +---> direct to destination     |
|                                         (TLS passthrough / TCP)   |
+------------------------------------------------------------------+
        |
        v
    Internet (via host NAT / MASQUERADE)
```

**Key points:**

- The VM's data NIC (hot-added after boot via QMP) connects to the Docker bridge through a TAP device on the host.
- The gateway container sits on the same bridge, receiving all forwarded traffic from the VM.
- nftables PREROUTING DNAT rules intercept the forwarded traffic and redirect it into the pipeline components.
- The gateway's own outbound connections (Envoy forwarding to real destinations) follow standard Docker NAT to reach the internet.

## Per-session network

Each session receives its own /28 subnet carved from a configurable base range (default: `10.209.0.0/24`). A /24 base provides 16 concurrent sessions.

### IP addressing

| Address | Role |
|---------|------|
| `.0`    | Network address |
| `.1`    | Docker bridge gateway (auto-claimed by Docker) |
| `.2`    | Gateway container |
| `.3`    | VM data NIC |
| `.4-.14`| Unused |
| `.15`   | Broadcast |

For example, the first session gets `10.209.0.0/28`: the gateway container is `10.209.0.2`, the VM is `10.209.0.3`. The second session gets `10.209.0.16/28`, and so on.

### Naming conventions

| Resource | Name pattern |
|----------|-------------|
| Docker network | `sandbox-net-{session_id}` |
| Docker bridge interface | `sb-{session_id[0..11]}` (max 15 chars) |
| Gateway container | `sandbox-gw-{session_id}` |
| TAP device | `tap-sb-{session_id[0..6]}` (max 15 chars) |

### Isolation

Each session's Docker bridge is a separate L2 segment. There is no cross-session traffic path. The gateway container is attached only to its session's bridge -- it has no access to the host network or other sessions.

## Traffic flow

When an application inside the VM makes an outbound connection, the traffic follows this path:

1. **VM to bridge.** The application's packets exit the VM through the virtio-net data NIC, cross the TAP device, and arrive on the Docker bridge.

2. **Bridge to gateway.** The gateway container receives the forwarded packets on its `eth0` interface.

3. **nftables DNAT.** PREROUTING rules in the gateway's network namespace intercept the forwarded traffic:
   - DNS (UDP/TCP port 53) is redirected to CoreDNS on the gateway's own IP, port 53.
   - All other TCP traffic is redirected to Envoy on the gateway's own IP, port 10000.
   - Cloud metadata (`169.254.169.254`) is dropped.
   - All IPv6 traffic is dropped (the system is IPv4-only).

4. **Envoy routing.** Envoy receives the DNAT-redirected TCP connections and uses the `original_dst` listener filter to recover the real destination. Based on the destination's policy configuration:
   - **HTTP-inspected destinations** are forwarded to mitmproxy on `127.0.0.1:8080`.
   - **TLS-verified destinations** are forwarded directly with SNI validation.
   - **Transport-only (opaque TCP)** destinations are forwarded directly.

5. **mitmproxy inspection.** For HTTP-inspected traffic, mitmproxy terminates TLS using the per-session CA, inspects the HTTP request, and forwards it to the destination.

6. **Outbound NAT.** The gateway's MASQUERADE rule translates the source address so the traffic can reach the internet via the host's network stack.

### Inner Docker traffic

When the agent runs Docker containers inside the VM, their outbound traffic follows the same path transparently:

```text
Inner container --> inner Docker bridge --> VM kernel NAT --> VM virtio-net
  --> Docker bridge --> gateway --> pipeline --> destination
```

The proxy pipeline sees the VM's IP (`.3`) as the source -- inner container IPs are not visible and no special configuration is needed.

Traffic between inner containers (e.g., services in a `docker compose` stack) stays on the inner Docker bridge and never reaches the gateway.

### Direct IP access

Direct IP access (bypassing DNS) is controlled by the firewall. By default, the deny-all nftables rules reject any traffic that does not match a permitted destination. Applications that try to connect to an IP address directly -- without going through DNS resolution -- will fail unless the IP/port is explicitly allowed by policy.

## DNS

All DNS queries from the VM are served by CoreDNS running inside the gateway container.

### How DNS is enforced

1. The VM's `/etc/resolv.conf` points to the gateway container's IP (`.2`), making CoreDNS the default resolver.
2. As a safety net, nftables PREROUTING DNAT rules redirect **all** DNS traffic (UDP/TCP port 53) from the VM to CoreDNS, regardless of the destination address. Applications that ignore `resolv.conf` or hardcode alternate resolver addresses (e.g., `8.8.8.8`) are still forced through CoreDNS.

### CoreDNS configuration

CoreDNS forwards queries to upstream resolvers (default: `8.8.8.8`, `8.8.4.4`) and logs all queries for observability. A health endpoint is available on port `8180` for liveness checks.

In policy-enforcement mode, CoreDNS uses a custom plugin that:

- Only resolves domains permitted by policy; non-allowed domains get NXDOMAIN.
- Strips HTTPS/SVCB records carrying ECHConfig to prevent Encrypted Client Hello from defeating TLS interception.
- Reports resolved IP-to-domain mappings to sandboxd for propagation to nftables rules.

## TLS interception

The sandbox inspects HTTPS traffic by generating a per-session CA certificate and using mitmproxy to perform man-in-the-middle TLS interception.

### Certificate lifecycle

1. **Generation.** At session creation, sandboxd generates an ECDSA P-256 CA keypair. The CA is named `Sandbox CA {short_id}` (where `short_id` is the first 8 characters of the session UUID). Files are stored in the session's `ca/` directory:
   - `cert.pem` -- CA certificate (public)
   - `key.pem` -- CA private key (PKCS#8 PEM)
   - `mitmproxy-ca.pem` -- key + cert concatenated (mitmproxy format)
   - `mitmproxy-ca-cert.pem` -- cert-only alias (mitmproxy format)

2. **Gateway mount.** The CA files are bind-mounted into the gateway container at `/root/.mitmproxy/` (read-only). mitmproxy uses them to sign intercepted certificates.

3. **VM trust injection.** The CA public certificate is injected into the VM via the guest agent:
   - Installed in `/usr/local/share/ca-certificates/` and registered with `update-ca-certificates`.
   - Environment variables set for applications that use their own trust resolution:
     - `SSL_CERT_FILE`
     - `REQUESTS_CA_BUNDLE`
     - `NODE_EXTRA_CA_CERTS`
     - `CURL_CA_BUNDLE`
   - Installed in Docker daemon trust store (`/etc/docker/certs.d/`) for registry image pulls.

4. **Cleanup.** The CA files are deleted when the session is removed. On stop, the CA is preserved on disk so it can be reused when the session is started again.

### Certificate pinning

Applications that use certificate pinning or hardcoded trust stores will reject the interception CA. These applications must be configured with a TLS-verified bypass (assurance level 2), which allows the traffic through without inspection.

### Security properties

- The CA private key is never present inside the VM. It exists only in the gateway container.
- Each session gets its own CA. Compromise of one session's CA does not affect other sessions.
- The CA validity period matches the session lifetime.

## Session lifecycle

Networking resources are created and destroyed as part of the session lifecycle.

### Create

When a session is created, sandboxd performs these steps in order:

1. Generate per-session CA certificate.
2. Create Docker bridge network (`sandbox-net-{id}`) with a /28 subnet.
3. Start gateway container (`sandbox-gw-{id}`) on the bridge, with CA files mounted.
4. Inject deny-all nftables rules into the gateway's network namespace (immediate, before any component is ready).
5. Wait for all gateway components to become ready (mitmproxy, Envoy, CoreDNS).
6. Inject DNAT rules (traffic routing starts only after all components are healthy).
7. Create a TAP device on the host, attached to the Docker bridge.
8. Hot-add the TAP as a NIC to the running VM via QMP.
9. Configure the NIC inside the VM with a static IP and default route to the gateway.
10. Inject the CA certificate into the VM's trust store.
11. Store network info in the database.

If any step fails, all preceding steps are rolled back (gateway stopped, network deleted, CA removed).

### Stop

On stop, networking is torn down in reverse order (best-effort, errors are logged but do not block):

1. Detach the VM from the bridge (remove TAP device).
2. Stop and remove the gateway container.
3. Remove the Docker bridge network.

The subnet allocation and CA certificate files are preserved on disk so they can be reused on the next start.

### Start (resume)

When a stopped session is started again, sandboxd recreates the networking infrastructure using the same subnet and IPs that were originally allocated:

1. Recreate the Docker bridge network with the stored subnet.
2. Create a new gateway container with the existing CA files.
3. Inject nftables rules and wait for component readiness.
4. Reattach the VM to the bridge.
5. Re-inject the CA certificate into the VM.

### Remove

Full teardown -- all resources are released:

1. Tear down networking (TAP, gateway, bridge).
2. Delete the Docker network and release the subnet allocation back to the pool.
3. Delete the CA certificate files from disk.

## Gateway health

### Components

The gateway container runs three processes managed by the entrypoint script:

| Component | Listen address | Health check |
|-----------|---------------|--------------|
| mitmproxy (mitmdump) | `127.0.0.1:8080` | Process alive (`pgrep -x mitmdump`) |
| Envoy | `0.0.0.0:10000` (proxy), `127.0.0.1:9901` (admin) | `GET http://127.0.0.1:9901/ready` |
| CoreDNS | `:53` (DNS), `:8180` (health), `:8181` (ready) | `GET http://127.0.0.1:8180/health` |

### Startup ordering

Components start in a specific order to prevent transient exposure:

1. **mitmproxy** starts first (Envoy forwards to it, so it must be ready first).
2. **Envoy** starts next (receives DNAT-redirected TCP traffic).
3. **CoreDNS** starts last.

nftables DNAT rules are injected only after all three components pass their readiness checks. Before that, the deny-all rules drop all traffic.

### Process monitoring

The entrypoint script polls all three processes every 2 seconds. If any process exits, the script logs the failure and exits non-zero, triggering Docker's `unless-stopped` restart policy. On container restart, sandboxd re-injects the full nftables ruleset.

### Health API

sandboxd exposes health information through its Unix socket API:

**Per-session health:**
```
GET /sessions/{id}/health
```

Returns the status of each gateway component (Envoy, mitmproxy, CoreDNS) and the guest agent connectivity.

**Global health:**
```
GET /health
```

Returns gateway status for all running sessions.

## Inspecting sessions

The `sandbox` CLI is the primary interface for inspecting sessions and their networking state.

### List sessions with gateway status

```bash
sandbox ps
```

Each running session in the output includes agent and gateway status columns.

<details>
<summary>Direct API alternative</summary>

```bash
curl -s --unix-socket ~/.sandboxd/sandboxd.sock http://localhost/sessions | jq .
```

</details>

### Check session health

```bash
sandbox health <session>
```

Example output:

```
Session:   a1b2c3d4-...
VM:        running
Agent:     connected
Gateway:
  Container: running
  Envoy:     healthy
  mitmproxy: healthy
  CoreDNS:   healthy
Network:
  Bridge:  exists
  TAP:     exists
```

<details>
<summary>Direct API alternative</summary>

```bash
curl -s --unix-socket ~/.sandboxd/sandboxd.sock \
  http://localhost/sessions/{id}/health | jq .
```

</details>

### View gateway logs

```bash
# View all gateway logs (last 100 lines)
sandbox logs <session>

# View a specific component's logs
sandbox logs <session> --component envoy
sandbox logs <session> --component mitmproxy
sandbox logs <session> --component coredns

# Stream logs continuously
sandbox logs <session> --follow

# Show last N lines
sandbox logs <session> --tail 50
```

<details>
<summary>Direct Docker alternative</summary>

Gateway component logs are written to `/var/log/gateway/` inside the container:

```bash
docker logs sandbox-gw-{session_id}
docker exec sandbox-gw-{session_id} cat /var/log/gateway/mitmproxy.log
docker exec sandbox-gw-{session_id} cat /var/log/gateway/envoy.log
docker exec sandbox-gw-{session_id} cat /var/log/gateway/coredns.log
```

</details>

### Inspect nftables rules

nftables rules live in the gateway container's network namespace. To inspect them:

```bash
# Get the container PID
PID=$(docker inspect --format '{{.State.Pid}}' sandbox-gw-{session_id})

# List all rules
sudo nsenter --net=/proc/$PID/ns/net nft list ruleset
```

### Check Docker network

```bash
# List sandbox networks
docker network ls --filter label=sandbox.session_id

# Inspect a specific session's network
docker network inspect sandbox-net-{session_id}
```

## Troubleshooting

### VM cannot reach the internet

1. **Check session state.** The session must be in the `running` state. Networking is torn down on stop.

2. **Check gateway status.**
   ```bash
   sandbox health <session>
   ```
   If the gateway container is `not_running`, sandboxd should restart it automatically via Docker's restart policy. If it remains down, check the gateway logs:
   ```bash
   sandbox logs <session>
   ```

   <details>
   <summary>Direct API alternative</summary>

   ```bash
   curl -s --unix-socket ~/.sandboxd/sandboxd.sock \
     http://localhost/sessions/{id}/health | jq .gateway
   ```

   </details>

3. **Check nftables rules.** If the DNAT rules are missing (e.g., after a crash), traffic will hit the deny-all rules and be rejected.
   ```bash
   PID=$(docker inspect --format '{{.State.Pid}}' sandbox-gw-{session_id})
   sudo nsenter --net=/proc/$PID/ns/net nft list ruleset
   ```
   Look for the `sandbox_dnat` table with PREROUTING rules. If missing, restart the session.

4. **Check VM NIC.** Inside the VM, verify the data NIC exists and has the correct IP:
   ```bash
   ip addr show  # Look for the interface with the .3 address
   ip route      # Default route should point to .2 (gateway)
   ```

### DNS failures

1. **Check CoreDNS health.**
   ```bash
   sandbox health <session>
   ```
   Look at the `CoreDNS` line in the gateway section.

2. **Check CoreDNS logs.**
   ```bash
   sandbox logs <session> --component coredns
   ```

3. **Test resolution from inside the gateway.**
   ```bash
   docker exec sandbox-gw-{session_id} dig @127.0.0.1 example.com
   ```

4. **Check resolv.conf inside the VM.** It should point to the gateway IP (`.2`):
   ```bash
   cat /etc/resolv.conf  # Inside the VM
   ```

5. **If domains resolve but connections fail,** the domain may not be allowed by policy. Check CoreDNS logs:
   ```bash
   sandbox logs <session> --component coredns --tail 200
   ```

### TLS errors

1. **Verify the CA is trusted inside the VM.**
   ```bash
   # Inside the VM:
   openssl s_client -connect example.com:443 -servername example.com </dev/null 2>&1 \
     | grep "verify return"
   ```
   If verification fails, the CA may not have been injected properly. Check the session creation logs.

2. **Check the CA environment variables inside the VM.**
   ```bash
   # Inside the VM:
   echo $SSL_CERT_FILE
   echo $NODE_EXTRA_CA_CERTS
   ```

3. **Certificate pinning.** If a specific application rejects the certificate, it likely uses certificate pinning. This application needs a TLS-verified bypass (assurance level 2) in the policy configuration.

4. **Check mitmproxy is running.**
   ```bash
   sandbox health <session>
   ```
   Look at the `mitmproxy` line. For detailed mitmproxy logs:
   ```bash
   sandbox logs <session> --component mitmproxy
   ```

### Gateway container keeps restarting

Check the container logs for the failing component:

```bash
sandbox logs <session> --tail 50
```

<details>
<summary>Direct Docker alternative</summary>

```bash
docker logs --tail 50 sandbox-gw-{session_id}
```

</details>

Common causes:
- **Port conflict** -- another process on the host is using the gateway's ports.
- **CA files missing** -- the bind-mounted CA files do not exist on disk. This can happen if the session's CA directory was deleted while the session was stopped.
- **Resource exhaustion** -- the host is out of memory or file descriptors.

### Session networking fails to set up

If session creation fails during the networking phase, sandboxd rolls back all resources. Check the daemon logs for the specific step that failed:

```bash
journalctl -u sandboxd  # If running as a systemd service
# Or check wherever sandboxd logs are directed
```

The error will indicate which step failed (CA generation, network creation, gateway creation, TAP attachment, QMP hot-add, guest configuration, or CA injection).
