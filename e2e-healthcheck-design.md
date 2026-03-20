# End-to-End Health-Check Design

## Status

Future enhancement — not part of initial implementation.

## Context

The network-control subsystem uses per-component liveness probes for health monitoring (see networking-design.md). These probes verify that individual components (nftables rules, local DNS resolver, Envoy, mitmproxy, sandbox daemon) are alive but do not guarantee that traffic is actually being proxied through the full pipeline.

This document describes an end-to-end health-check mechanism that provides stronger assurance by exercising the complete data path.

## Design

### Health-check container

A dedicated container runs a minimal HTTPS server with a single endpoint. Its sole purpose is to serve as the target for end-to-end health probes.

The container has:

* a mounted interception CA certificate (so TLS through mitmproxy succeeds)
* a mounted status file (shared volume with the sandbox daemon)
* its own network policy: **inbound allowed, outbound blocked**

The container does not have access to the control plane, sandbox daemon APIs, or any sandbox state.

### Probe flow

1. A probe process is spawned in the sandbox network namespace (not inside the sandboxed container)
2. The probe makes an HTTPS request to the health-check container
3. The request traverses the full pipeline: nftables redirect → Envoy → mitmproxy → health-check container
4. The health-check container updates the status file on successful receipt
5. The sandbox daemon reads the status file to determine pipeline health

### Why a separate container

The health-check endpoint must be reachable from inside the sandbox namespace (to exercise the real data path), which means sandboxed code can also reach it. A separate container with blocked outbound traffic ensures that even if the endpoint is compromised, the attacker gains a container that is **more locked down** than the sandbox they are already in — no outbound connectivity, no secrets, no control plane access.

### Security properties

* the sandbox daemon never exposes a network endpoint
* the health-check container is a strict downgrade for an attacker compared to the sandbox
* the status file is a one-directional data channel (health-check writes, sandbox daemon reads)
* the health-check container has no outbound network access
* compromise of the health-check container yields nothing useful

### Why this is deferred

The mechanism requires:

* an additional container with its own lifecycle management
* CA certificate mounting
* shared volume for the status file
* a dedicated network policy for the health-check container
* probe process management in the namespace

This complexity is justified for high-assurance deployments but is not required for initial implementation, where per-component probes provide sufficient diagnostics without introducing additional attack surface.
