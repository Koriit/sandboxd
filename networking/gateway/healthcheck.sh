#!/usr/bin/env bash
#
# Gateway container health check
# Checks all four pipeline components. Exits 0 if all healthy, 1 otherwise.

set -uo pipefail

healthy=true

# Check Envoy admin health endpoint
if ! curl -sf http://127.0.0.1:9901/ready >/dev/null 2>&1; then
    echo "UNHEALTHY: Envoy not ready (admin endpoint 127.0.0.1:9901/ready failed)"
    healthy=false
fi

# Check mitmproxy — verify process is running
# mitmdump does not have a built-in health endpoint, so we check the process
if ! pgrep -x mitmdump >/dev/null 2>&1; then
    echo "UNHEALTHY: mitmproxy (mitmdump) process not running"
    healthy=false
fi

# Check CoreDNS health endpoint
if ! curl -sf http://127.0.0.1:8180/health >/dev/null 2>&1; then
    echo "UNHEALTHY: CoreDNS not ready (health endpoint 127.0.0.1:8180/health failed)"
    healthy=false
fi

# Check the two nft-logger `/health` endpoints (deny on :10003,
# allow on :10004).
#
# Both listeners are bound on the gateway bridge IP (see entrypoint:
# `--bind-ip ${GATEWAY_IP}`), not 127.0.0.1 — PREROUTING DNAT to
# loopback is dropped as a martian destination unless
# `route_localnet=1` is set, which the gateway container does not
# set (spec 2026-04-21 Part 3 / "Listener design / Bind address").
# The probes therefore have to go through the bridge IP. Discover it
# the same way the entrypoint does (`hostname -i`, first address) so
# the two scripts stay consistent.
#
# A non-200 from either probe means a listener task has exited or
# failed to bind; Docker's HEALTHCHECK treats the non-zero exit as
# unhealthy, and sandboxd's gateway poller restarts the container
# (spec Part 3 / "Liveness posture" — observability of denials and
# allow-flow audit are hard invariants, no degraded mode). The two
# loggers are independent failure domains (M12-S2 Decision 4): if
# either fails the container is unhealthy.
GATEWAY_IP_FOR_HEALTH="$(hostname -i | awk '{print $1}')"
if [[ -z "${GATEWAY_IP_FOR_HEALTH}" ]]; then
    echo "UNHEALTHY: could not discover gateway bridge IP via 'hostname -i'"
    healthy=false
else
    if ! curl -sf "http://${GATEWAY_IP_FOR_HEALTH}:10003/health" >/dev/null 2>&1; then
        echo "UNHEALTHY: sandbox-nft-deny-logger not ready (health endpoint ${GATEWAY_IP_FOR_HEALTH}:10003/health failed)"
        healthy=false
    fi
    if ! curl -sf "http://${GATEWAY_IP_FOR_HEALTH}:10004/health" >/dev/null 2>&1; then
        echo "UNHEALTHY: sandbox-nft-allow-logger not ready (health endpoint ${GATEWAY_IP_FOR_HEALTH}:10004/health failed)"
        healthy=false
    fi
fi

if [[ "$healthy" = true ]]; then
    echo "HEALTHY: all components running"
    exit 0
else
    exit 1
fi
