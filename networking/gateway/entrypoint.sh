#!/usr/bin/env bash
#
# Gateway container entrypoint
# Starts mitmproxy, Envoy, deny-logger, and CoreDNS in the design-specified
# order, waits for readiness, then monitors all processes.
#
# Startup order (per networking-design.md § Component lifecycle + spec
# 2026-04-21 Part 3 / "Deny-logger component"):
#   1. mitmproxy    (must be ready before Envoy, which forwards to it)
#   2. Envoy        (must be ready before DNS, which triggers resolution)
#   3. deny-logger  (must be ready before VM traffic starts — nftables
#                    DNAT sends denied packets to :10001/:10002 and the
#                    container's HEALTHCHECK probes :10003)
#   4. CoreDNS      (last — completing the pipeline)
#
# nftables rules are managed externally by sandboxd, not by this script.
#
# **M9-S18**: Envoy config is split into a **static bootstrap**
# (`/etc/envoy/envoy-bootstrap.yaml`) and a **dynamic listener file** served
# via filesystem LDS from `/etc/envoy/listeners/listener.yaml`. The bootstrap
# is written into the tmpfs by sandboxd via `docker exec` right after the
# container starts; the listener directory is a bind-mount from the host so
# sandboxd can atomically rewrite the listener file via host-side rename
# (Envoy's filesystem LDS watcher only fires on `MovedTo` inotify events —
# upstream issue `#20474`). Changes to the listener are picked up via xDS
# without process restart, so the SIGHUP restart handler used before M9-S18
# has been removed.
#
# If any process exits, this script logs the failure and exits non-zero
# so Docker can restart the container.

set -euo pipefail

LOG_DIR="${LOG_DIR:-/var/log/gateway}"
READY_TIMEOUT="${READY_TIMEOUT:-30}"
ENVOY_BOOTSTRAP_FILE="${ENVOY_BOOTSTRAP_FILE:-/etc/envoy/envoy-bootstrap.yaml}"
ENVOY_LISTENER_FILE="${ENVOY_LISTENER_FILE:-/etc/envoy/listeners/listener.yaml}"
ENVOY_CONFIG_WAIT_TIMEOUT="${ENVOY_CONFIG_WAIT_TIMEOUT:-30}"

# M10-S2 Phase 6b: default path for the mitmproxy JSONL event stream.
# `/var/log/gateway/events/` is the per-session bind-mount target
# (host-side: `{events_host_root}/<session>/`), so writes here land on
# the host filesystem where sandboxd's ingester tails them.  Export so
# both policy_addon.py and passthrough_addon.py see it.
export SANDBOX_MITMPROXY_EVENTS="${SANDBOX_MITMPROXY_EVENTS:-/var/log/gateway/events/mitmproxy.jsonl}"

# Ensure runtime directories exist (tmpfs mounts wipe them out).
# The events/ directory is normally a bind mount from the host, but
# we pre-create it so the addon's append-mode open(…) never misses a
# parent directory on cold start before sandboxd attaches the mount.
mkdir -p "${LOG_DIR}" "${LOG_DIR}/events" /tmp/mitmproxy

# PIDs of managed processes
MITM_PID=""
ENVOY_PID=""
COREDNS_PID=""
DENY_LOGGER_PID=""

log() {
    echo "[gateway] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

# ── Signal handling ──────────────────────────────────────────────────

shutdown_all() {
    log "Shutting down components..."
    # Shutdown order (reverse of startup): CoreDNS, deny-logger, Envoy,
    # mitmproxy. deny-logger handles SIGTERM cleanly — it flushes any
    # pending rate_limited summary to the JSONL before exiting (see
    # sandbox-deny-logger spec Part 3 / "Liveness posture"), so SIGKILL
    # fallback below is for the hang-protection deadline only.
    for pid_var in COREDNS_PID DENY_LOGGER_PID ENVOY_PID MITM_PID; do
        local pid="${!pid_var}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "Sending SIGTERM to ${pid_var}=${pid}"
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Wait for all to exit (up to 10 seconds total)
    local deadline=$((SECONDS + 10))
    for pid_var in COREDNS_PID DENY_LOGGER_PID ENVOY_PID MITM_PID; do
        local pid="${!pid_var}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            local remaining=$((deadline - SECONDS))
            if [[ $remaining -gt 0 ]]; then
                timeout "$remaining" tail --pid="$pid" -f /dev/null 2>/dev/null || true
            fi
            if kill -0 "$pid" 2>/dev/null; then
                log "Force-killing ${pid_var}=${pid}"
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    done
    log "All components stopped."
}

on_signal() {
    log "Received shutdown signal."
    shutdown_all
    exit 0
}

trap on_signal SIGTERM SIGINT SIGQUIT

# M9-S18: Envoy configuration now updates via xDS (filesystem LDS for
# listener, in-process cluster definitions for clusters). A SIGHUP-driven
# process restart would drain the listener and reset in-flight
# connections, defeating the whole point of the xDS path. The previous
# SIGHUP restart trap has therefore been removed.

# ── Readiness checks ────────────────────────────────────────────────

wait_for_ready() {
    local name="$1"
    local check_cmd="$2"
    local timeout_secs="${3:-$READY_TIMEOUT}"
    local deadline=$((SECONDS + timeout_secs))

    log "Waiting for ${name} to become ready (timeout=${timeout_secs}s)..."
    while [[ $SECONDS -lt $deadline ]]; do
        if eval "$check_cmd" >/dev/null 2>&1; then
            log "${name} is ready."
            return 0
        fi
        sleep 1
    done
    log "ERROR: ${name} failed to become ready within ${timeout_secs}s"
    return 1
}

# ── Start mitmproxy ─────────────────────────────────────────────────

# Select the mitmproxy addon based on image variant. Both addon scripts
# (passthrough_addon.py and policy_addon.py) are baked into the image at
# build time; the presence of policy_addon.py indicates this image was
# built with policy enforcement enabled. The dynamic policy data lives
# at /tmp/mitmproxy/policy.json (written by sandboxd) and is separate
# from the addon code selected here.
MITM_ADDON="/etc/mitmproxy/passthrough_addon.py"
if [[ -f /etc/mitmproxy/policy_addon.py ]]; then
    MITM_ADDON="/etc/mitmproxy/policy_addon.py"
fi

log "Starting mitmproxy (mitmdump) on 127.0.0.1:18080 in regular (forward-proxy) mode (addon=${MITM_ADDON})..."
mitmdump \
    --mode regular \
    --listen-host 127.0.0.1 \
    --listen-port 18080 \
    --set stream_large_bodies=1 \
    -s "${MITM_ADDON}" \
    >>"${LOG_DIR}/mitmproxy.log" 2>&1 &
MITM_PID=$!
log "mitmproxy started (PID=${MITM_PID})"

# mitmdump has no health endpoint; check that the process is alive and
# the port is open. The port check is the real readiness signal.
wait_for_ready "mitmproxy" \
    "kill -0 ${MITM_PID} 2>/dev/null && bash -c '</dev/tcp/127.0.0.1/18080' 2>/dev/null"

# ── Start Envoy ─────────────────────────────────────────────────────

# M9-S18: the bootstrap config is written into the tmpfs at
# ${ENVOY_BOOTSTRAP_FILE} by sandboxd right after `docker run` (via
# `docker exec`). The listener file at ${ENVOY_LISTENER_FILE} lives in a
# bind-mounted host directory and is seeded by sandboxd before the
# container starts. Wait for both to appear before launching Envoy so we
# don't race sandboxd's bootstrap write on first boot.
mkdir -p "$(dirname "${ENVOY_BOOTSTRAP_FILE}")" "$(dirname "${ENVOY_LISTENER_FILE}")"

wait_for_ready "Envoy bootstrap file" \
    "[[ -s '${ENVOY_BOOTSTRAP_FILE}' ]]" \
    "${ENVOY_CONFIG_WAIT_TIMEOUT}"

wait_for_ready "Envoy listener file" \
    "[[ -s '${ENVOY_LISTENER_FILE}' ]]" \
    "${ENVOY_CONFIG_WAIT_TIMEOUT}"

log "Starting Envoy (bootstrap=${ENVOY_BOOTSTRAP_FILE})..."
envoy \
    -c "${ENVOY_BOOTSTRAP_FILE}" \
    --log-level warning \
    --log-path "${LOG_DIR}/envoy.log" \
    &
ENVOY_PID=$!
log "Envoy started (PID=${ENVOY_PID})"

wait_for_ready "Envoy" "curl -sf http://127.0.0.1:9901/ready"

# ── Start sandbox-deny-logger ───────────────────────────────────────
#
# The deny-logger binds its TCP (:10001), UDP (:10002), and health
# (:10003) listeners on the gateway container's bridge IP — NOT
# 127.0.0.1. PREROUTING DNAT to loopback is dropped by the kernel as a
# martian destination unless `route_localnet=1` is enabled on the
# ingress interface, which the gateway container does not enable (see
# spec 2026-04-21 Part 3 / "Deny-logger component / Listener design").
# Discover the bridge IP at runtime via `hostname -i`; take the first
# address in case a future setup adds more interfaces.
GATEWAY_IP="${GATEWAY_IP:-$(hostname -i | awk '{print $1}')}"
if [[ -z "${GATEWAY_IP}" ]]; then
    log "ERROR: could not discover gateway bridge IP via 'hostname -i'"
    exit 1
fi
log "Discovered gateway bridge IP: ${GATEWAY_IP}"

# Per-session JSONL target. Lives under the per-session events bind
# mount (/var/log/gateway/events/<session-id>/) so sandboxd's ingest
# watcher picks it up from the host side without an extra file
# descriptor dance.
SANDBOX_DENY_LOGGER_EVENTS="${SANDBOX_DENY_LOGGER_EVENTS:-/var/log/gateway/events/deny-logger.jsonl}"

log "Starting sandbox-deny-logger on ${GATEWAY_IP}:10001/10002/10003..."
/usr/local/bin/sandbox-deny-logger \
    --bind-ip "${GATEWAY_IP}" \
    --event-path "${SANDBOX_DENY_LOGGER_EVENTS}" \
    >>"${LOG_DIR}/deny-logger.log" 2>&1 &
DENY_LOGGER_PID=$!
log "sandbox-deny-logger started (PID=${DENY_LOGGER_PID})"

# The health endpoint on :10003 is the definitive readiness signal; it
# only reports 200 once the TCP and UDP listener tasks are alive.
wait_for_ready "deny-logger" "curl -sf http://${GATEWAY_IP}:10003/health"

# ── Start CoreDNS ───────────────────────────────────────────────────

# Ensure the policy file exists. sandboxd writes the real policy, but
# CoreDNS needs the file present at startup. The default is deny-all
# (empty) so no traffic leaks before sandboxd applies the session policy.
# For sessions without an explicit policy, sandboxd writes allow-all ("*").
COREDNS_POLICY_FILE="${COREDNS_POLICY_FILE:-/etc/coredns/policy.conf}"
if [[ ! -f "$COREDNS_POLICY_FILE" ]]; then
    log "Creating default deny-all policy at ${COREDNS_POLICY_FILE} (sandboxd will overwrite)"
    printf '# Default deny-all — sandboxd writes the real policy after gateway starts\n' > "$COREDNS_POLICY_FILE"
fi

log "Starting CoreDNS..."
coredns \
    -conf /opt/coredns/Corefile \
    >>"${LOG_DIR}/coredns.log" 2>&1 &
COREDNS_PID=$!
log "CoreDNS started (PID=${COREDNS_PID})"

wait_for_ready "CoreDNS" "curl -sf http://127.0.0.1:8180/health"

# ── All components running ──────────────────────────────────────────

log "All components are running and healthy."
log "  mitmproxy    PID=${MITM_PID}        (127.0.0.1:18080 regular mode; reached via Envoy CONNECT)"
log "  Envoy        PID=${ENVOY_PID}        (0.0.0.0:10000, admin 127.0.0.1:9901)"
log "  deny-logger  PID=${DENY_LOGGER_PID}  (${GATEWAY_IP}:10001 tcp, :10002 udp, :10003 health)"
log "  CoreDNS      PID=${COREDNS_PID}      (DNS :53, health :8180)"

# ── Monitor processes ───────────────────────────────────────────────
# Wait for any child to exit. If any managed process dies, log and exit
# so Docker's restart policy can handle recovery.

while true; do
    for pid_var in MITM_PID ENVOY_PID DENY_LOGGER_PID COREDNS_PID; do
        local_pid="${!pid_var}"
        if [[ -n "$local_pid" ]] && ! kill -0 "$local_pid" 2>/dev/null; then
            # Process is gone. Retrieve exit code.
            set +e
            wait "$local_pid" 2>/dev/null
            exit_code=$?
            set -e
            log "FATAL: ${pid_var} (PID=${local_pid}) exited with code ${exit_code}"
            shutdown_all
            exit 1
        fi
    done
    # Sleep briefly between polls. Signals (SIGTERM etc.) interrupt sleep.
    sleep 2 &
    wait $! 2>/dev/null || true
done
