#!/usr/bin/env bash
#
# Gateway container entrypoint
# Starts mitmproxy, Envoy, and CoreDNS in the design-specified order,
# waits for readiness, then monitors all processes.
#
# Startup order (per networking-design.md § Component lifecycle):
#   1. mitmproxy  (must be ready before Envoy, which forwards to it)
#   2. Envoy      (must be ready before DNS, which triggers resolution)
#   3. CoreDNS    (last — completing the pipeline)
#
# nftables rules are managed externally by sandboxd, not by this script.
#
# If any process exits, this script logs the failure and exits non-zero
# so Docker can restart the container.

set -euo pipefail

LOG_DIR="${LOG_DIR:-/var/log/gateway}"
READY_TIMEOUT="${READY_TIMEOUT:-30}"

# Ensure runtime directories exist (tmpfs mounts wipe them out).
mkdir -p "${LOG_DIR}" /tmp/mitmproxy

# PIDs of managed processes
MITM_PID=""
ENVOY_PID=""
COREDNS_PID=""

log() {
    echo "[gateway] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*"
}

# ── Signal handling ──────────────────────────────────────────────────

shutdown_all() {
    log "Shutting down components..."
    # Shutdown order (reverse of startup): CoreDNS, Envoy, mitmproxy
    for pid_var in COREDNS_PID ENVOY_PID MITM_PID; do
        local pid="${!pid_var}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "Sending SIGTERM to ${pid_var}=${pid}"
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Wait for all to exit (up to 10 seconds total)
    local deadline=$((SECONDS + 10))
    for pid_var in COREDNS_PID ENVOY_PID MITM_PID; do
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

# ── SIGHUP handler: restart Envoy with updated config ──────────────

restart_envoy() {
    log "Restarting Envoy with updated config..."
    kill "$ENVOY_PID" 2>/dev/null
    wait "$ENVOY_PID" 2>/dev/null
    envoy \
        -c /etc/envoy/envoy.yaml \
        --log-level warning \
        --log-path "${LOG_DIR}/envoy.log" \
        &
    ENVOY_PID=$!
    log "Envoy restarted (PID=${ENVOY_PID})"
}

trap restart_envoy HUP

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

# Choose the mitmproxy addon: policy enforcement when a config file is
# present (written by sandboxd), otherwise fall back to pass-through.
# The policy addon also falls back internally when the config file is
# absent, but using the dedicated pass-through addon avoids loading the
# policy machinery when it is not needed.
MITM_ADDON="/etc/mitmproxy/passthrough_addon.py"
if [[ -f /etc/mitmproxy/policy_addon.py ]]; then
    MITM_ADDON="/etc/mitmproxy/policy_addon.py"
fi

log "Starting mitmproxy (mitmdump) on 0.0.0.0:8080 (addon=${MITM_ADDON})..."
mitmdump \
    --mode transparent \
    --listen-host 0.0.0.0 \
    --listen-port 8080 \
    --set stream_large_bodies=1 \
    -s "${MITM_ADDON}" \
    >>"${LOG_DIR}/mitmproxy.log" 2>&1 &
MITM_PID=$!
log "mitmproxy started (PID=${MITM_PID})"

# mitmdump has no health endpoint; check that the process is alive and
# the port is open. The port check is the real readiness signal.
wait_for_ready "mitmproxy" \
    "kill -0 ${MITM_PID} 2>/dev/null && bash -c '</dev/tcp/127.0.0.1/8080' 2>/dev/null"

# ── Start Envoy ─────────────────────────────────────────────────────

# Copy base Envoy config from read-only /opt/envoy into the writable /etc/envoy
# tmpfs. PolicyDistributor will overwrite this when a policy is applied.
mkdir -p /etc/envoy
cp /opt/envoy/envoy-base.yaml /etc/envoy/envoy.yaml

log "Starting Envoy..."
envoy \
    -c /etc/envoy/envoy.yaml \
    --log-level warning \
    --log-path "${LOG_DIR}/envoy.log" \
    &
ENVOY_PID=$!
log "Envoy started (PID=${ENVOY_PID})"

wait_for_ready "Envoy" "curl -sf http://127.0.0.1:9901/ready"

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
log "  mitmproxy  PID=${MITM_PID}  (0.0.0.0:8080)"
log "  Envoy      PID=${ENVOY_PID}  (0.0.0.0:10000, admin 127.0.0.1:9901)"
log "  CoreDNS    PID=${COREDNS_PID}  (DNS :53, health :8180)"

# ── Monitor processes ───────────────────────────────────────────────
# Wait for any child to exit. If any managed process dies, log and exit
# so Docker's restart policy can handle recovery.

while true; do
    for pid_var in MITM_PID ENVOY_PID COREDNS_PID; do
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
