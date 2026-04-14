# Gateway container: Envoy + mitmproxy + CoreDNS proxy pipeline
# CoreDNS is built from source with the sandboxpolicy plugin for DNS-level
# policy enforcement. Envoy and mitmproxy handle TCP/HTTP proxying.

# ---------- Stage 1: Build custom CoreDNS with sandboxpolicy plugin ----------
FROM golang:1.22 AS coredns-builder

WORKDIR /build

# Copy the plugin module and build the custom CoreDNS binary.
# Build context is networking/ (parent of coredns-plugin/).
COPY coredns-plugin/ ./coredns-plugin/

WORKDIR /build/coredns-plugin

RUN go mod download \
    && CGO_ENABLED=0 go build -o /coredns ./cmd/coredns

# ---------- Stage 2: Runtime image ----------
FROM debian:bookworm-slim

# Versions — pinned for reproducibility
ARG MITMPROXY_VERSION=11.1.3
ARG TARGETARCH=amd64

# ---------- install envoy from official apt repo ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        nftables \
        procps \
        wget \
    && mkdir -p /etc/apt/keyrings \
    && wget -qO- https://apt.envoyproxy.io/signing.key \
        | gpg --dearmor -o /etc/apt/keyrings/envoy-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/envoy-keyring.gpg] \
        https://apt.envoyproxy.io bookworm main" \
        > /etc/apt/sources.list.d/envoy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends envoy \
    && apt-get purge -y gnupg wget \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# ---------- install custom CoreDNS with sandboxpolicy plugin ----------
COPY --from=coredns-builder /coredns /usr/local/bin/coredns
RUN chmod +x /usr/local/bin/coredns

# ---------- install mitmproxy static binary ----------
RUN curl -fsSL "https://downloads.mitmproxy.org/${MITMPROXY_VERSION}/mitmproxy-${MITMPROXY_VERSION}-linux-x86_64.tar.gz" \
        | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/mitmdump /usr/local/bin/mitmproxy /usr/local/bin/mitmweb

# ---------- create runtime directories ----------
RUN mkdir -p /var/log/gateway /var/run/gateway /tmp/gateway \
    && mkdir -p /etc/envoy /etc/coredns /etc/mitmproxy \
    && mkdir -p /opt/envoy

# ---------- copy configuration files ----------
# Build context is networking/ (parent of gateway/)
# Base Envoy config goes to /opt/envoy/ (read-only) since /etc/envoy is a
# tmpfs at runtime. The entrypoint copies it into /etc/envoy on startup.
COPY envoy/envoy-base.yaml /opt/envoy/envoy-base.yaml
COPY envoy/envoy-base.yaml /etc/envoy/envoy.yaml
COPY gateway/Corefile /opt/coredns/Corefile
COPY mitmproxy/passthrough_addon.py /etc/mitmproxy/passthrough_addon.py
COPY mitmproxy/policy_addon.py /etc/mitmproxy/policy_addon.py
COPY gateway/entrypoint.sh /entrypoint.sh
COPY gateway/healthcheck.sh /healthcheck.sh

RUN chmod +x /entrypoint.sh /healthcheck.sh

# ---------- ports ----------
# 10000 - Envoy listener (TCP pass-through)
# 8080  - mitmproxy listener (HTTP/HTTPS inspection)
# 53    - CoreDNS (DNS)
# 9901  - Envoy admin (loopback only in config, but declared for docs)
# 8180  - CoreDNS health endpoint
EXPOSE 10000 8080 53/udp 53/tcp

# ---------- health check ----------
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/healthcheck.sh"]

# ---------- read-only root intent ----------
# Writable volumes expected at runtime: /var/log, /var/run, /tmp
# Container should be started with --read-only and tmpfs/volume mounts for
# the writable paths. We don't enforce --read-only in the Dockerfile itself
# because that's a runtime concern for docker-compose / sandboxd.

ENTRYPOINT ["/entrypoint.sh"]
