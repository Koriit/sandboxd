# Gateway container: Envoy + mitmproxy + CoreDNS + deny-logger pipeline.
# CoreDNS is built from source with the sandboxpolicy plugin for DNS-level
# policy enforcement. Envoy and mitmproxy handle TCP/HTTP proxying.
# `sandbox-deny-logger` catches denied VM egress via nftables DNAT and
# emits structured `deny` events to the shared JSONL stream.
#
# Build context is the repository root (see Makefile `.gateway-image.stamp`
# target); `.dockerignore` prunes heavyweight directories.

# ---------- Stage 1: Build custom CoreDNS with sandboxpolicy plugin ----------
FROM golang:1.22 AS coredns-builder

WORKDIR /build

# Copy the plugin module and build the custom CoreDNS binary.
COPY networking/coredns-plugin/ ./coredns-plugin/

WORKDIR /build/coredns-plugin

RUN go mod download \
    && CGO_ENABLED=0 go build -o /coredns ./cmd/coredns

# ---------- Stage 2: Build sandbox-deny-logger binary ----------
#
# Compiled in a dedicated Rust builder stage so the runtime image stays
# free of the Rust toolchain (~1.5 GB compressed). Linked against glibc
# (the builder's debian:bookworm and the runtime's debian:bookworm-slim
# ship compatible glibc versions); no musl gymnastics required.
#
# The `sandboxd/` workspace is copied wholesale because
# `sandbox-deny-logger` resolves against workspace-level `Cargo.toml` /
# `Cargo.lock` and the shared `[workspace.dependencies]` table. Sibling
# crates are not dragged in by `cargo build -p sandbox-deny-logger` —
# cargo builds only the requested package plus its actual dependency
# graph. `.dockerignore` already excludes `sandboxd/target/`.
FROM rust:1.88-bookworm AS deny-logger-builder

WORKDIR /src

COPY sandboxd/ ./sandboxd/

WORKDIR /src/sandboxd

RUN cargo build --release -p sandbox-deny-logger \
    && install -D -m 0755 target/release/sandbox-deny-logger /out/sandbox-deny-logger

# ---------- Stage 3: Runtime image ----------
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

# ---------- install sandbox-deny-logger ----------
# Runtime-only dependency is glibc (≥ the debian:bookworm version the
# builder stage linked against); no extra packages needed.
COPY --from=deny-logger-builder /out/sandbox-deny-logger /usr/local/bin/sandbox-deny-logger
RUN chmod +x /usr/local/bin/sandbox-deny-logger

# ---------- install mitmproxy static binary ----------
RUN curl -fsSL "https://downloads.mitmproxy.org/${MITMPROXY_VERSION}/mitmproxy-${MITMPROXY_VERSION}-linux-x86_64.tar.gz" \
        | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/mitmdump /usr/local/bin/mitmproxy /usr/local/bin/mitmweb

# ---------- create runtime directories ----------
#
# `/var/log/gateway/events/` is the bind-mount target for the per-session
# events host directory (see sandbox-core::events::EVENTS_DIR_IN_CONTAINER
# and gateway.rs::create_gateway). At runtime `/var/log` is a tmpfs and
# the narrower bind lands on top of it, so the mountpoint created here
# is strictly a documentation / image-inspection aid — Docker would
# auto-create it anyway. Keeping it next to the other /var/log/gateway/
# directories makes the intent visible to anyone reading the image.
RUN mkdir -p /var/log/gateway/events /var/run/gateway /tmp/gateway \
    && mkdir -p /etc/envoy /etc/coredns /etc/mitmproxy \
    && mkdir -p /opt/envoy

# ---------- copy configuration files ----------
# Build context is the repository root. Paths below are repo-relative.
#
# M9-S18: Envoy configuration is now provided at runtime by sandboxd.
#  - `/etc/envoy/envoy-bootstrap.yaml` is written via `docker exec` after
#    `docker run` but before the entrypoint starts Envoy.
#  - `/etc/envoy/listeners/listener.yaml` lives in a per-session host
#    directory bind-mounted into the container (see `atomic_listener_writer`
#    in `sandbox-core`). Docker creates the mountpoint automatically.
# We therefore no longer ship `envoy-base.yaml` inside the image.
COPY networking/gateway/Corefile /opt/coredns/Corefile
# M10-S2 Phase 6b: both addons import the shared EventEmitter from
# ``events.py``, so it must sit alongside the addon scripts in
# ``/etc/mitmproxy/`` — mitmdump loads the addon by path, and Python
# resolves the sibling ``events`` module via the addon's own directory.
COPY networking/mitmproxy/events.py /etc/mitmproxy/events.py
COPY networking/mitmproxy/passthrough_addon.py /etc/mitmproxy/passthrough_addon.py
COPY networking/mitmproxy/policy_addon.py /etc/mitmproxy/policy_addon.py
COPY networking/gateway/entrypoint.sh /entrypoint.sh
COPY networking/gateway/healthcheck.sh /healthcheck.sh

RUN chmod +x /entrypoint.sh /healthcheck.sh

# ---------- ports ----------
# 10000 - Envoy listener (TCP pass-through)
# 10001 - sandbox-deny-logger TCP listener (denied VM TCP, DNAT'd here)
# 10002 - sandbox-deny-logger UDP listener (denied VM UDP, DNAT'd here)
# 10003 - sandbox-deny-logger health endpoint
# 8080  - mitmproxy listener (HTTP/HTTPS inspection)
# 53    - CoreDNS (DNS)
# 9901  - Envoy admin (loopback only in config, but declared for docs)
# 8180  - CoreDNS health endpoint
#
# Only the externally reachable ports are `EXPOSE`d. 10001/10002/10003
# are bridge-internal only: nftables DNAT routes denied VM packets to
# 10001/10002, and the HEALTHCHECK probes 10003 from inside the
# container (via the bridge IP since the listener binds on the bridge
# IP, not 127.0.0.1 — see healthcheck.sh). They are not in the EXPOSE
# list.
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
