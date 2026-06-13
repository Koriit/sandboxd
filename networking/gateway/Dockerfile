# Gateway container: Envoy + mitmproxy + CoreDNS + nft-loggers pipeline.
# CoreDNS is built from source with the sandboxpolicy plugin for DNS-level
# policy enforcement. Envoy and mitmproxy handle TCP/HTTP proxying.
# Two sibling `nft-` binaries observe the kernel/nft layer and emit
# structured JSONL events:
#   - `sandbox-nft-deny-logger` catches denied VM egress: TCP is DNAT'd
#     to a userland listener on `:10001`; UDP is dropped at PREROUTING
#     and the kernel mirrors a copy to NFLOG group 1 where the logger's
#     netlink subscriber decodes it. `/health` on `:10003`.
#   - `sandbox-nft-allow-logger` audits allowed UDP flows by subscribing
#     to `nfnetlink_conntrack`'s `NFNLGRP_CONNTRACK_NEW` multicast group
#     (filtered for UDP) and emits one JSONL `allow` record per new
#     tracked flow. `/health` on `:10004`.
# The two binaries are independent failure domains: each owns its own
# data source, JSONL file, and `/health` endpoint; they share only the
# `sandbox-event-emitter` lib crate.
#
# Build context is the repository root (see Makefile `.gateway-image.stamp`
# target); `.dockerignore` prunes heavyweight directories.

# ---------- Stage 1: Build custom CoreDNS with sandboxpolicy plugin ----------
FROM golang:1.25 AS coredns-builder

WORKDIR /build

# Copy the plugin module and build the custom CoreDNS binary.
COPY networking/coredns-plugin/ ./coredns-plugin/

WORKDIR /build/coredns-plugin

RUN go mod download \
    && CGO_ENABLED=0 go build -o /coredns ./cmd/coredns

# ---------- Stage 2: Build nft-logger binaries ----------
#
# Compiled in a dedicated Rust builder stage so the runtime image stays
# free of the Rust toolchain (~1.5 GB compressed). Linked against glibc
# (the builder's debian:bookworm and the runtime's debian:bookworm-slim
# ship compatible glibc versions); no musl gymnastics required.
#
# The `sandboxd/` workspace is copied wholesale because both nft-logger
# binaries resolve against workspace-level `Cargo.toml` / `Cargo.lock`
# and the shared `[workspace.dependencies]` table. Sibling crates are
# not dragged in by `cargo build -p ...`; cargo builds only the
# requested packages plus their actual dependency graphs.
# `.dockerignore` already excludes `sandboxd/target/`.
#
# Both packages are built in a single `cargo build` invocation so the
# shared `sandbox-event-emitter` lib crate is compiled once. Two `-p`
# flags collapse to one cache layer instead of two; the resulting
# binaries are installed side-by-side in `/out/` for stage 4 to copy.
FROM rust:1.88-bookworm AS nft-loggers-builder

WORKDIR /src

COPY sandboxd/ ./sandboxd/

WORKDIR /src/sandboxd

RUN cargo build --release \
        -p sandbox-nft-deny-logger \
        -p sandbox-nft-allow-logger \
    && install -D -m 0755 target/release/sandbox-nft-deny-logger /out/sandbox-nft-deny-logger \
    && install -D -m 0755 target/release/sandbox-nft-allow-logger /out/sandbox-nft-allow-logger

# ---------- Stage 3: Envoy binary source ----------
# Pinned to an explicit version for reproducibility.
# This FROM line is tracked by Dependabot (docker ecosystem).
FROM envoyproxy/envoy:v1.38.2 AS envoy

# ---------- Stage 4: Runtime image ----------
FROM debian:bookworm-slim

# Versions — pinned for reproducibility
ARG MITMPROXY_VERSION=11.1.3
ARG TARGETARCH=amd64

# ---------- base packages ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        nftables \
        procps \
    && rm -rf /var/lib/apt/lists/*

# ---------- install Envoy (copied from pinned official image) ----------
COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy

# ---------- install custom CoreDNS with sandboxpolicy plugin ----------
COPY --from=coredns-builder /coredns /usr/local/bin/coredns
RUN chmod +x /usr/local/bin/coredns

# ---------- install nft-logger binaries ----------
# Runtime-only dependency is glibc (≥ the debian:bookworm version the
# builder stage linked against); no extra packages needed. Both
# binaries land side-by-side in `/usr/local/bin/`; the entrypoint
# launches each as its own supervised PID (independent failure
# domains).
COPY --from=nft-loggers-builder /out/sandbox-nft-deny-logger  /usr/local/bin/sandbox-nft-deny-logger
COPY --from=nft-loggers-builder /out/sandbox-nft-allow-logger /usr/local/bin/sandbox-nft-allow-logger
RUN chmod +x /usr/local/bin/sandbox-nft-deny-logger /usr/local/bin/sandbox-nft-allow-logger

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
# Envoy configuration is provided at runtime by sandboxd, not baked
# into the image:
#  - `/etc/envoy/envoy-bootstrap.yaml` is written via `docker exec` after
#    `docker run` but before the entrypoint starts Envoy.
#  - `/etc/envoy/listeners/listener.yaml` lives in a per-session host
#    directory bind-mounted into the container (see `atomic_listener_writer`
#    in `sandbox-core`). Docker creates the mountpoint automatically.
COPY networking/gateway/Corefile /opt/coredns/Corefile
# Both addons import the shared EventEmitter from ``events.py``, so
# it must sit alongside the addon scripts in ``/etc/mitmproxy/`` —
# mitmdump loads the addon by path, and Python resolves the sibling
# ``events`` module via the addon's own directory.
COPY networking/mitmproxy/events.py /etc/mitmproxy/events.py
COPY networking/mitmproxy/passthrough_addon.py /etc/mitmproxy/passthrough_addon.py
COPY networking/mitmproxy/policy_addon.py /etc/mitmproxy/policy_addon.py
COPY networking/gateway/entrypoint.sh /entrypoint.sh
COPY networking/gateway/healthcheck.sh /healthcheck.sh

RUN chmod +x /entrypoint.sh /healthcheck.sh

# ---------- ports ----------
# 10000 - Envoy listener (TCP pass-through)
# 10001 - sandbox-nft-deny-logger TCP listener (denied VM TCP, DNAT'd here)
# 10003 - sandbox-nft-deny-logger health endpoint
# 10004 - sandbox-nft-allow-logger health endpoint
# 8080  - mitmproxy listener (HTTP/HTTPS inspection)
# 53    - CoreDNS (DNS)
# 9901  - Envoy admin (loopback only in config, but declared for docs)
# 8180  - CoreDNS health endpoint
#
# Only the externally reachable ports are `EXPOSE`d. 10001/10003/10004
# are bridge-internal only: nftables DNAT routes denied VM TCP to
# 10001 (denied VM UDP is dropped at PREROUTING and copied via NFLOG
# group 1 — no userland UDP port; allowed VM UDP exits direct via
# MASQUERADE and is observed via NFCT — also no userland UDP port),
# and the HEALTHCHECK probes 10003 + 10004 from inside the container
# (via the bridge IP since the listeners bind on the bridge IP, not
# 127.0.0.1 — see healthcheck.sh). They are not in the EXPOSE list.
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
