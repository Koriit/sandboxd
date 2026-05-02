# Lite-mode container image: minimal Ubuntu 24.04 userland with the
# sandbox-guest agent baked in. Built locally on first use of a given
# daemon version (see `ContainerRuntime::ensure_image`); never pulled
# from a registry.
#
# Spec: `.tasks/specs/2026-04-22-lite-mode-container-backend-design`
#       § "Image building / Dockerfile shape" — base, packages, user,
#       and entrypoint are all pinned by the spec.
#
# This Dockerfile must remain self-contained (`Dockerfile` + a
# prebuilt `sandbox-guest` binary in the build context, nothing else).
# The daemon embeds this file via `include_str!` at compile time and
# runs `docker build` from a tempdir at runtime, on user machines that
# do not have the Rust workspace source or toolchain available
# (`sandbox-core::backend::container::build_lite_image`). An
# in-container builder stage — like the gateway image's nft-loggers —
# would break that runtime path. The host-built binary is therefore a
# constraint of the runtime build, not a stylistic choice.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash coreutils git socat ca-certificates iproute2 curl tini \
      bind9-dnsutils rsync \
    && rm -rf /var/lib/apt/lists/*
# `rsync` is required by `sandbox sync` (the `docker exec -i <ctr>
# rsync --server …` remote side). Keeping it in the image avoids a
# runtime "command not found" the first time an operator reaches for
# directory mirroring.

# Ubuntu 24.04 ships a default `ubuntu` user at uid 1000; the spec pins the
# agent user at uid 1000 / gid 1000, so remove the default first.
RUN userdel --remove ubuntu 2>/dev/null || true \
    && useradd --uid 1000 --user-group --create-home --shell /bin/bash agent \
    && install -d -o agent -g agent /home/agent/workspace
# `/home/agent/workspace/` is pre-created so cp/sync to subpaths under
# it (e.g. `ws:/home/agent/workspace/attr`) succeeds without the test
# or operator having to mkdir first. Lima's cloud-init creates the
# same directory; this mirrors it so both backends present an
# identical filesystem layout.

COPY sandbox-guest /usr/local/bin/sandbox-guest
RUN chmod +x /usr/local/bin/sandbox-guest

USER 1000:1000
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandbox-guest"]
