# Lite-mode container image: minimal Ubuntu 24.04 userland with the
# sandbox-guest agent baked in. Built locally on first use of a given
# daemon version (see `ContainerRuntime::ensure_image`); never pulled
# from a registry.
#
# Spec: `.tasks/specs/2026-04-22-lite-mode-container-backend-design`
#       § "Image building / Dockerfile shape" — base, packages, user,
#       and entrypoint are all pinned by the spec.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash coreutils git socat ca-certificates iproute2 curl tini \
      bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu 24.04 ships a default `ubuntu` user at uid 1000; the spec pins the
# agent user at uid 1000 / gid 1000, so remove the default first.
RUN userdel --remove ubuntu 2>/dev/null || true \
    && useradd --uid 1000 --user-group --create-home --shell /bin/bash agent

COPY sandbox-guest /usr/local/bin/sandbox-guest
RUN chmod +x /usr/local/bin/sandbox-guest

USER 1000:1000
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandbox-guest"]
