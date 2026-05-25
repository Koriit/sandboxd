# Lite-mode container image: minimal Ubuntu 24.04 userland with the
# sandbox-guest agent baked in. Built locally on first use of a given
# daemon version (see `ContainerRuntime::ensure_image`); never pulled
# from a registry.
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
      bind9-dnsutils rsync openssh-server \
    && rm -rf /var/lib/apt/lists/*
# `rsync` is required by `sandbox sync` (the `docker exec -i <ctr>
# rsync --server …` remote side). Keeping it in the image avoids a
# runtime "command not found" the first time an operator reaches for
# directory mirroring.
#
# `openssh-server` provides the in-container sshd reached via the
# daemon's `docker exec ... socat - TCP:127.0.0.1:22` byte mover —
# the unified entry point across both backends. Daemon-side wiring of
# the WebSocket proxy that drives the byte mover is delivered in a
# later session; the lite-image side of the contract is complete here.

# Ubuntu 24.04 ships a default `ubuntu` user at uid 1000; the sandbox
# guest user is pinned at uid 1000 / gid 1000, so remove the default
# first.
RUN userdel --remove ubuntu 2>/dev/null || true \
    && useradd --uid 1000 --user-group --create-home --shell /bin/bash sandbox \
    && install -d -o sandbox -g sandbox /home/sandbox/workspace
# `/home/sandbox/workspace/` is pre-created so cp/sync to subpaths
# under it (e.g. `ws:/home/sandbox/workspace/attr`) succeeds without
# the test or operator having to mkdir first.

COPY sandbox-guest /usr/local/bin/sandbox-guest
RUN chmod +x /usr/local/bin/sandbox-guest

# In-image sshd_config baked into the image so the launch wrapper does
# not have to template it on every container start. The host key path
# points at a tmpfs location (`/tmp/sshd/`) written at container start
# by the launch wrapper — the rootfs is `--read-only` at runtime so a
# persistent file would not work, and the spec specifies the host key
# is ephemeral (regenerated per container start) anyway.
#
# `AuthorizedKeysFile /run/sandbox/authorized_keys` is read by sshd
# from a tmpfs bind-mount that the daemon installs at container start
# in a later session; for now the path is reserved and sshd reports
# "no such file" on connection attempts that are not expected to
# succeed yet.
#
# `UsePAM no` + `PasswordAuthentication no` + `PubkeyAuthentication
# yes` keep the surface tight: the only credential sshd accepts is the
# operator's per-session ed25519 keypair (delivered via the
# `AuthorizedKeysFile`). `StrictModes no` is required because the
# `AuthorizedKeysFile` lives on a tmpfs whose parent directory is not
# owned by the `sandbox` user in the usual way `StrictModes` expects.
# Host-key verification is disabled at the client end (see the
# generated SSH config block); the in-container sshd is reachable
# only through the daemon-mediated `docker exec` byte mover, so there
# is no MITM surface between the SSH client and the in-container sshd.
RUN install -d -o root -g root -m 0755 /etc/sandbox-sshd \
    && printf '%s\n' \
        'Port 22' \
        'ListenAddress 127.0.0.1' \
        'HostKey /tmp/sshd/ssh_host_ed25519_key' \
        'PidFile /tmp/sshd/sshd.pid' \
        'UsePAM no' \
        'PermitRootLogin no' \
        'PubkeyAuthentication yes' \
        'PasswordAuthentication no' \
        'KbdInteractiveAuthentication no' \
        'AuthorizedKeysFile /run/sandbox/authorized_keys' \
        'StrictModes no' \
        'PrintMotd no' \
        'PrintLastLog no' \
        'LogLevel ERROR' \
        'AllowUsers sandbox' \
      > /etc/sandbox-sshd/sshd_config

# Launch wrapper: generate the ephemeral ed25519 host key on every
# container start, start sshd, then exec sandbox-guest as the
# foreground process the way the previous entrypoint did. Both
# processes run as the container's uid in the same user namespace;
# sshd binds port 22 because the daemon-side
# `--sysctl net.ipv4.ip_unprivileged_port_start=22` lowers the
# privileged-port floor inside the container netns, no capabilities
# required.
#
# `tini` (the existing ENTRYPOINT) reaps zombies and forwards signals
# so the lingering sshd children get cleaned up on container stop.
#
# Best-effort sshd. OpenSSH (both `ssh-keygen` and `sshd`) calls
# `getpwuid(geteuid())` at startup and aborts when the running uid
# has no entry in `/etc/passwd`. With the runtime's
# `--user <daemon-uid>:<daemon-gid>` flag, the in-container uid may
# match no passwd entry (e.g. the daemon's `sandbox` system uid 999
# on a host where the image's `sandbox` user is uid 1000). The script
# logs the sshd-startup failure and continues to `sandbox-guest` so
# the in-container guest-agent transport (`docker exec ... socat -
# TCP:127.0.0.1:5123`) the existing `sandbox ssh` path uses still
# works. The new daemon-mediated SSH proxy is built on top of sshd
# and so only works when the running uid is the in-image `sandbox`
# user (uid 1000) — the daemon-side keypair plumbing delivered in a
# later session pairs naturally with that configuration.
RUN printf '%s\n' \
        '#!/bin/sh' \
        '# Intentionally no `set -e`: sshd startup is best-effort.' \
        '# If `ssh-keygen` or `sshd` exits non-zero (e.g. because the' \
        '# running uid has no entry in /etc/passwd), we still want to' \
        '# exec the foreground `sandbox-guest` so the existing' \
        '# `docker exec`-based guest-agent transport keeps working.' \
        '' \
        '# Ephemeral sshd host key + pidfile dir on tmpfs (/tmp is' \
        '# writable per the daemon-supplied --tmpfs flag).' \
        'mkdir -p /tmp/sshd 2>/dev/null && chmod 0700 /tmp/sshd 2>/dev/null' \
        'if ssh-keygen -q -t ed25519 -f /tmp/sshd/ssh_host_ed25519_key -N "" </dev/null 2>/dev/null; then' \
        '  # Start sshd in the background, listening on 127.0.0.1:22' \
        '  # inside the container netns. Not exposed to the host —' \
        '  # reachable only via the daemon-mediated `docker exec` byte' \
        '  # mover delivered in a later session.' \
        '  if ! /usr/sbin/sshd -f /etc/sandbox-sshd/sshd_config 2>/dev/null; then' \
        '    echo "sandbox-entrypoint: sshd failed to start; continuing without it" >&2' \
        '  fi' \
        'else' \
        '  echo "sandbox-entrypoint: ssh-keygen failed (probably uid has no /etc/passwd entry); continuing without sshd" >&2' \
        'fi' \
        '' \
        '# Hand over to sandbox-guest as the foreground process the' \
        '# previous entrypoint produced. tini (the actual PID 1)' \
        '# wraps both processes.' \
        'exec /usr/local/bin/sandbox-guest "$@"' \
      > /usr/local/bin/sandbox-entrypoint.sh \
    && chmod +x /usr/local/bin/sandbox-entrypoint.sh

USER 1000:1000
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sandbox-entrypoint.sh"]
