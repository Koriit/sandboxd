---
title: What is sandboxd?
description: A daemon that gives coding agents isolated Linux VMs with per-session networking, TLS interception, and a deny-by-default policy engine.
---

sandboxd runs coding agents inside real Linux virtual machines, one per session, with an opinionated networking pipeline that you can lock down to just the traffic you want. It is built for workflows where you hand an LLM a shell and a repository and would rather not hand it the rest of your machine too.

## What you get per session

Every session you create gives you:

- A dedicated guest runtime — by default a QEMU/KVM virtual machine managed by Lima, optionally a Docker container via `--lite` / `--backend container` for fast ephemeral sessions; either way with its own filesystem and an in-guest agent.
- A per-session Docker bridge network — no cross-session traffic path, no access to the host network.
- A gateway container running five processes — Envoy, mitmproxy, CoreDNS, sandbox-nft-deny-logger, and sandbox-nft-allow-logger — that together mediate all outbound traffic.
- A per-session CA that mitmproxy uses for TLS interception. The private key never leaves the gateway.
- A deny-by-default policy. Without an allow rule, DNS returns `NXDOMAIN` and outbound connections fail.

You talk to the daemon with the `sandbox` CLI over a Unix socket. The CLI creates sessions, runs commands, ships files in and out, and hot-reloads policies without restarting the VM.

## Problems it solves

**You want to run an agent against a real codebase without trusting it with your user account.** The VM gives you hardware-level isolation (Lima backend); for less-sensitive workloads the lite container backend gives you the same gateway and policy contract with a smaller, faster substrate. The policy engine gives you a short, auditable list of domains the agent is allowed to reach.

**You need to see what the agent actually talks to.** mitmproxy intercepts TLS with the per-session CA, so you can inspect HTTPS traffic that would otherwise be opaque. Policy rules can go as deep as matching HTTP methods and paths.

**You want reproducible, disposable environments.** Sessions are cheap. You create one per task, run the agent, capture anything you care about, and remove it. State in `/home/agent/workspace` lives only as long as the session does, unless you bind-mount a host directory with `--workspace shared:<path>`.

**You want to clone and push repositories into the VM without exposing ports.** `git-remote-sandbox` is a symlink to the `sandbox` binary that tunnels the git pack protocol over the daemon's SSH channel, so `git clone sandbox::my-session/home/agent/workspace` just works.

## When to use it

sandboxd fits best when you are:

- Running coding agents (Claude Code and similar) against repositories you do not want them to exfiltrate.
- Building CI-like flows where each job runs in a fresh, policy-bounded VM.
- Experimenting with agent tool use and want to inspect every outbound request.
- Giving teammates or untrusted scripts a short-lived shell with a tight network allowlist.

It is probably not what you want if you need sub-second start-up, macOS guests, or a hosted multi-tenant platform. Session create takes 2 to 5 minutes on first run and under a minute with the cached base image. Everything runs locally on your Linux host.

## How it fits together

The CLI talks to a single daemon over a Unix socket. The daemon owns session lifecycle, drives `limactl` to manage VMs, allocates per-session Docker bridges, and compiles policy rules into configuration for Envoy, mitmproxy, CoreDNS, and nftables. A guest agent inside each VM handles command execution and file transfer.

For the full component breakdown and the traffic path, see [Architecture](/sandboxd/concepts/architecture/). When you are ready to install, jump to [Installation](/sandboxd/start/installation/) or the [Quickstart](/sandboxd/start/quickstart/).
