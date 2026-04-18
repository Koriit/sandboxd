---
title: sandboxd
description: Isolated, policy-controlled Linux VMs for coding agents — per-session networking, TLS interception, and a deny-by-default policy engine.
template: splash
hero:
  title: sandboxd
  tagline: Isolated, policy-controlled Linux VMs for coding agents.
  actions:
    - text: Quickstart
      link: /start/quickstart/
      icon: right-arrow
      variant: primary
    - text: Concepts
      link: /concepts/architecture/
    - text: Reference
      link: /reference/cli/
---

Give your coding agents a real Linux box without giving them the keys to your laptop. Every session boots its own QEMU/KVM VM with a per-session gateway that filters outbound traffic, intercepts TLS for inspection, and denies everything you have not explicitly allowed.

Start with the [Quickstart](/start/quickstart/) to get a session running in about five minutes, or read [What is sandboxd?](/start/what-is-sandboxd/) for the motivation and trade-offs.
