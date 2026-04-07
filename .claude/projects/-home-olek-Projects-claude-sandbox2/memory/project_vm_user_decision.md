---
name: VM agent user is passwordless sudoer, not root
description: Lima makes running as root difficult — VM user is a passwordless-sudoer 'agent' user instead of root. Design doc still says root and needs updating.
type: project
---

Agent runs as passwordless-sudoer `agent` user inside the VM, not root. Lima makes direct root login difficult.

**Why:** Lima's architecture doesn't easily support running as root. A passwordless-sudoer user provides the same effective privileges (agents can `sudo` any command without a password prompt) while working with Lima's grain.

**How to apply:** The sandbox-design.md still says "agent runs as root" in the VM privilege model section. This needs updating to reflect the sudoer model. The security argument is unchanged — the VM boundary provides isolation, not the privilege level inside the guest. Update the design doc when touching that section.
