# macOS Operations Guide

This guide covers macOS-specific operational topics: coexistence with other
Lima-based tools, disk usage and APFS accounting, and DNS resolver behavior
across host network changes.

## Coexistence with existing Lima and Colima setups

sandboxd uses Lima internally but is completely isolated from any Lima or
Colima installation you use for personal development.

**Separate home directories.** sandboxd stores all its Lima instance state
under `/var/lib/sandboxd/<_sandboxd-uid>/lima/` (gateway VM, per-operator base
images). Your personal Lima home (`~/.lima/`) and any Colima state are never
read or written by sandboxd.

**Separate vmnet sockets.** sandboxd registers its own pool of `socket_vmnet`
instances under the LaunchDaemon labels `io.sandboxd.vmnet.<n>`. These are
separate from any Homebrew-managed `socket_vmnet` instance that Colima or Lima
uses. sandboxd writes no shared `networks.yaml` configuration; each VM's
template specifies its vmnet socket path directly.

**No shared Docker.** sandboxd does not use the host Docker daemon, Docker
Desktop, OrbStack, or Rancher Desktop. It communicates exclusively with Docker
inside the `sandboxd-gateway` Lima VM via a forwarded Unix socket.

**CPU and memory ceilings are shared.** macOS gives each process its own
scheduling context, but QEMU VMs compete for host RAM and vCPUs with any other
VMs running at the same time. If you run large personal Lima VMs alongside
sandboxd sessions, budget accordingly — there is no hypervisor-level
reservation isolating them.

**Summary of what sandboxd touches (and does not touch):**

| Resource | sandboxd uses | Personal Lima/Colima |
|---|---|---|
| Lima home | `/var/lib/sandboxd/<uid>/lima/` | `~/.lima/` |
| vmnet sockets | `/var/run/sandbox/vmnet/` | `/var/run/lima/` (Homebrew default) |
| Docker daemon | Inside gateway VM only | Host Docker / Desktop / OrbStack |
| `networks.yaml` | Never written | Managed by Lima/Colima |

## Disk usage and APFS accounting

sandboxd stores sandbox VM disk images under the daemon's LIMA_HOME. On APFS
volumes (the default on Apple Silicon Macs), APFS copy-on-write means that
clones share unchanged blocks with the base image at no extra cost.

### Footprint components

| Component | Typical size | Notes |
|---|---|---|
| `sandboxd-gateway` Lima VM | ~4–6 GB | One per host; shared across all operators |
| `sandbox-base` Lima VM (per operator) | ~4–6 GB | One per operator; clones diverge from here |
| Session VM clone | < 1 GB initially | Grows as the session writes files |
| Gateway image tarball | ~500 MB | Retained at daemon LIMA_HOME for self-heal |
| Lite container image | ~300 MB | Retained at daemon LIMA_HOME |

### APFS accounting notes

**`du` overstates usage.** The `du` command reports apparent size and does not
account for APFS block sharing between clones. A base VM plus N clones each
report their full apparent size in `du` output even though most blocks are
shared.

**Use `diskutil` or `df` for actual free space.** `diskutil apfs cliInfo
<volume>` and `df -h /` report the volume's true free space after APFS
deduplication. These are the authoritative numbers to watch.

**APFS GC is async.** When `sandbox rm` deletes a session, the diverged
blocks specific to that session's clone are freed, but APFS garbage-collects
them asynchronously. Free space may not increase immediately after a delete.

**Boot-volume accounting.** All sandbox state lives on the boot volume by
default. Finder and macOS system tools (Storage → System Information) see the
sandbox disk images as ordinary files and report the space as used. This is
expected.

**Disk space warning.** `sandbox doctor` warns when free space on the sandbox
state volume drops below 10 GiB. There is no hard enforcement threshold —
`sandbox create` does not consult free space before starting. The 10 GiB
threshold is a conservative starting point; refine it based on your session
workload.

### Reclaiming disk space

```
# Build cache (largest reclaimable chunk; does NOT remove tagged images):
docker builder prune -f

# Dangling/untagged image layers only:
docker image prune -f

# Reap orphaned QEMU processes from crashed sessions:
pkill -f qemu-system

# Remove a session and its VM clone:
sandbox rm <session-name>
```

Do **not** run `docker system prune -a` while sandboxd is in use — it removes
the tagged `sandbox-gateway` and `sandbox-lite` images and forces the daemon to
reload them from the retained tarballs on next start.

## DNS resolver staleness across host network changes

### How resolvers are configured

When the `sandboxd-gateway` Lima VM starts, the daemon reads the host's
current DNS resolvers from `scutil --dns` and writes them into the gateway
VM's `/etc/resolv.conf`. CoreDNS inside the gateway VM uses these resolvers
as its upstream for all sandbox sessions.

### The staleness scenario

The gateway VM is **persistent** — it keeps running across daemon restarts and
across host sleep/wake cycles. If you change networks (e.g., move from your
office Wi-Fi to a home network or a VPN), the gateway VM's `/etc/resolv.conf`
still contains the resolvers from the time it last booted. Those resolvers may
be unreachable from the new network, causing DNS resolution to fail for all
sandbox sessions.

**Symptoms:** sandbox sessions can reach IP addresses directly but cannot
resolve domain names. `sandbox doctor` may report DNS-related health issues.

### Remedy

Restart the gateway VM to pick up the new resolvers:

```sh
# Option 1: restart the daemon (also restarts the gateway VM):
sudo launchctl kickstart -k system/io.sandboxd.daemon

# Option 2: direct limactl restart (daemon must be stopped first):
# sudo launchctl stop system/io.sandboxd.daemon
# limactl stop sandboxd-gateway && limactl start sandboxd-gateway
# sudo launchctl start system/io.sandboxd.daemon
```

Running sessions survive a daemon restart if their VMs are still up; the
daemon reconciles and reconnects their gateway containers on startup.

**Note:** Automatic detection of host network changes and live re-injection of
resolvers into the running gateway VM is not implemented in the current
release. The manual restart is the supported remedy. Watch the issue tracker
for a future `sandbox update-resolvers` command or a daemon-triggered
auto-refresh.
