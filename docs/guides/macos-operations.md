# macOS Operations Guide

This guide covers macOS-specific operational topics: coexistence with other
Lima-based tools, disk usage and APFS accounting, and DNS resolver behavior
across host network changes.

## Host IP forwarding must be disabled

sandboxd requires `net.inet.ip.forwarding=0` on the host before it will start.
This is an egress-safety gate: when host IP forwarding is enabled, the macOS
vmnet bridge can route guest traffic off the sandbox network segment, bypassing
the gateway and voiding the egress enforcement guarantee.

If the daemon refuses to start with a message like:

```
host IP forwarding (net.inet.ip.forwarding=1) must be 0 for egress control
```

reset it with:

```sh
sudo sysctl -w net.inet.ip.forwarding=0
```

**What enables host IP forwarding.** Two common sources:

- **Internet Sharing.** Enabling Internet Sharing in System Settings flips
  `net.inet.ip.forwarding=1`. Turn Internet Sharing off and run the reset command
  above before starting sandboxd.
- **Sleep/wake cycles.** On some macOS versions, returning from sleep can
  re-enable forwarding if Internet Sharing was ever active. If the daemon refuses
  to start after a sleep/wake, run the reset command.

The reset reverts immediately and does not require a reboot. The value is not
persisted across reboots unless Internet Sharing is left enabled in System Settings.

`sandbox doctor` surfaces this as check **C24 — IP forwarding disabled** and
shows the current sysctl value so you can confirm the state without running the
reset blindly.

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

## Resizing the session pool (`max_macos_sessions`)

`max_macos_sessions` (env `SANDBOX_MAX_MACOS_SESSIONS`, default 8, range
1–32) caps how many full-backend sessions run concurrently: it fixes the size
of the `socket_vmnet` pool and the number of NICs the gateway VM is created
with. Because Lima fixes a VM's NIC set at creation and the pool daemons are
root-owned, a changed value is picked up at daemon startup — and applied only
when it can be applied without disrupting live sessions.

**Changing the value while sessions are running is safe.** When sandboxd
starts and finds `max_macos_sessions` no longer matches the gateway's actual
NIC count while one or more full-backend sessions are still `Running`, it does
not rebuild or resize the pool. It keeps the currently-discovered set of vmnet
slots and their launchd daemons, logs a warning, and continues serving the
running sessions with the existing pool. This holds in both directions,
including when the new limit is set *below* the number of sessions currently
live — running sessions are never torn down to satisfy a lowered limit. The
resize is deferred, not rejected.

**Applying a deferred change.** Stop all full-backend sessions, then restart
sandboxd; with nothing running, startup rebuilds the gateway to the new NIC
count. A resize also requires the root-owned vmnet daemon set to match the new
size; if it does not, startup logs that requirement and again keeps the
current pool rather than rebuilding. Re-provision the daemon set with the
privileged setup step and restart sandboxd once more:

```
make setup-dev-env DARWIN_VMNET_SLOTS=<n>
```

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

## Workspace access and TCC (Transparency, Consent, and Control)

macOS TCC governs access to user data in protected directories: `~/Documents`,
`~/Desktop`, `~/Downloads`, `~/Pictures`, `~/Movies`, `~/Music`, and similar
locations. sandboxd interacts with TCC only through `shared:` workspace mounts
on the full Lima backend.

### Zero-prompt default

If you keep your workspace outside protected directories — for example
`~/projects/my-repo`, `~/dev/work`, `/tmp/scratch` — TCC never triggers.
No consent dialog, no System Settings entry needed. This is the recommended
starting point.

```sh
# No TCC involvement:
sandbox create --workspace shared:~/projects/my-repo
```

### One-time TCC consent for protected directories

`sandbox create --workspace shared:~/Documents/my-project` makes the sandbox
VM access `~/Documents` on the host via a 9p shared mount whose host-side file
access is performed by the `sandbox-agent` process running in your login
session.

Because the agent runs in your Aqua session as your own uid, macOS can show you
a normal "allow access to your Documents?" consent prompt — the first time you
use a protected directory. After you click Allow, the grant persists across
subsequent uses.

**Which binary triggers the prompt** depends on how macOS TCC attributes the
file access within the `sandbox-agent` → `limactl` → `qemu-system` process
chain. The possible outcomes are:

| Attribution | Effect |
|---|---|
| `sandbox-agent` | One clean grant, stable across `brew upgrade qemu` and `brew upgrade lima` |
| `qemu-system` or `limactl` | Grant re-triggers on every `brew upgrade qemu`/`lima` because the cdhash changes |

Both cases produce a working grant; only the upgrade-invalidation behavior
differs. See the manual verification procedure at the end of this section for
the step to confirm which binary your system attributes the access to.

### Full Disk Access fallback

If no TCC prompt appears when you first use a protected directory — possible
when `qemu-system` is fully daemonized and detached from the agent's
responsibility chain — the access is silently denied. The remedy is a one-time
manual grant via System Settings:

1. Open **System Settings → Privacy & Security → Full Disk Access**.
2. Click the `+` button and add the binary that owns the access (either
   `sandbox-agent` at `/usr/local/libexec/sandboxd/sandbox-agent`, or
   `/opt/homebrew/bin/qemu-system-aarch64` if TCC attributed the access there).
3. Toggle the switch to On and authenticate.

After granting Full Disk Access, the protected-directory mount works without
further prompts.

**`brew upgrade` caveat.** If TCC granted access to `qemu-system` or `limactl`
rather than to `sandbox-agent`, any `brew upgrade qemu` or `brew upgrade lima`
changes the binary's cdhash and invalidates the grant, re-triggering a prompt
on next use. To avoid repeated grants, either use the Full Disk Access option
(which is stable across upgrades) or keep workspaces outside protected
directories.

### TCC and the lite (container) backend

The lite backend uses `_sandboxd` (the system daemon user) to perform host-side
file access for `shared:` mounts, not the operator's session. TCC consent from
the operator does not apply to the daemon user — access is silently denied for
protected directories regardless of any per-operator grant. Keep lite-backend
`shared:` sources outside TCC-protected directories.

### `sandbox doctor` TCC check

`sandbox doctor` displays a **C23 — TCC workspace access** row. This row is
informational only; it does not block doctor from passing or prevent session
creation. If a `shared:` mount into a protected directory fails, consult
the Full Disk Access grant steps above rather than the doctor row.

---

## Real-chain TCC verification procedure (manual, Aqua GUI session required)

This procedure records which binary in the agent → `limactl` → `qemu-system`
chain TCC attributes a protected-directory file access to, and whether a
consent prompt appears at all. Run it on a real Apple-Silicon Mac with an
active GUI login session. It cannot be performed headlessly or in a CI
environment.

**Prerequisites before starting:**

- [ ] sandboxd installed and the daemon running (`sandbox doctor` reports
      healthy).
- [ ] The `io.sandboxd.agent` LaunchAgent is loaded in your login session
      (check: `launchctl print gui/$(id -u)/io.sandboxd.agent` — should not
      return error).
- [ ] No existing TCC grant for `sandbox-agent`, `qemu-system-aarch64`, or
      `limactl` in **System Settings → Privacy & Security → Full Disk Access**.
      Remove any pre-existing grants before running this test to avoid masking
      a denial.
- [ ] `~/Documents/tcc-test/` directory exists and contains at least one file
      the test session can read.

**Steps:**

1. Open a terminal in your GUI login session (not SSH-only).

2. Confirm the agent is running in your Aqua session:
   ```sh
   launchctl print gui/$(id -u)/io.sandboxd.agent
   ```
   The output should show `state = running`. If it shows `state = not running`,
   the agent has not checked in with the daemon yet — wait a moment and retry,
   or check `/var/log/sandbox/agent.stderr.log` for errors.

3. Create a full-backend session with a `shared:` mount into `~/Documents`:
   ```sh
   sandbox create --workspace shared:~/Documents/tcc-test my-tcc-test
   ```

4. **Observe:** Does a TCC consent dialog appear?

   - **If yes:** Note the binary name shown in the dialog. It is either
     `sandbox-agent`, `limactl`, or `qemu-system-aarch64`. Record it in the
     results table below.
   - **If no dialog appears and the mount fails:** TCC silently denied access
     (fully daemonized qemu with no Aqua responsibility chain). Record
     "no prompt, access denied" and use the Full Disk Access fallback.
   - **If no dialog appears and the mount succeeds:** A pre-existing grant
     is masking the test. Re-check and clear all relevant grants, then retry.

5. If a dialog appeared, click **Allow**.

6. Verify the mount works:
   ```sh
   sandbox exec my-tcc-test -- ls /workspace
   ```
   You should see the files from `~/Documents/tcc-test/`.

7. Test grant persistence across a session restart:
   ```sh
   sandbox stop my-tcc-test
   sandbox start my-tcc-test
   sandbox exec my-tcc-test -- ls /workspace
   ```
   No second prompt should appear; the mount should succeed.

8. Test upgrade invalidation (only relevant if the dialog named `qemu-system`
   or `limactl`):
   ```sh
   brew upgrade qemu  # or: brew upgrade lima
   sandbox stop my-tcc-test
   sandbox start my-tcc-test
   sandbox exec my-tcc-test -- ls /workspace
   ```
   If a new consent prompt appears after the upgrade, the grant was keyed to
   the Homebrew binary's cdhash. Record this behavior in the table below.

9. Clean up:
   ```sh
   sandbox rm --force my-tcc-test
   ```

**Results table — record outcome here:**

| Item | Result |
|---|---|
| macOS version | |
| Apple Silicon model | |
| Prompt appeared on first `shared:~/Documents` access? | yes / no |
| If yes — binary named in the prompt | sandbox-agent / qemu-system-aarch64 / limactl / other |
| Mount succeeded after Allow? | yes / no |
| Grant persisted across session restart? | yes / no |
| After `brew upgrade qemu` — new prompt appeared? | yes / no / not tested |
| Full Disk Access required as fallback? | yes / no |
| Notes | |
