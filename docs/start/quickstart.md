---
title: Quickstart
description: Install prerequisites, build sandboxd, and run your first policy-bounded session in about five minutes.
---

This page takes you from a fresh Linux host to a running sandbox session you can shell into. You need about five minutes, plus the first-boot image download.

If you hit a snag, jump to [Troubleshooting](/guides/troubleshooting/) or the deeper [Installation guide](/start/installation/).

## Prerequisites

You need a Linux x86_64 host with KVM, Docker, Lima, QEMU, and a Rust toolchain. Check them in one go:

```bash
ls /dev/kvm && docker info >/dev/null && limactl --version && rustc --version
```

If any of those fail, stop here and follow [Installation](/start/installation/). The most common blockers are KVM group membership and Docker group membership — both require a logout after `usermod -aG`.

## 1. Clone and build

```bash
git clone https://github.com/anthropics/claude-sandbox.git
cd claude-sandbox
make build
make gateway-image
```

`make build` produces `sandboxd`, `sandbox`, and `sandbox-guest` in `sandboxd/target/debug/`. `make gateway-image` builds the Docker image that runs Envoy, mitmproxy, and CoreDNS inside each session's gateway container.

Put the CLI on your `PATH` for convenience:

```bash
export PATH="$PWD/sandboxd/target/debug:$PATH"
```

## 2. Start the daemon

In one terminal, run the daemon in the foreground so you can watch it:

```bash
sandboxd
```

The daemon creates its state directory at `~/.local/share/sandboxd/` and listens on `$XDG_RUNTIME_DIR/sandboxd/sandboxd.sock`. Leave this terminal open.

## 3. Create your first session

In a second terminal:

```bash
sandbox create --name hello
```

On the first run, Lima downloads the Ubuntu 24.04 cloud image (about 700 MB) and caches it. First create takes 2 to 5 minutes end-to-end; subsequent creates drop to under a minute.

When it finishes, check the session:

```bash
sandbox ps
```

You should see something like:

```
ID            NAME   STATE     AGENT      GATEWAY    CREATED
a1b2c3d4e5f6  hello  running   connected  healthy    30s ago
```

## 4. Run a command

Use `sandbox exec` to run a command through the daemon's guest agent channel:

```bash
sandbox exec hello -- uname -a
```

For an interactive shell, use `sandbox ssh`:

```bash
sandbox ssh hello
```

You land in the VM as the `agent` user. The workspace lives at `/home/agent/workspace`. Exit the shell with `Ctrl-D` or `exit`.

## 5. Copy files in and out

```bash
echo "hello from host" > note.txt
sandbox cp note.txt hello:/home/agent/workspace/note.txt
sandbox exec hello -- cat /home/agent/workspace/note.txt
```

Pull files back with the same command, reversed:

```bash
sandbox cp hello:/home/agent/workspace/note.txt ./note-from-vm.txt
```

## 6. Clean up

Remove the session when you are done. This stops the VM, tears down networking, and deletes the session from the database:

```bash
sandbox rm hello
```

## What to read next

- [Architecture](/concepts/architecture/) for what the components do and how traffic flows.
- [CLI reference](/reference/cli/) for every command and flag.
- [Troubleshooting](/guides/troubleshooting/) when something does not work.
