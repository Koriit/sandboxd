---
title: Your first real session
description: Go beyond the quickstart — clone a repo into a session, apply a network policy, run a real build, and copy artifacts back to your host.
---

The [Quickstart](/sandboxd/start/quickstart/) gets a session running and a shell inside it. This guide walks you through a realistic flow: you clone a repository into the session, apply a network policy that restricts what the session can reach, run a real command inside, and copy an artifact back to the host.

You need sandboxd installed and the daemon running. If either is missing, see [Installation](/sandboxd/start/installation/) and the [Quickstart](/sandboxd/start/quickstart/).

## What you will build

By the end you will have:

- A session that cloned a public GitHub repository at creation time.
- A network policy that denies everything by default and explicitly allows GitHub + the Rust crates registry.
- A real build running inside that policy.
- A build artifact copied back to your host.

## 1. Write a policy file

Before you create the session, write the policy it will run under. A policy is JSON: a `version` and an ordered list of rules. Each rule specifies a `host`, an explicit `port`, an L4 `protocol` (`tcp` or `udp`), and an assurance level. Unmatched destinations are denied.

Save this as `~/policies/rust-build.json`:

```json
{
  "version": "2.0.0",
  "rules": [
    {
      "host": "github.com",
      "port": 443,
      "protocol": "tcp",
      "level": "tls",
      "reason": "source fetch"
    },
    {
      "host": "codeload.github.com",
      "port": 443,
      "protocol": "tcp",
      "level": "tls",
      "reason": "GitHub tarball CDN"
    },
    {
      "host": "static.crates.io",
      "port": 443,
      "protocol": "tcp",
      "level": "tls",
      "reason": "crate downloads"
    },
    {
      "host": "index.crates.io",
      "port": 443,
      "protocol": "tcp",
      "level": "tls",
      "reason": "crates.io sparse index"
    },
    {
      "host": "crates.io",
      "port": 443,
      "protocol": "tcp",
      "level": "tls",
      "reason": "crates.io metadata"
    }
  ]
}
```

This grants the session "TLS-verified passthrough" to exactly those five hosts. That is: the gateway terminates the TLS SNI, verifies the destination, but does not MITM the traffic. Anything else — DNS lookups, direct-IP connections, other domains — is denied.

For a deeper look at what each assurance level means, see [Policy model](/sandboxd/concepts/policy-model/).

## 2. Create the session

Create a session that clones a repository at boot and applies the policy you just wrote:

```bash
sandbox create \
    --name rust-build \
    --cpus 4 --memory 8192 \
    --repo https://github.com/BurntSushi/ripgrep.git \
    --policy ~/policies/rust-build.json
```

What happens, in order:

1. The daemon clones (fast path) or builds (slow path) the VM.
2. The gateway container starts with the initial policy already loaded.
3. The VM's cloud-init runs `git clone https://github.com/BurntSushi/ripgrep.git /home/sandbox/workspace`.
4. The guest agent comes up; `sandbox create` returns.

On a warm host this takes under a minute. On first run it can take two to five minutes because Lima downloads the Ubuntu cloud image.

Check the state:

```bash
sandbox ps
```

You should see `running` + `connected` + `healthy`.

## 3. Verify the policy is in effect

Before running the build, confirm the policy does what you think it does. Try reaching a host that is **not** in the allow-list:

```bash
sandbox exec rust-build -- curl -s -o /dev/null -w '%{http_code}\n' https://example.com
```

You should see a curl failure (connection refused / DNS failure) — not a 200. The session cannot resolve or reach `example.com` because it is not in the policy.

Now try a host that **is** allowed:

```bash
sandbox exec rust-build -- curl -s -o /dev/null -w '%{http_code}\n' https://github.com
```

You should see a 200 (or a redirect).

## 4. Run the real build

`ripgrep` is a Rust project; the base image already has `rustc` and `cargo`. Kick off a release build:

```bash
sandbox exec rust-build -- bash -c 'cd /home/sandbox/workspace && cargo build --release 2>&1 | tail -20'
```

Cargo reaches out to `index.crates.io` and `static.crates.io` for dependencies — both of which your policy allows. You should see crate downloads streaming by, then a normal compile.

If you need an interactive session to poke around mid-build, `sandbox ssh`:

```bash
sandbox ssh rust-build
```

You land as the `sandbox` user with the workspace at `/home/sandbox/workspace` (the in-VM user is named `sandbox` on both backends, with home at `/home/sandbox/`). Exit with `Ctrl-D`.

## 5. Copy the artifact back to your host

Once the build finishes, pull the binary back to the host:

```bash
sandbox cp rust-build:/home/sandbox/workspace/target/release/rg ./rg
chmod +x ./rg
./rg --version
```

`sandbox cp` uses `session:path` syntax on whichever side is the remote one. Reverse the arguments to upload a file instead.

## 6. Tighten or relax the policy on the fly

You can swap the active policy on a running session without restarting the VM. To tighten (say, revoke GitHub):

```bash
jq 'del(.rules[] | select(.host=="github.com"))' \
    ~/policies/rust-build.json > ~/policies/rust-build-no-gh.json
sandbox policy update rust-build --policy ~/policies/rust-build-no-gh.json
```

To wipe the policy entirely and go fail-closed (empty allow-list — nothing reachable):

```bash
sandbox policy update rust-build --clear
```

`--clear` is idempotent: it leaves the session in the same fail-closed state as a freshly created session with no `--policy`. There is no built-in "allow everything" escape hatch — denials surface through gateway logs, and the workflow is to widen the policy to cover what the build actually needs.

## 7. Clean up

When you are done:

```bash
sandbox rm rust-build
```

`rm` stops the VM, tears down the gateway and Docker bridge, removes the CA, and deletes the session row. The session ID is gone — next `create` gets a new one.

If you want to pause instead, `sandbox stop rust-build` halts the VM but keeps the config, policy, and subnet allocation. `sandbox start rust-build` brings it back.

## What to read next

- [Workspaces](/sandboxd/guides/workspaces/) — use `--workspace shared:...` to mount a host directory instead of cloning.
- [Network policies](/sandboxd/guides/network-policies/) — author and distribute policies at scale.
- [Integrate with a coding agent](/sandboxd/guides/integrate-agent/) — drive all of this from a script.
- [Concepts: policy model](/sandboxd/concepts/policy-model/) — what each assurance level does under the hood.
