# Workspace Modes

This guide covers the different ways to provide source code and project
files to a sandbox VM.  Each mode offers a different trade-off between
isolation, performance, and developer ergonomics.

## Overview

A sandbox session can receive workspace files through several mechanisms:

| Mode                | Flag / API field            | Direction     | Latency       | Isolation |
|---------------------|-----------------------------|---------------|---------------|-----------|
| Clone               | `--repo <url>`              | One-shot pull | Minutes       | Full      |
| Shared mount        | `--workspace shared:<path>` | Bidirectional | Instant       | Reduced   |
| sandbox cp          | `sandbox cp`                | Bidirectional | Per-transfer  | Full      |
| git remote transport      | `ext::sandbox git-remote`   | Push / pull   | Per-operation | Full      |

The sections below describe each mode in detail.


## Clone mode

Clone mode pulls a git repository into the VM during session creation.
This is the default way to provision source code when the project lives
in a remote repository.

### Usage

```bash
# Create a session and clone a public repo
sandbox create --name dev \
    --repo https://github.com/octocat/Hello-World.git

# Private repos: the gateway must allow the git host
sandbox create --name dev \
    --policy policy.json \
    --repo https://github.com/myorg/private-repo.git
```

API equivalent:

```json
{
  "name": "dev",
  "repo": "https://github.com/myorg/private-repo.git"
}
```

### Details

- The repository is cloned into `/root/workspace/` inside the VM.
- The clone runs as a post-boot provisioning step via the guest agent.
- A network policy must allow the git hosting domain (e.g. `github.com`)
  at the `transport` assurance level or higher, otherwise the clone will
  fail.  Clone failure is non-fatal: the session is still usable, but
  the workspace directory will be missing.
- Clone mode runs `git clone` once.  Subsequent pulls or pushes require
  either network access (via policy) or the git remote transport.


## Shared mount

Shared mount mode exposes a host directory directly inside the VM using
Lima's 9p mount support.  File changes are bidirectional and visible
immediately on both sides.

### Usage

```bash
# Mount the current project directory into the VM
sandbox create --name dev \
    --workspace shared:/home/user/my-project

# Combine with a boot command for post-mount setup
sandbox create --name dev \
    --workspace shared:/home/user/my-project \
    --boot-cmd "cd /home/agent/workspace && npm install"
```

API equivalent:

```json
{
  "name": "dev",
  "workspace": "shared:/home/user/my-project"
}
```

### Details

- The host path must be **absolute** and must **exist** at creation
  time.  The CLI and daemon validate this before starting the VM.
- The host directory is mounted at `/home/agent/workspace` inside the
  VM, writable by the guest.
- The mount uses Lima's `9p` mount type, which is built into QEMU and
  compatible with the seccomp sandbox in hardened mode.
- Changes made by the guest are **immediately visible** on the host, and
  vice versa.  There is no synchronization delay.
- `--workspace` is **mutually exclusive** with `--repo`.  Use one or the
  other, not both.

### Security considerations

Shared mount mode adds a 9p filesystem device to the VM.  This **expands
the attack surface** compared to a fully isolated session:

1. **Host filesystem exposure.** The guest has read-write access to the
   mounted host directory.  A malicious or compromised process in the VM
   could modify or delete host files within that directory.

2. **9p device.** The 9p filesystem server runs inside the QEMU process.
   While mature, it represents additional code reachable from the guest.

3. **No network policy bypass.** The shared mount does not affect
   network isolation.  Gateway policies still apply normally.

**Recommendation:** Use shared mounts only for development workflows
where the convenience of instant bidirectional file access outweighs the
reduced isolation.  For production or security-sensitive workloads,
prefer clone mode combined with `sandbox cp` or git remote transport for file
transfer.


## sandbox cp

The `sandbox cp` command copies individual files or directories between
the host and a running VM.  It works like `scp` with a
`session:path` syntax.

### Usage

```bash
# Upload a file to the VM
sandbox cp local/config.toml my-session:/home/agent/config.toml

# Download a file from the VM
sandbox cp my-session:/home/agent/output.log ./output.log
```

### Details

- Files are transferred via the guest agent using base64-encoded
  payloads over the daemon API.
- Large files are chunked automatically.  There is no hard size limit,
  but transfer speed is bounded by the host-guest communication channel.
- The transfer is a point-in-time snapshot: changes after the copy do
  not propagate.
- `sandbox cp` works with any session regardless of workspace mode.
- Maintains **full isolation** because the guest agent mediates all
  access.  The host filesystem is never directly exposed.


## git remote transport

The git remote transport allows standard `git push` and `git pull`
operations against a repository inside a sandbox VM, without requiring
network access.  It uses the `ext::` remote transport built into git.

### Usage

```bash
# Add the sandbox as a git remote
git remote add sandbox \
    "ext::sandbox --socket ~/.sandboxd/sandboxd.sock git-remote %S my-session"

# Push local changes into the VM
git push sandbox main

# Pull changes from the VM
git pull sandbox main
```

### Details

- The `sandbox git-remote` subcommand acts as a git remote helper.  Git
  invokes it via the `ext::` transport, and it relays the git protocol
  stream through the daemon's API to the guest agent.
- The repository path inside the VM defaults to `/root/workspace`.  Use
  `--repo-path` to specify a different path.
- Both `git-upload-pack` (fetch/pull) and `git-receive-pack` (push)
  operations are supported.
- No network policy rules are needed because the communication path is
  entirely host-local (daemon socket to guest agent).
- git remote transport maintains **full VM isolation** while enabling
  incremental code synchronization.


## Boot command

The `--boot-cmd` flag runs an arbitrary shell command inside the VM
after all other provisioning steps (clone, mount) have completed.

### Usage

```bash
# Clone a repo and install dependencies
sandbox create --name dev \
    --repo https://github.com/example/app.git \
    --boot-cmd "cd /root/workspace && npm install"

# Set up a shared workspace after mount
sandbox create --name dev \
    --workspace shared:/home/user/project \
    --boot-cmd "cd /home/agent/workspace && make setup"
```

### Details

- The command runs as `bash -c "<your command>"` via the guest agent.
- It executes after the repository clone (if `--repo` is set) or after
  the VM has booted and mounts are ready (if `--workspace` is set).
- Boot command failure is **non-fatal**: the session enters the Running
  state regardless.  Check the daemon logs or use `sandbox exec` to
  diagnose failures.
- The command runs as the default guest user.  Use `sudo` for operations
  that require root.


## Choosing a mode

| Criterion                  | Clone       | Shared mount | sandbox cp  | git remote transport |
|----------------------------|-------------|--------------|-------------|----------------|
| Initial setup speed        | Slow (clone)| Fast (mount) | N/A         | N/A            |
| Incremental sync           | Manual      | Automatic    | Manual      | Manual         |
| Bidirectional              | No (*)      | Yes          | Yes         | Yes            |
| Requires network policy    | Yes         | No           | No          | No             |
| Preserves full isolation   | Yes         | **No**       | Yes         | Yes            |
| Works offline              | No          | Yes          | Yes         | Yes            |
| IDE integration            | Via cp/git  | Native       | Via cp      | Native (git)   |

(*) Clone is one-shot.  Use git remote transport or `sandbox cp` for
subsequent transfers.

**When to use each mode:**

- **Clone** -- You want a one-time copy of a remote repository and plan
  to use git remote transport or `sandbox cp` for incremental updates.  Best
  for CI/CD pipelines and automated environments.

- **Shared mount** -- You are actively developing and need instant
  bidirectional file visibility.  Best for interactive development with
  an IDE on the host and build tools in the VM.  Accept the reduced
  isolation trade-off.

- **sandbox cp** -- You need to transfer individual files without
  setting up git.  Best for one-off file exchanges (config files, build
  artifacts, logs).

- **git remote transport** -- You want version-controlled incremental sync
  without network access.  Best for workflows where you commit locally,
  push into the VM, build/test, and pull results back.


## Examples

### Interactive development with shared mount

```bash
# Start a sandbox with your project mounted
sandbox create --name dev \
    --workspace shared:$(pwd) \
    --boot-cmd "cd /home/agent/workspace && npm install"

# Edit files on your host with your IDE -- changes appear instantly in the VM
# Run tests inside the VM
sandbox exec dev -- bash -c "cd /home/agent/workspace && npm test"

# Clean up
sandbox rm dev
```

### CI pipeline with clone mode

```bash
# Create a sandbox with the repo cloned
sandbox create --name ci-run \
    --policy ci-policy.json \
    --repo https://github.com/myorg/app.git \
    --boot-cmd "cd /root/workspace && make build && make test"

# Check the results
sandbox exec ci-run -- cat /root/workspace/test-results.xml

# Download the artifact
sandbox cp ci-run:/root/workspace/dist/app.tar.gz ./app.tar.gz

# Tear down
sandbox rm ci-run
```

### Push local changes via git remote transport

```bash
# Create a bare sandbox and copy seed files
sandbox create --name review
sandbox cp ./my-patch.diff review:/root/workspace/patch.diff

# Or use git remote transport for full repo sync
git remote add review \
    "ext::sandbox git-remote %S review"
git push review main

# Apply and test in the sandbox
sandbox exec review -- bash -c \
    "cd /root/workspace && git apply patch.diff && make test"

# Pull results back
git pull review main

# Clean up
sandbox rm review
```
