# Parallel E2E testing (pytest-xdist)

`make test-e2e PARALLEL=N` runs the E2E suite with `N` `pytest-xdist`
workers.  Each worker is a separate Python process that spawns its own
`sandboxd` daemon and its own temporary base-dir.  Some host state is
shared across workers, so the test harness coordinates via filesystem
locks.

## Shared host state and coordination

### Golden base image (`~/.lima/sandbox-base`)

The Lima "golden" base VM lives at a single host path.  Every worker's
`_ensure_base_image` fixture would otherwise shell out to `sandbox
rebuild-image` at session start, racing on the same VM.

The fix, implemented in `tests/e2e/conftest.py`:

* `_ensure_base_image` takes an exclusive `filelock.FileLock` on
  `~/.lima/sandbox-base.rebuild.lock` (fallback `/tmp/...` if `~/.lima`
  doesn't exist yet).  The first worker to acquire the lock rebuilds
  the image; subsequent workers query the daemon's
  `GET /base-image-status` endpoint and skip the rebuild if it's
  already `fresh`.
* Every test runs under an autouse rwlock via `fcntl.flock` on the
  same file:
  * `test_rebuild_image_from_scratch` (from
    `test_m85_golden_image.py`) takes `LOCK_EX` -- no clone can run
    while this destructive test deletes and rebuilds the base VM.
  * All other tests take `LOCK_SH` -- many workers can clone the
    base VM in parallel, but `LOCK_EX` waits for all of them to
    finish.

### Preflight cleanup of stale `sandbox-*` VMs and Docker resources

`_preflight_checks` (autouse session-scoped) deletes any leftover
`sandbox-*` Lima VMs, Docker containers, and networks before tests
begin.  Under xdist, we run this cleanup **only on worker `gw0`** (or
on `master` when running serially).  Non-primary workers acquire the
same exclusive rebuild-lock so they wait until `gw0` finishes cleanup
before starting session setup.

Without this coordination, a slow worker's preflight would delete VMs
that faster workers already started creating.

## Audit: Docker subnet pool contention

**Audit result: no contention at `PARALLEL=4`.**

`sandbox-core::network::NetworkManager` allocates each session a `/28`
out of an explicit base range (default `10.209.0.0/24`, 16 blocks).
This is a private, fixed range -- it does not use Docker's default
address pool (typically `172.17.0.0/16` for the default bridge).

Each daemon has its own in-memory allocator starting at block 0, so
two daemons in different worker processes will both try to allocate
`10.209.0.0/28` first.  Docker's `network create` is serialized
internally; the losing daemon gets a `"Pool overlaps"` error and
`NetworkManager::create_network` retries with the next block (it
keeps the failed block marked allocated so `allocate()` moves on).

With 16 blocks and at most N concurrent sessions across N workers
(tests create sessions sequentially within a test file), contention
is well below capacity.  No fix required.

If the pool is ever exhausted (N > 16 active sessions, or sessions
leak without cleanup), a daemon-side `--subnet-base` CLI flag plus
Docker's `default-address-pools` config would be the mitigation.

## Audit: concurrent nftables injection

**Audit result: no contention -- nftables state is per-container.**

The gateway is one Docker container per session
(`sandbox-gw-{session_id}`).  Each container has its own network
namespace, so `docker exec -i <container> nft -f -` writes rules
into that container's private nftables state.  There are no shared
chains between sessions: `table inet sandbox` and `table inet
sandbox_dnat` live separately inside each container's netns.

Consequence: two workers injecting rules simultaneously into different
sessions cannot clobber each other's rules.  No fix required.

## Workload distribution

The `Makefile` passes `--dist=loadfile` to pytest-xdist.  All tests
in one file run on a single worker.  This is important because test
files share file-scoped state (e.g.  `test_m85_golden_image.py`'s
destructive tests mutate the base VM in an order-dependent way).
The rwlock handles cross-file coordination; `loadfile` handles
intra-file ordering.

## Running

```bash
make test-e2e PARALLEL=2     # 2 workers
make test-e2e PARALLEL=4     # 4 workers
make test-e2e                # serial (PARALLEL=1)
```

Use `PARALLEL=N` up to the number of physical CPU cores.  Each worker
boots a real Lima/QEMU VM for many tests, so memory is the usual
bottleneck (each VM defaults to 2 GB).
