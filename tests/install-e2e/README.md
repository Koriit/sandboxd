# `install-e2e` — install.sh / `sandbox update` E2E suite

Pytest suite that boots a fresh Lima VM per test, runs `install.sh` or `sandbox update` end-to-end against it, and asserts the produced on-disk state matches the design. Each test owns a dedicated VM; there is no shared install state between tests.

The harness lives in `conftest.py`; the per-feature suites are `test_install_*.py` (install.sh paths) and `test_update_*.py` (`sandbox update` paths). See `make test-e2e-container` and `make test-e2e-matrix` for the canonical entry points.

## Landmine for test authors: the `sandbox` user's shell is `nologin`

Production installs of sandboxd create a system user whose login shell is `/usr/sbin/nologin`. The audit boundary is intentional — the daemon's runtime user should never be coaxed into running an interactive shell — but the same property is a landmine for tests that need to perform privileged file work on behalf of the `sandbox` user.

`sudo -u sandbox <direct-binary>` works fine. Direct binaries (`jq`, `tee`, `cat`, `env`, `install`, `ls`) are `execvp`'d by `sudo` without invoking a shell, so the user's shell field never comes into play:

```bash
# All fine: each is a direct execvp by sudo, no shell involved.
sudo -u sandbox jq -r .version /var/lib/sandbox/.install-state.json
sudo -u sandbox tee /tmp/out.txt < /tmp/in.txt
sudo -u sandbox install -m 0600 src dst
```

Shell-invoking forms fail with `This account is currently not available`:

```bash
# All fail: each form invokes the user's shell, which is /usr/sbin/nologin.
sudo -u sandbox flock -c '...'      # flock -c spawns sh -c
sudo -u sandbox sh -c '...'         # explicit sh
sudo -u sandbox bash -c '...'       # explicit bash
```

The fix is one of:

- **Refactor to a direct invocation** when possible (`flock -c "cmd"` → call `flock` against an FD without `-c`, then run the command directly).
- **Wrap the shell invocation in a sudo'd inline script** when a shell really is needed. Write the script to a temp file as root, then `sudo -u sandbox /path/to/script`. The script's shebang line takes precedence over the user's shell field, so a `#!/bin/sh` script runs even though `getent passwd sandbox` reports `/usr/sbin/nologin`.
- **Use `runuser -u sandbox <cmd>`** (root only). `runuser` does not honor the user's shell field by default; it execs the supplied command directly. The same caveat about `sh -c` applies if you pass `--shell` or use `runuser -l`.

The same shape applies to the `docs/guides/rollback.md` recipe's `sudo -u sandbox sh -c '...'` invocations — those are operator-facing and rely on the recipe being copy-pasted by an operator with a working interactive shell, not by a test harness from a `nologin`-shelled context. When porting any of those snippets into a test, replace the `sh -c` wrapper.

## Running individual tests

```bash
cd tests/install-e2e
source .venv/bin/activate
python -m pytest test_lib_sh_drift.py -v
python -m pytest test_update_idempotency.py::test_update_interrupted_then_resumed -v
```

The Lima VM boots take 3–10 minutes per test. Run one test first to verify your local Lima/QEMU setup before invoking the full suite.

## Related

- `make test-e2e-container` — PR-time E2E (~5–10 min).
- `make test-e2e-matrix` — full matrix (~30–45 min).
- `conftest.py` — fixture helpers (`release_tarball_x86_64`, `parse_install_log_actions`, `assert_doctor_passes`, …).
