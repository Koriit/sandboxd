.PHONY: build fmt fmt-check test test-integration test-e2e test-e2e-container test-e2e-matrix test-install-e2e test-install-e2e-quick gateway-image lite-image docs-dev docs-build clean \
	setup-dev-env install-route-helper-prod-cap install-route-helper-test-cap install-lima-helper-prod-cap install-lima-helper-test-cap setup-bridge-conf setup-users-conf setup-bridge-helper-setuid \
	setup-sandbox-user setup-operator-group-membership setup-test-sudoers-fragment setup-sandboxd-state-dir setup-sandbox-prod-base-dir setup-e2e-test-operator

# Green/reset for ✓ confirmation lines. TTY-aware: empty when stdout
# is piped/redirected, so non-TTY consumers (CI logs, `less` without
# -R, file capture) don't see escape garbage.
ifneq ($(shell test -t 1 && echo tty),)
GREEN := $(shell tput setaf 2 2>/dev/null)
RESET := $(shell tput sgr0 2>/dev/null)
else
GREEN :=
RESET :=
endif

build: fmt-check
	# FORCE_COLOR (set in this env) forces ANSI color even into redirected files.
	# Detect interactive: stdout is a TTY and CI/NO_COLOR are unset → keep color;
	# otherwise emit plain text so captured logs and CI output stay greppable.
	@if [ -t 1 ] && [ -z "$${CI:-}" ] && [ -z "$${NO_COLOR:-}" ]; then \
	  cd sandboxd && cargo build --workspace; \
	else \
	  cd sandboxd && CARGO_TERM_COLOR=never cargo build --workspace; \
	fi

fmt:
	cd sandboxd && cargo fmt --all

fmt-check:
	cd sandboxd && cargo fmt --all -- --check

# Hermetic unit tests: in-process, no Docker / Lima / nftables. The
# default nextest profile (`sandboxd/.config/nextest.toml`) filters out
# every test named `integration_*`, so this target stays fast and
# deterministic even as the workspace grows more integration tests.
test:
	# FORCE_COLOR (set in this env) forces ANSI color even into redirected files.
	# Detect interactive: stdout is a TTY and CI/NO_COLOR are unset → keep color;
	# otherwise emit plain text so captured logs stay greppable.
	@# Build with the same `test-env-override` features as `test-integration`
	@# so both targets compile the identical test universe and differ only in
	@# which nextest profile selects. Without this, `#[cfg(feature =
	@# "test-env-override")]` unit tests (e.g. the *_honors_env_* path-resolution
	@# tests) compile only under test-integration's features but are then skipped
	@# by its `integration_*`-only profile — so they would run in neither target.
	@# These are hermetic unit tests (env-var seam resolution); no Docker/Lima.
	@if [ -t 1 ] && [ -z "$${CI:-}" ] && [ -z "$${NO_COLOR:-}" ]; then \
	  cd sandboxd && cargo nextest run --workspace --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override; \
	else \
	  cd sandboxd && CARGO_TERM_COLOR=never cargo nextest run --workspace --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override; \
	fi

# Integration tests: every test named `integration_*` in the workspace.
# These require out-of-process state — a real `sandbox-gateway`
# container, the external validator CLIs (`nft -c` / `envoy --mode
# validate`) that ship inside it, etc. The `integration` nextest profile
# (`sandboxd/.config/nextest.toml`) selects them via the name prefix; the
# default profile filters them out. No `#[ignore]`, no env gate —
# membership is self-describing at the call site via the prefix.
#
# For finer selection while iterating, layer an `-E` filter on top of
# the profile, e.g. `cargo nextest run --profile integration -E \
# 'test(integration_gateway_lifecycle)'`.
#
# `--features sandbox-route-helper/test-env-override` lets the tests
# redirect users.conf via `SANDBOX_USERS_CONF` (default builds ignore
# it — see the privilege-boundary rationale on
# `install-route-helper-test-cap`). Flag must match the install step
# or the test's checksum check rejects the on-disk cap'd binary as
# stale.
test-integration: gateway-image lite-image install-route-helper-test-cap install-lima-helper-test-cap
	# FORCE_COLOR (set in this env) forces ANSI color even into redirected files.
	# Detect interactive: stdout is a TTY and CI/NO_COLOR are unset → keep color;
	# otherwise emit plain text so captured logs stay greppable.
	@if [ -t 1 ] && [ -z "$${CI:-}" ] && [ -z "$${NO_COLOR:-}" ]; then \
	  cd sandboxd && \
	    cargo build --workspace --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override && \
	    cargo nextest run --workspace --profile integration --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override; \
	else \
	  cd sandboxd && \
	    CARGO_TERM_COLOR=never cargo build --workspace --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override && \
	    CARGO_TERM_COLOR=never cargo nextest run --workspace --profile integration --features sandbox-route-helper/test-env-override,sandbox-lima-helper/test-env-override; \
	fi

# The stamp filename embeds the host's Python minor version (e.g.
# `.installed.python3.12`) so a host interpreter upgrade — say
# 3.12 → 3.13 — invalidates the marker and forces a venv rebuild.
# Without the embedded version, the existing `.venv` becomes
# ABI-incompatible with the new interpreter while the stamp remains
# fresh, and `make test-e2e` crashes with `No module named pytest`.
PY_VERSION := $(shell python3 -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')
VENV_STAMP := tests/e2e/.venv/.installed.$(PY_VERSION)

$(VENV_STAMP): tests/e2e/pyproject.toml
	rm -rf tests/e2e/.venv
	python3 -m venv tests/e2e/.venv
	tests/e2e/.venv/bin/python -c \
		"import tomllib, subprocess, sys; \
		deps = tomllib.load(open('tests/e2e/pyproject.toml', 'rb'))['project']['dependencies']; \
		subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + deps)"
	touch $(VENV_STAMP)

TEST ?=
# CI policy:
#
#   | Trigger           | Scope                           | Wall clock |
#   | ----------------- | ------------------------------- | ---------- |
#   | PR                | Full E2E against container only | ~5-10 min  |
#   | Merge to main     | Full E2E matrix (both backends) | ~30-45 min |
#   | Nightly           | Matrix + perf benchmarks        | longer     |
#
# `test-e2e-container` runs the PR-time scope. `test-e2e-matrix` runs
# the merge-to-main scope. `test-e2e` is kept as a back-compat alias
# for `test-e2e-matrix` so existing developer muscle-memory does not
# break.
#
# All three targets depend on `gateway-image` so the container running
# mitmproxy / Envoy / CoreDNS always reflects the current `networking/`
# sources -- forgetting to rebuild baked stale addon code into the
# image and produced silent semantic drift between sandboxd (Rust) and
# the enforcement layer. The container-scoped targets additionally
# depend on `lite-image` so the lite-mode container image (consumed by
# the parametrized `[container]` runs and the `tests/e2e/test_lite.py`
# suite) is up to date before the suite runs.

# PR-time: container backend only. The selector is fixture-symmetric
# with the e2e marker convention (see `tests/e2e/conftest.py` →
# "Backend parametrization"):
#
#   * `-m "not lima"` excludes Lima-only tests (whole-file or per-test
#     `@pytest.mark.lima`).
#   * `-k "not [lima]"` filters out the `[lima]` parametrization of
#     cross-backend tests (which take the `backend` fixture).
#
# What remains is exactly the `[container]` half of cross-backend
# tests and the container-only `test_lite.py` (`@pytest.mark.
# container`). Zero convention-driven skips on a properly-configured
# host; runs in ~5-10 min on a warm runner.
#
# The daemon socket is mode 0660 group=sandbox. A developer added via
# `usermod -aG sandbox` but not yet re-logged-in does not have the
# group active in their shell. Wrapping pytest in `sg sandbox`
# activates the group for the subprocess without requiring a re-login.
test-e2e-container: $(VENV_STAMP) gateway-image lite-image install-route-helper-prod-cap install-lima-helper-test-cap
	cd tests/e2e && \
	  if [ -t 1 ] && [ -z "$${CI:-}" ] && [ -z "$${NO_COLOR:-}" ]; then _color=yes; else _color=no; fi; \
	  _pytest=". .venv/bin/activate && python -m pytest -v -rs --timeout=600 --durations=20 --color=$$_color -m \"not lima\" -k \"not [lima]\" $(TEST)"; \
	  echo "[make] wrapping pytest in 'sg sandbox' (daemon socket is group=sandbox)"; \
	  sg sandbox -c "$$_pytest"

# Merge-to-main: full matrix -- Lima + container parametrizations plus
# the Lima-only and container-only test files. Wall clock ~30-45 min.
# Single-backend tests (`@pytest.mark.lima` / `@pytest.mark.
# container`) run once on their applicable backend; cross-backend
# tests run twice. Lima-marked tests on a host without limactl /
# qemu-bridge-helper / bridge.conf emit per-test skips via the
# `_lima_required_for_lima_tests` fixture; everything else runs.
#
# The daemon socket is mode 0660 group=sandbox. A developer added via
# `usermod -aG sandbox` but not yet re-logged-in does not have the
# group active in their shell. Wrapping pytest in `sg sandbox`
# activates the group for the subprocess without requiring a re-login.
test-e2e-matrix: $(VENV_STAMP) gateway-image lite-image install-route-helper-prod-cap install-lima-helper-test-cap
	cd tests/e2e && \
	  if [ -t 1 ] && [ -z "$${CI:-}" ] && [ -z "$${NO_COLOR:-}" ]; then _color=yes; else _color=no; fi; \
	  _pytest=". .venv/bin/activate && python -m pytest -v -rs --timeout=600 --durations=20 --color=$$_color $(TEST)"; \
	  echo "[make] wrapping pytest in 'sg sandbox' (daemon socket is group=sandbox)"; \
	  sg sandbox -c "$$_pytest"

# Back-compat alias. `make test-e2e` continues to run the full matrix.
test-e2e: test-e2e-matrix

# Install-E2E suite — boots Lima VMs and exercises install.sh /
# uninstall.sh / update.sh end-to-end against a freshly-built local
# tarball (which the `local_tarball` fixture builds via
# `tests/install-e2e/build-local-tarball.sh`; the script invokes
# `make gateway-image` itself when needed, so we deliberately do NOT
# declare it as a Make prereq here). The route helper is installed
# *inside* the Lima VM by `install.sh`, not on the host, so neither
# `install-route-helper-prod-cap` nor `install-route-helper-test-cap`
# is required.
#
# Mirrors the e2e venv-stamp pattern: the stamp name embeds the host
# Python minor version so a 3.12 → 3.13 host upgrade invalidates the
# marker and forces a venv rebuild against the new interpreter.
INSTALL_E2E_VENV_STAMP := tests/install-e2e/.venv/.installed.$(PY_VERSION)

$(INSTALL_E2E_VENV_STAMP): tests/install-e2e/pyproject.toml
	rm -rf tests/install-e2e/.venv
	python3 -m venv tests/install-e2e/.venv
	tests/install-e2e/.venv/bin/python -c \
		"import tomllib, subprocess, sys; \
		deps = tomllib.load(open('tests/install-e2e/pyproject.toml', 'rb'))['project']['dependencies']; \
		subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + deps)"
	touch $(INSTALL_E2E_VENV_STAMP)

# Full install-e2e suite. Wall clock ~2h on a warm runner (each test
# boots its own Lima VM). Use `TEST=` to narrow selection while
# iterating, e.g.
#   make test-install-e2e TEST="test_install_happy_path.py -k ubuntu-22.04"
test-install-e2e: $(INSTALL_E2E_VENV_STAMP)
	cd tests/install-e2e && . .venv/bin/activate && \
	  python -m pytest -v -rs --durations=20 --timeout=600 $(TEST)

# Single happy-path smoke for fast confidence in the install path
# (~5-7 min wall clock — one Lima VM, ubuntu-22.04 only). Threads
# `TEST=` at the end so callers can layer extra flags, e.g.
#   make test-install-e2e-quick TEST=--collect-only
test-install-e2e-quick: $(INSTALL_E2E_VENV_STAMP)
	cd tests/install-e2e && . .venv/bin/activate && \
	  python -m pytest -v -rs --durations=20 --timeout=600 \
	  test_install_happy_path.py::test_install_fresh_then_doctor_passes \
	  -k "ubuntu-22.04" $(TEST)

# Always run `docker build`; Docker's layer cache handles the no-op case
# cheaply (a few seconds for context upload when nothing has changed).
# The previous stamp-file indirection attempted to skip the build when its
# tracked inputs hadn't changed, but the input list would silently drift
# from reality and the stale image would get used by integration / E2E
# tests — see the gateway_integration flakiness that was actually stale-image
# failures hitting the component-ready timeout.
#
# Build context is the repository root so the Rust deny-logger build stage
# can `COPY sandboxd/` into its builder. `.dockerignore` at the repo root
# keeps `sandboxd/target/` and other heavy directories out of the context
# upload.
# The gateway image is tagged with the workspace's `sandbox-core`
# package version so the daemon's `CARGO_PKG_VERSION` (used at runtime
# to compose `sandbox-gateway:<version>`) and the image actually built
# here agree byte-for-byte. The daemon refuses to compose
# `sandbox-gateway:latest`; pinning here is what makes
# `make gateway-image && sandbox session create` work end-to-end.
GATEWAY_VERSION := $(shell awk -F'"' '/^version/ { print $$2; exit }' sandboxd/sandbox-core/Cargo.toml)

gateway-image:
	docker build -t sandbox-gateway:$(GATEWAY_VERSION) -f networking/gateway/Dockerfile .

# Build the lite-mode container image as `sandboxd-lite:<workspace-version>`,
# matching the `<repository>:<daemon-version>` tag scheme that
# `ContainerRuntime::ensure_image` (sandbox-core/src/backend/container.rs)
# uses at run-time. Useful for local iteration and for warming the daemon
# version's image before the first `--lite` create.
#
# This target intentionally mirrors the daemon's runtime build path: a
# host `cargo build`, then `docker build` from a small staging dir
# containing the Dockerfile and the prebuilt `sandbox-guest` binary.
# The daemon does the same at runtime on user machines that do not
# have the Rust workspace source — see the comment at the top of
# `sandboxd/images/lite/Dockerfile`. Aligning `make lite-image` with
# the runtime build keeps the dev image and the user-built image
# byte-identical (modulo the sandbox-guest binary itself), so dev
# testing reflects what users actually run. The image is tagged with
# the `sandbox-core` package version because the daemon's
# `CARGO_PKG_VERSION` (used at run-time) is sourced from the same
# package.
LITE_VERSION := $(shell awk -F'"' '/^version/ { print $$2; exit }' sandboxd/sandbox-core/Cargo.toml)

lite-image:
	cd sandboxd && cargo build --release --workspace
	mkdir -p sandboxd/images/lite/.context
	cp sandboxd/target/release/sandbox-guest sandboxd/images/lite/.context/sandbox-guest
	cp sandboxd/images/lite/Dockerfile sandboxd/images/lite/.context/Dockerfile
	docker build -t sandboxd-lite:$(LITE_VERSION) sandboxd/images/lite/.context
	rm -rf sandboxd/images/lite/.context

docs-dev:
	cd site && npm install && npm run dev

docs-build:
	cd site && npm ci && npm run build

clean:
	cd sandboxd && cargo clean
	rm -rf tests/e2e/.venv/
	rm -rf site/node_modules site/dist
	sudo -k rm -f "$(ROUTE_HELPER_TEST_PATH)"
	sudo -k rm -f "$(LIMA_HELPER_TEST_PATH)"
	sudo -k rmdir --ignore-fail-on-non-empty /usr/local/libexec/sandboxd-test 2>/dev/null || true
	@echo "[clean] removing e2e test operator '$(E2E_TEST_OPERATOR_NAME)' and its sudoers fragment (if present)"
	sudo -k userdel $(E2E_TEST_OPERATOR_NAME) 2>/dev/null || true
	sudo -k rm -f "$(E2E_TEST_OPERATOR_SUDOERS)"

# ---------------------------------------------------------------------------
# Dev-environment setup
# ---------------------------------------------------------------------------
#
# `make setup-dev-env` is the one-shot operator entry point: it runs
# every per-host install/configure step the project needs in order for
# `make test-integration` and `make test-e2e` to pass on a freshly
# checked-out workspace. Each sub-target is independently runnable
# and idempotent — re-running `make setup-dev-env` should print a row
# of `✓ already configured` lines and invoke no `sudo` on the second
# pass (the principle is "if a step is a no-op, do not even prompt
# for a password").
#
# Each step that mutates host state prints `[sudo] <exact change>`
# BEFORE invoking sudo, so the operator sees the file path / mode /
# content that is about to change before authenticating. Operators
# who want to dry-run can read the line and bail.
#
# Stamp directory under `sandboxd/target/.dev-env-stamps/` keeps the
# stamp files out of the workspace tree but tied to the cargo build
# output's lifetime — `make clean` wipes them, forcing the next setup
# to re-verify.

ROUTE_HELPER_PROD_PATH      := /usr/local/libexec/sandboxd/sandbox-route-helper
ROUTE_HELPER_TEST_PATH      := /usr/local/libexec/sandboxd-test/sandbox-route-helper
LIMA_HELPER_PROD_PATH       := /usr/local/libexec/sandboxd/sandbox-lima-helper
LIMA_HELPER_TEST_PATH       := /usr/local/libexec/sandboxd-test/sandbox-lima-helper
USERS_CONF_PATH             := /etc/sandboxd/users.conf
BRIDGE_CONF_PATH            := /etc/qemu/bridge.conf
QEMU_BRIDGE_HELPER_PATH     := /usr/lib/qemu/qemu-bridge-helper

# Path of the sudoers fragment authorising the operator to run the
# fallback `sudo -u sandbox` daemon launch without a password prompt.
# `setup-test-sudoers-fragment` writes this file; the e2e harness
# reads it back via the `SANDBOXD_TEST_SUDOERS_FRAGMENT` env-var name
# (no consumers need the raw path beyond visudo validation here, so
# keeping it as a Makefile-local constant is enough).
TEST_SUDOERS_FRAGMENT_PATH  := /etc/sudoers.d/sandboxd-test

# Constants for the persistent cross-user e2e test operator account.
# uid 4099: distinct from the daemon (999) and the typical dev (1000),
# in the install-e2e test-uid range, and unlikely to collide on a fresh
# dev host.
E2E_TEST_OPERATOR_NAME        := sandbox-e2e-test
E2E_TEST_OPERATOR_UID         := 4099
E2E_TEST_OPERATOR_SUDOERS     := /etc/sudoers.d/sandboxd-e2e-test-operator

setup-dev-env: install-route-helper-prod-cap install-route-helper-test-cap install-lima-helper-prod-cap install-lima-helper-test-cap setup-bridge-conf setup-users-conf setup-bridge-helper-setuid setup-sandbox-user setup-operator-group-membership setup-test-sudoers-fragment setup-sandboxd-state-dir setup-sandbox-prod-base-dir setup-e2e-test-operator
	@echo "$(GREEN)✓ make setup-dev-env complete$(RESET)"

# setup-sandboxd-state-dir — create /var/lib/sandboxd/ owned by sandbox:sandbox
# mode 0750.  This is the root of per-operator Lima state trees
# (/var/lib/sandboxd/<op_uid>/lima/); per-operator subdirs are created at
# first session-create time by the daemon via ensure_operator_lima_home().
#
# Idempotence:
#   - Directory present with correct ownership and mode → ✓ already configured.
#   - Directory present but wrong ownership/mode → correct in place.
#   - Directory absent → create it.
#
# The `acl` package must be installed on the host (provides setfacl/getfacl).
# The daemon uses setfacl to apply per-operator ACLs at session-create time.
setup-sandboxd-state-dir:
	@if ! getent passwd sandbox >/dev/null 2>&1; then \
	  echo "ERROR: system user 'sandbox' does not exist; run 'make setup-sandbox-user' first"; \
	  exit 1; \
	fi
	@if [ ! -d /var/lib/sandboxd ]; then \
	  echo "[sudo] mkdir -p /var/lib/sandboxd"; \
	  sudo -k mkdir -p /var/lib/sandboxd; \
	  echo "[sudo] chown sandbox:sandbox /var/lib/sandboxd"; \
	  sudo -k chown sandbox:sandbox /var/lib/sandboxd; \
	  echo "[sudo] chmod 0750 /var/lib/sandboxd"; \
	  sudo -k chmod 0750 /var/lib/sandboxd; \
	else \
	  owner=$$(stat -c '%U:%G' /var/lib/sandboxd 2>/dev/null || echo "?:?"); \
	  mode=$$(stat -c '%a' /var/lib/sandboxd 2>/dev/null || echo "?"); \
	  if [ "$$owner" = "sandbox:sandbox" ] && [ "$$mode" = "750" ]; then \
	    echo "$(GREEN)✓ already configured: /var/lib/sandboxd (sandbox:sandbox 0750)$(RESET)"; \
	  else \
	    echo "[sudo] chown sandbox:sandbox /var/lib/sandboxd (was: $$owner $$mode)"; \
	    sudo -k chown sandbox:sandbox /var/lib/sandboxd; \
	    echo "[sudo] chmod 0750 /var/lib/sandboxd"; \
	    sudo -k chmod 0750 /var/lib/sandboxd; \
	  fi; \
	fi
	@if ! command -v setfacl >/dev/null 2>&1; then \
	  echo "WARNING: setfacl not found — install the 'acl' package (apt install acl / dnf install acl)."; \
	  echo "         The daemon uses setfacl to provision per-operator LIMA_HOME ACLs at session-create time."; \
	fi

# setup-sandbox-prod-base-dir — create /var/lib/sandbox owned by sandbox:sandbox
# mode 0750. This is the daemon's base directory and home directory
# (see useradd --home-dir /var/lib/sandbox). The daemon writes all state here,
# including the unix socket (/var/lib/sandbox/sandboxd.sock); running as the
# sandbox user it needs no root to create or bind the socket. The 0750 mode
# (group=sandbox, r-x) lets any operator in the sandbox group connect.
#
# Idempotence:
#   - Directory present with correct ownership and mode → ✓ already configured.
#   - Directory present but wrong ownership/mode → correct in place.
#   - Directory absent → create it.
#
# Ordering: must run after setup-sandbox-user (the sandbox user/group must exist).
setup-sandbox-prod-base-dir: setup-sandbox-user
	@if ! getent passwd sandbox >/dev/null 2>&1; then \
	  echo "ERROR: system user 'sandbox' does not exist; run 'make setup-sandbox-user' first"; \
	  exit 1; \
	fi
	@if [ ! -d /var/lib/sandbox ]; then \
	  echo "[sudo] mkdir -p /var/lib/sandbox"; \
	  sudo -k mkdir -p /var/lib/sandbox; \
	  echo "[sudo] chown sandbox:sandbox /var/lib/sandbox"; \
	  sudo -k chown sandbox:sandbox /var/lib/sandbox; \
	  echo "[sudo] chmod 0750 /var/lib/sandbox"; \
	  sudo -k chmod 0750 /var/lib/sandbox; \
	else \
	  owner=$$(stat -c '%U:%G' /var/lib/sandbox 2>/dev/null || echo "?:?"); \
	  mode=$$(stat -c '%a' /var/lib/sandbox 2>/dev/null || echo "?"); \
	  if [ "$$owner" = "sandbox:sandbox" ] && [ "$$mode" = "750" ]; then \
	    echo "$(GREEN)✓ already configured: /var/lib/sandbox (sandbox:sandbox 0750)$(RESET)"; \
	  else \
	    echo "[sudo] chown sandbox:sandbox /var/lib/sandbox (was: $$owner $$mode)"; \
	    sudo -k chown sandbox:sandbox /var/lib/sandbox; \
	    echo "[sudo] chmod 0750 /var/lib/sandbox"; \
	    sudo -k chmod 0750 /var/lib/sandbox; \
	  fi; \
	fi

# setup-sandbox-user — create the `sandbox` system user and group
# that the e2e harness drops the daemon to. Mirrors the production
# `install.sh` Step 12 behaviour (system user, no-create-home,
# no-login shell, `/var/lib/sandbox` as $HOME). Adds the user to the
# `docker` and `kvm` groups when they exist so the daemon can reach
# `/dev/kvm` and the Docker socket without root.
#
# Idempotence:
#
#   - User present  → print `✓ already configured` and invoke no sudo.
#   - User missing  → emit a `[sudo]` announce line first, then
#                     `sudo useradd`. Group adds via `usermod -aG`
#                     are themselves idempotent (already-member is a
#                     no-op exit 0).
#
# Group-only pre-existing state (group `sandbox` exists but the
# matching user does not, as can happen on hosts whose group was
# created by an earlier partial setup) is detected separately and
# left untouched — `useradd --user-group` would refuse to create a
# group that already exists, so we pass the existing group through
# `--gid sandbox` when only the group is present.
setup-sandbox-user:
	@if getent passwd sandbox >/dev/null 2>&1; then \
	  echo "$(GREEN)✓ already configured: system user 'sandbox' exists$(RESET)"; \
	else \
	  if getent group sandbox >/dev/null 2>&1; then \
	    echo "[sudo] useradd --system --gid sandbox --no-create-home --home-dir /var/lib/sandbox --shell /usr/sbin/nologin sandbox  (group already exists; binding user to it)"; \
	    sudo -k useradd \
	        --system \
	        --gid sandbox \
	        --no-create-home \
	        --home-dir /var/lib/sandbox \
	        --shell /usr/sbin/nologin \
	        --comment "sandboxd - isolated environment broker" \
	        sandbox; \
	  else \
	    echo "[sudo] useradd --system --user-group --no-create-home --home-dir /var/lib/sandbox --shell /usr/sbin/nologin sandbox"; \
	    sudo -k useradd \
	        --system \
	        --user-group \
	        --no-create-home \
	        --home-dir /var/lib/sandbox \
	        --shell /usr/sbin/nologin \
	        --comment "sandboxd - isolated environment broker" \
	        sandbox; \
	  fi; \
	fi
	@if getent group docker >/dev/null 2>&1; then \
	  if id -nG sandbox 2>/dev/null | tr ' ' '\n' | grep -qx docker; then \
	    echo "$(GREEN)✓ already configured: user 'sandbox' is in group 'docker'$(RESET)"; \
	  else \
	    echo "[sudo] usermod -aG docker sandbox"; \
	    sudo -k usermod -aG docker sandbox; \
	  fi; \
	fi
	@if getent group kvm >/dev/null 2>&1; then \
	  if id -nG sandbox 2>/dev/null | tr ' ' '\n' | grep -qx kvm; then \
	    echo "$(GREEN)✓ already configured: user 'sandbox' is in group 'kvm'$(RESET)"; \
	  else \
	    echo "[sudo] usermod -aG kvm sandbox"; \
	    sudo -k usermod -aG kvm sandbox; \
	  fi; \
	fi

# setup-operator-group-membership — add the invoking operator
# ($USER) to the `sandbox` group so the operator's CLI can read/write
# the daemon socket at `/run/sandbox/sandboxd.sock` (mode 0660,
# group=sandbox). Idempotent: an already-member operator is a no-op.
#
# Implementation note: group changes do **not** take effect in the
# current login session. The operator must log out + back in, or run
# subsequent commands inside `sg sandbox -c '...'`, before the new
# group is visible. The e2e harness asserts group membership at
# start-up (see `tests/e2e/conftest.py`) and fails loudly with the
# remediation instructions if the test process is not in the group.
setup-operator-group-membership:
	@if [ -z "$$USER" ] || [ "$$USER" = "root" ]; then \
	  echo "$(GREEN)✓ already configured: operator-group-add skipped (no non-root $$USER set)$(RESET)"; \
	elif id -nG "$$USER" 2>/dev/null | tr ' ' '\n' | grep -qx sandbox; then \
	  echo "$(GREEN)✓ already configured: operator '$$USER' is in group 'sandbox'$(RESET)"; \
	else \
	  echo "[sudo] usermod -aG sandbox $$USER  (operator-group membership; new group visible after re-login or via 'sg sandbox -c …')"; \
	  sudo -k usermod -aG sandbox "$$USER"; \
	  echo "$(GREEN)✓ added '$$USER' to group 'sandbox' — re-login (or 'sg sandbox -c …') required for the change to take effect in the current shell$(RESET)"; \
	fi

# setup-test-sudoers-fragment — install a NOPASSWD sudoers fragment
# that grants the invoking operator ($USER) blanket passwordless
# impersonation of the unprivileged `sandbox` system user. The e2e
# harness launches the daemon and runs state-reset commands exclusively
# as the `sandbox` user via `sudo -u sandbox`; runtime sudo is never
# root. The `sandbox` user is an unprivileged system user (nologin, no
# sudo of its own, no capabilities), so this grant is not privilege
# escalation — test/dev hosts only.
#
# The fragment is validated via `visudo -c -f` on a tempfile before
# being installed at the canonical path, so a malformed fragment never
# lands in `/etc/sudoers.d/` (a broken fragment there can disable sudo
# system-wide).
#
# Idempotence: if the canonical path already contains the exact text
# we would write, print `✓ already configured` and invoke no sudo.
setup-test-sudoers-fragment:
	@if [ -z "$$USER" ] || [ "$$USER" = "root" ]; then \
	  echo "$(GREEN)✓ already configured: sudoers fragment skipped (no non-root $$USER set)$(RESET)"; \
	else \
	  fragment_envkeep="Defaults:$$USER env_keep += \"SANDBOX_USERS_CONF SANDBOX_BASE_VM_NAME SANDBOX_SOCKET SANDBOX_LIMA_HELPER_PATH SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH\""; \
	  fragment="$$USER ALL=(sandbox) NOPASSWD: ALL"; \
	  tmp=$$(mktemp); \
	  printf '# Managed by `make setup-test-sudoers-fragment` — do not edit.\n# Grants the operator passwordless impersonation of the unprivileged\n# `sandbox` system user for the e2e harness. Runtime sudo is\n# exclusively `sudo -u sandbox` (never root). The `sandbox` user is\n# an unprivileged system user (nologin, no sudo of its own, no caps);\n# test/dev hosts only.\n#\n# The env_keep directive propagates test-harness variables through\n# sudo (which strips the environment by default).\n%s\n%s\n' "$$fragment_envkeep" "$$fragment" > "$$tmp"; \
	  chmod 0440 "$$tmp"; \
	  if sudo -k visudo -c -f "$$tmp" >/dev/null 2>&1; then \
	    : ok; \
	  else \
	    echo "ERROR: generated sudoers fragment failed visudo validation. Contents:"; \
	    cat "$$tmp"; \
	    rm -f "$$tmp"; \
	    exit 1; \
	  fi; \
	  if sudo -k test -f $(TEST_SUDOERS_FRAGMENT_PATH) && sudo -k cmp -s "$$tmp" $(TEST_SUDOERS_FRAGMENT_PATH); then \
	    echo "$(GREEN)✓ already configured: $(TEST_SUDOERS_FRAGMENT_PATH) matches expected NOPASSWD fragment$(RESET)"; \
	    rm -f "$$tmp"; \
	  else \
	    echo "[sudo] install -o root -g root -m 0440 <validated-fragment> $(TEST_SUDOERS_FRAGMENT_PATH)"; \
	    echo "      contents: $$fragment_envkeep | $$fragment"; \
	    sudo -k install -o root -g root -m 0440 "$$tmp" $(TEST_SUDOERS_FRAGMENT_PATH); \
	    rm -f "$$tmp"; \
	  fi; \
	fi

# setup-e2e-test-operator — create a persistent host system user
# `sandbox-e2e-test` (uid 4099) used as the *distinct* operator uid in
# cross-user e2e tests.  Using a real non-1000 uid means the Lima
# cloud-init `usermod -u {op}` realignment actually fires and can be
# verified by the test.
#
# WARNING: this creates a permanent host account.  It is printed on
# every `make setup-e2e-test-operator` (and on `make setup-dev-env`)
# run regardless of whether the account already exists, so the operator
# always knows the account is present.  Run `make clean` to remove it.
#
# Idempotency contract:
#   - If `sandbox-e2e-test` already exists      → skip useradd (no-op).
#   - If uid 4099 is taken by a DIFFERENT user  → fail loudly.
#   - Group add (`usermod -aG sandbox`)         → idempotent (already-member is exit 0).
#   - Sudoers fragment                          → install if absent or stale; validated
#                                                 via `visudo -cf` before landing.
#
# Ordering: must run after `setup-sandbox-user` (the `sandbox` group
# must exist before we can add the test operator to it).
setup-e2e-test-operator: setup-sandbox-user
	@echo "WARNING: host system user '$(E2E_TEST_OPERATOR_NAME)' (uid $(E2E_TEST_OPERATOR_UID)) is used for cross-user e2e operator tests. This is a persistent host account; remove it with 'make clean'."
	@# Check whether uid 4099 is already taken by a different user.
	@if getent passwd "$(E2E_TEST_OPERATOR_UID)" >/dev/null 2>&1; then \
	  existing=$$(getent passwd "$(E2E_TEST_OPERATOR_UID)" | cut -d: -f1); \
	  if [ "$$existing" != "$(E2E_TEST_OPERATOR_NAME)" ]; then \
	    echo "ERROR: uid $(E2E_TEST_OPERATOR_UID) is already taken by user '$$existing' (expected '$(E2E_TEST_OPERATOR_NAME)')."; \
	    echo "Choose a different uid in setup-e2e-test-operator or remove the conflicting account."; \
	    exit 1; \
	  fi; \
	fi
	@if getent passwd "$(E2E_TEST_OPERATOR_NAME)" >/dev/null 2>&1; then \
	  echo "$(GREEN)✓ already configured: system user '$(E2E_TEST_OPERATOR_NAME)' exists$(RESET)"; \
	else \
	  echo "[sudo] useradd -M -u $(E2E_TEST_OPERATOR_UID) -s /usr/sbin/nologin -c 'sandboxd cross-user e2e test operator' $(E2E_TEST_OPERATOR_NAME)"; \
	  sudo -k useradd \
	      -M \
	      -u "$(E2E_TEST_OPERATOR_UID)" \
	      -s /usr/sbin/nologin \
	      -c "sandboxd cross-user e2e test operator" \
	      "$(E2E_TEST_OPERATOR_NAME)"; \
	fi
	@if id -nG "$(E2E_TEST_OPERATOR_NAME)" 2>/dev/null | tr ' ' '\n' | grep -qx sandbox; then \
	  echo "$(GREEN)✓ already configured: '$(E2E_TEST_OPERATOR_NAME)' is in group 'sandbox'$(RESET)"; \
	else \
	  echo "[sudo] usermod -aG sandbox $(E2E_TEST_OPERATOR_NAME)"; \
	  sudo -k usermod -aG sandbox "$(E2E_TEST_OPERATOR_NAME)"; \
	fi
	@if [ -z "$$USER" ] || [ "$$USER" = "root" ]; then \
	  echo "$(GREEN)✓ already configured: e2e-test-operator sudoers fragment skipped (no non-root $$USER set)$(RESET)"; \
	else \
	  fragment_envkeep="Defaults:$$USER env_keep += \"SANDBOX_SOCKET\""; \
	  fragment="$$USER ALL=($(E2E_TEST_OPERATOR_NAME)) NOPASSWD: ALL"; \
	  tmp=$$(mktemp); \
	  printf '# Managed by `make setup-e2e-test-operator` — do not edit.\n# Grants the operator passwordless impersonation of the unprivileged\n# `sandbox-e2e-test` system user (uid 4099). Used by\n# TestHelperPivotUsermodRealignment to run a session as a distinct\n# non-1000 operator uid so the Lima cloud-init `usermod -u {op}`\n# realignment actually fires. The harness invokes the CLI via\n# `sudo -u sandbox-e2e-test env SANDBOX_SOCKET=... <binary> ...`, so a\n# narrow per-binary grant would not match the `env` wrapper; blanket\n# impersonation of this unprivileged nologin account is not privilege\n# escalation. Test/dev hosts only.\n#\n# env_keep preserves SANDBOX_SOCKET through sudo so the CLI\n# reaches the production-shaped daemon socket.\n%s\n%s\n' "$$fragment_envkeep" "$$fragment" > "$$tmp"; \
	  chmod 0440 "$$tmp"; \
	  if sudo -k visudo -c -f "$$tmp" >/dev/null 2>&1; then \
	    : ok; \
	  else \
	    echo "ERROR: generated sudoers fragment failed visudo validation. Contents:"; \
	    cat "$$tmp"; \
	    rm -f "$$tmp"; \
	    exit 1; \
	  fi; \
	  if sudo -k test -f $(E2E_TEST_OPERATOR_SUDOERS) && sudo -k cmp -s "$$tmp" $(E2E_TEST_OPERATOR_SUDOERS); then \
	    echo "$(GREEN)✓ already configured: $(E2E_TEST_OPERATOR_SUDOERS) matches expected NOPASSWD fragment$(RESET)"; \
	    rm -f "$$tmp"; \
	  else \
	    echo "[sudo] install -o root -g root -m 0440 <validated-fragment> $(E2E_TEST_OPERATOR_SUDOERS)"; \
	    echo "      contents: $$fragment"; \
	    sudo -k install -o root -g root -m 0440 "$$tmp" "$(E2E_TEST_OPERATOR_SUDOERS)"; \
	    rm -f "$$tmp"; \
	  fi; \
	fi

# install-route-helper-prod-cap — production cap'd install at the
# canonical FHS-libexec path. Default-feature build (no
# `test-env-override`), so the cap'd binary at this path REFUSES to
# honor `SANDBOX_USERS_CONF` (the privilege-boundary contract).
#
# Stamp-driven on the cargo binary's mtime: if the workspace hasn't
# rebuilt the route helper, this is a no-op. We deliberately do NOT
# stamp on the installed path's mtime alone — a freshly-built but
# already-installed identical binary is detected by the size+mtime
# pair on the stamp file written after a successful install.
install-route-helper-prod-cap: sandboxd/target/.dev-env-stamps/route-helper-prod.stamp
	@true

sandboxd/target/.dev-env-stamps/route-helper-prod.stamp: sandboxd/target/release/sandbox-route-helper
	@mkdir -p $(dir $@)
	@if [ -f "$(ROUTE_HELPER_PROD_PATH)" ] && \
	    cmp -s "sandboxd/target/release/sandbox-route-helper" "$(ROUTE_HELPER_PROD_PATH)" && \
	    getcap "$(ROUTE_HELPER_PROD_PATH)" 2>/dev/null | grep -q cap_net_admin && \
	    getcap "$(ROUTE_HELPER_PROD_PATH)" 2>/dev/null | grep -q cap_sys_admin && \
	    getcap "$(ROUTE_HELPER_PROD_PATH)" 2>/dev/null | grep -q cap_sys_ptrace; then \
	  echo "$(GREEN)✓ already configured: $(ROUTE_HELPER_PROD_PATH) (cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip, content matches build)$(RESET)"; \
	else \
	  echo "[sudo] install -m 0755 sandboxd/target/release/sandbox-route-helper $(ROUTE_HELPER_PROD_PATH)"; \
	  echo "[sudo] setcap cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip $(ROUTE_HELPER_PROD_PATH)"; \
	  sudo -k install -D -m 0755 \
	    sandboxd/target/release/sandbox-route-helper \
	    "$(ROUTE_HELPER_PROD_PATH)"; \
	  sudo -k setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip' "$(ROUTE_HELPER_PROD_PATH)"; \
	fi
	@touch $@

# Mark `.PHONY`-equivalent (always-rebuild) so cargo's own up-to-date
# check runs on every invocation rather than make's mtime check
# against the binary file. cargo skips the rebuild on a no-op
# invocation, so this is cheap on the warm-cache path; without
# `.PHONY` here, an edit to `sandbox-route-helper`'s sources that
# preserves the binary's mtime (rare but possible — `git checkout`
# preserves mtimes, for instance) would leave make convinced the
# target is up-to-date and the install step would silently ship a
# stale binary. Mirror the test variant below.
.PHONY: sandboxd/target/release/sandbox-route-helper
sandboxd/target/release/sandbox-route-helper:
	cd sandboxd && cargo build --release -p sandbox-route-helper

# install-route-helper-test-cap — test cap'd install. Built with
# `--features test-env-override` so the integration tests can pass
# `SANDBOX_USERS_CONF` to point at a tempfile. The two binaries
# (prod-feature release / test-feature debug) live in separate profile
# directories under `sandboxd/target/` (`release/` vs `debug/`) so
# they cannot clobber each other.
#
# Built in **debug** profile so the on-disk binary matches what
# `cargo nextest run --profile integration --features
# sandbox-route-helper/test-env-override` produces for
# `CARGO_BIN_EXE_sandbox-route-helper` (nextest defaults to dev). The
# integration tests then checksum the installed binary against
# `CARGO_BIN_EXE_sandbox-route-helper` and panic on mismatch — using a
# release install here would produce a permanent stale-checksum
# failure regardless of how recently the operator installed. Using
# the workspace default target-dir (`sandboxd/target/`) means cargo
# can re-use the same incremental build artifacts that nextest uses,
# which is what makes the install-time and test-time binaries
# bit-identical.
install-route-helper-test-cap: sandboxd/target/.dev-env-stamps/route-helper-test.stamp
	@true

sandboxd/target/.dev-env-stamps/route-helper-test.stamp: sandboxd/target/debug/sandbox-route-helper
	@mkdir -p $(dir $@)
	@# No cmp -s short-circuit here: the debug path is shared between
	@# feature-gated and non-feature builds, so a plain `cargo build`
	@# can overwrite it with a non-feature binary between make runs.
	@# Always reinstall to guarantee the installed test binary matches
	@# the --features test-env-override artifact built just above.
	echo "[sudo] install -m 0755 sandboxd/target/debug/sandbox-route-helper $(ROUTE_HELPER_TEST_PATH)"; \
	echo "[sudo] setcap cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip $(ROUTE_HELPER_TEST_PATH)"; \
	sudo -k install -D -m 0755 \
	  sandboxd/target/debug/sandbox-route-helper \
	  "$(ROUTE_HELPER_TEST_PATH)"; \
	sudo -k setcap 'cap_net_admin,cap_sys_admin,cap_sys_ptrace=eip' "$(ROUTE_HELPER_TEST_PATH)"
	@touch $@

# Build the test-feature debug binary into the workspace's default
# `sandboxd/target/debug/`. The cargo invocation below mirrors the
# one `cargo nextest run --workspace --profile integration --features
# sandbox-route-helper/test-env-override` uses, with `--tests` added
# so dev-dependency edges (e.g. `ring`, `tempfile`) are unified into
# the same feature graph nextest sees. A workspace build *without*
# `--tests` produces a structurally different `sandbox-route-helper`
# binary (different shared-dep feature flags from dev-dependency
# edges), so the integration test's checksum check would then fail
# with "installed route helper is stale" even right after a fresh
# install. The `--tests` flag also compiles the test harnesses, but
# that is a fast no-op on the warm-cache path that nextest will hit
# anyway when it spawns the run.
#
# We mark this as `.PHONY`-equivalent (always-rebuild) by routing
# through cargo's own up-to-date check — cargo skips the rebuild on
# a no-op invocation, so this is cheap on the warm-cache path.
.PHONY: sandboxd/target/debug/sandbox-route-helper
sandboxd/target/debug/sandbox-route-helper:
	cd sandboxd && cargo build --workspace --tests \
	  --features sandbox-route-helper/test-env-override

# install-lima-helper-prod-cap — production cap'd install at the
# canonical FHS-libexec path. Default-feature build (no
# `test-env-override`), so the cap'd binary at this path REFUSES to
# honor the test env vars (privilege boundary: any user who can exec
# the cap'd helper would otherwise be able to redirect the user/group
# checks to accounts they already control, bypassing the sandbox-user
# gate).
#
# The cap is `cap_setuid+ep` — narrower than the route helper's
# `cap_net_admin,cap_sys_admin=eip`. Only `setresuid` needs elevation;
# the helper clears all caps from permitted+effective+inheritable+ambient
# before exec'ing limactl so limactl inherits zero capabilities.
install-lima-helper-prod-cap: sandboxd/target/.dev-env-stamps/lima-helper-prod.stamp
	@true

sandboxd/target/.dev-env-stamps/lima-helper-prod.stamp: sandboxd/target/release/sandbox-lima-helper
	@mkdir -p $(dir $@)
	@if [ -f "$(LIMA_HELPER_PROD_PATH)" ] && \
	    cmp -s "sandboxd/target/release/sandbox-lima-helper" "$(LIMA_HELPER_PROD_PATH)" && \
	    getcap "$(LIMA_HELPER_PROD_PATH)" 2>/dev/null | grep -q 'cap_setuid'; then \
	  echo "$(GREEN)✓ already configured: $(LIMA_HELPER_PROD_PATH) (cap_setuid+ep, content matches build)$(RESET)"; \
	else \
	  echo "[sudo] install -m 0755 sandboxd/target/release/sandbox-lima-helper $(LIMA_HELPER_PROD_PATH)"; \
	  echo "[sudo] setcap cap_setuid+ep $(LIMA_HELPER_PROD_PATH)"; \
	  sudo -k install -D -m 0755 \
	    sandboxd/target/release/sandbox-lima-helper \
	    "$(LIMA_HELPER_PROD_PATH)"; \
	  sudo -k setcap 'cap_setuid+ep' "$(LIMA_HELPER_PROD_PATH)"; \
	fi
	@touch $@

# See `install-route-helper-prod-cap` for the `.PHONY` rationale —
# the same mtime-preservation problem applies to a `git checkout`
# of `sandbox-lima-helper`'s sources.
.PHONY: sandboxd/target/release/sandbox-lima-helper
sandboxd/target/release/sandbox-lima-helper:
	cd sandboxd && cargo build --release -p sandbox-lima-helper

# install-lima-helper-test-cap — test cap'd install. Built with
# `--features test-env-override` so the integration tests can pass
# `SANDBOX_LIMA_HELPER_TEST_SANDBOX_USER`, `SANDBOX_LIMA_HELPER_TEST_SANDBOX_GROUP`,
# and `SANDBOX_LIMA_HELPER_TEST_GUEST_BINARY_PATH` to drive the helper
# against synthetic accounts.
#
# Mirrors `install-spawn-helper-test-cap` byte-for-byte modulo the
# binary name and capability set:
#   - debug profile (matches nextest's `CARGO_BIN_EXE_*`)
#   - `--workspace --tests --features ...` so dev-dependency feature
#     edges are unified
#   - install to `/usr/local/libexec/sandboxd-test/` so the prod
#     install is never clobbered
install-lima-helper-test-cap: sandboxd/target/.dev-env-stamps/lima-helper-test.stamp
	@true

sandboxd/target/.dev-env-stamps/lima-helper-test.stamp: sandboxd/target/debug/sandbox-lima-helper
	@mkdir -p $(dir $@)
	@# No cmp -s short-circuit here: the debug path is shared between
	@# feature-gated and non-feature builds, so a plain `cargo build`
	@# can overwrite it with a non-feature binary between make runs.
	@# Always reinstall to guarantee the installed test binary matches
	@# the --features test-env-override artifact built just above.
	echo "[sudo] install -m 0755 sandboxd/target/debug/sandbox-lima-helper $(LIMA_HELPER_TEST_PATH)"; \
	echo "[sudo] setcap cap_setuid+ep $(LIMA_HELPER_TEST_PATH)"; \
	sudo -k install -D -m 0755 \
	  sandboxd/target/debug/sandbox-lima-helper \
	  "$(LIMA_HELPER_TEST_PATH)"; \
	sudo -k setcap 'cap_setuid+ep' "$(LIMA_HELPER_TEST_PATH)"
	@touch $@

.PHONY: sandboxd/target/debug/sandbox-lima-helper
sandboxd/target/debug/sandbox-lima-helper:
	cd sandboxd && cargo build --workspace --tests \
	  --features sandbox-lima-helper/test-env-override

# setup-bridge-conf — `/etc/qemu/bridge.conf`. The QEMU bridge helper
# (qemu-bridge-helper) reads this file to decide which bridges
# unprivileged callers may attach to. sandboxd creates per-session
# bridges named `sb-<id>`; we want either `allow sb-*` or `allow all`.
#
# Idempotent + fail-loud:
#   - If the file already contains exactly `allow all` or
#     exactly `allow sb-*`, print `✓ already configured` and exit.
#     A narrower whitelist (e.g. `allow sb-foo` for one specific
#     bridge) intentionally does NOT match — sandboxd creates a fresh
#     `sb-<id>` bridge per session, so a single-bridge whitelist is
#     not sufficient and the operator must broaden it before the
#     suite passes.
#   - If the file is missing, create it with `allow all` (the
#     simplest safe rule for a dev box) — print the `[sudo]` line
#     ahead of the actual sudo so the operator sees the change.
#   - If the file exists but does NOT contain a matching rule, refuse
#     to silently overwrite. Print the current contents and instruct
#     the operator to fix it manually. We never delete or rewrite an
#     existing file.
setup-bridge-conf:
	@if [ -f "$(BRIDGE_CONF_PATH)" ]; then \
	  if grep -qE '^allow (all|sb-\*)$$' "$(BRIDGE_CONF_PATH)" 2>/dev/null; then \
	    echo "$(GREEN)✓ already configured: $(BRIDGE_CONF_PATH) authorizes sandbox bridges$(RESET)"; \
	  else \
	    echo "ERROR: $(BRIDGE_CONF_PATH) exists but does not authorize sandbox bridges (sb-*)."; \
	    echo "Current contents:"; \
	    sed 's/^/    /' "$(BRIDGE_CONF_PATH)"; \
	    echo "Refusing to mutate an existing file. Add a line such as 'allow sb-*'"; \
	    echo "(or 'allow all' for a dev host) and re-run \`make setup-dev-env\`."; \
	    exit 1; \
	  fi; \
	else \
	  echo "[sudo] mkdir -p /etc/qemu  (creating bridge-helper config directory)"; \
	  echo "[sudo] write to $(BRIDGE_CONF_PATH): 'allow all' (qemu bridge auth for sb-* bridges)"; \
	  echo "[sudo] chmod 0644 $(BRIDGE_CONF_PATH)"; \
	  sudo -k mkdir -p /etc/qemu; \
	  echo "allow all" | sudo -k tee "$(BRIDGE_CONF_PATH)" > /dev/null; \
	  sudo -k chmod 0644 "$(BRIDGE_CONF_PATH)"; \
	fi

# setup-users-conf — `/etc/sandboxd/users.conf`.
#
# Two paths:
#
# (a) File does not exist — render `contrib/users.conf.example` with
#     `$USER` substituted in and install it at the canonical path.
#     Ships both the production pool (10.209.0.0/20) and the e2e test
#     pool (10.220.0.0/20).
#
# (b) File exists — leave operator-curated subnets alone, but ensure
#     the e2e test pool (10.220.0.0/20) is present. If absent, parse
#     the canonical JSON, append the test-pool entry to the end of the
#     `subnets` array, and write the result back via `sudo install`.
#     If present, print `✓ already configured` and invoke no sudo.
#
# The upgrade path in (b) exists because hosts that ran
# `make setup-dev-env` before the dual-pool change carry a
# single-pool `users.conf`. The e2e harness sets `SANDBOX_USERS_CONF`
# to point its test daemon at a tempfile users.conf containing only
# the test pool, but the production route helper continues reading
# the canonical file — so the canonical file must list the test pool
# too, or route-helper authorization for the test pool's gateway IP
# fails. See `docs/internal/milestones/M12.md` § S13 for the
# rationale.
#
# Mutation rule: only ever *append* the test-pool entry. Never
# remove, reorder, or rewrite any existing entry the operator has
# added. The append goes through a Python `json.load`/`json.dump`
# round-trip rather than regex/sed so we cannot corrupt the file's
# JSON shape.
setup-users-conf:
	@if [ ! -f "$(USERS_CONF_PATH)" ]; then \
	  rendered=$$(sed 's/$$USER/'"$$USER"'/g' contrib/users.conf.example); \
	  echo "[sudo] mkdir -p /etc/sandboxd  (creating sandboxd config directory)"; \
	  echo "[sudo] write to $(USERS_CONF_PATH):"; \
	  echo "$$rendered" | sed 's/^/    /'; \
	  echo "[sudo] chown root:root $(USERS_CONF_PATH); chmod 0644 $(USERS_CONF_PATH)"; \
	  sudo -k mkdir -p /etc/sandboxd; \
	  printf '%s\n' "$$rendered" | sudo -k tee "$(USERS_CONF_PATH)" > /dev/null; \
	  sudo -k chown root:root "$(USERS_CONF_PATH)"; \
	  sudo -k chmod 0644 "$(USERS_CONF_PATH)"; \
	fi
	@# Ensure the e2e test pool (10.220.0.0/20) lists the daemon's caller
	@# uid (`sandbox`) alongside the operator accounts. The route helper's
	@# pair-check requires BOTH the caller uid (the daemon, `sandbox`) AND
	@# the `--for-user` uid to appear in the matched pool's `allow_users`,
	@# so a test pool listing only the operator is denied for cross-user
	@# sessions. `sandbox-e2e-test` is the distinct operator used by the
	@# cross-user-operator Lima test; unresolvable names are harmless
	@# (the helper treats them as non-matches). Idempotent: rewrites only
	@# when allow_users differs, and only ever touches this managed
	@# test-pool entry — never reorders or removes other entries.
	@tmp=$$(mktemp); \
	result=$$(USER="$$USER" python3 -c 'import json,os,sys; cfg=json.load(open(sys.argv[1])); want=[os.environ["USER"],"sandbox","sandbox-e2e-test"]; subnets=cfg.setdefault("subnets",[]); entry=next((s for s in subnets if s.get("cidr")=="10.220.0.0/20"),None); changed=(entry is None or sorted(entry.get("allow_users",[]))!=sorted(want)); (subnets.append({"comment":"E2E test pool (cross-user e2e harness): sandbox daemon caller plus operator accounts for the route-helper pair-check","cidr":"10.220.0.0/20","allow_users":want}) if entry is None else entry.__setitem__("allow_users",want)); json.dump(cfg,open(sys.argv[2],"w"),indent=2); open(sys.argv[2],"a").write("\n"); print("changed" if changed else "unchanged")' "$(USERS_CONF_PATH)" "$$tmp" 2>/dev/null) || { \
	  echo "ERROR: $(USERS_CONF_PATH) exists but is not parseable as JSON."; \
	  echo "Refusing to mutate. Inspect the file and re-run after fixing."; \
	  rm -f "$$tmp"; exit 1; \
	}; \
	if [ "$$result" = "unchanged" ]; then \
	  echo "$(GREEN)✓ already configured: $(USERS_CONF_PATH) (test pool 10.220.0.0/20 lists sandbox + operators)$(RESET)"; \
	  rm -f "$$tmp"; \
	else \
	  echo "[sudo] set test pool 10.220.0.0/20 allow_users = [$$USER, sandbox, sandbox-e2e-test] in $(USERS_CONF_PATH)"; \
	  echo "[sudo] install -o root -g root -m 0644 <updated> $(USERS_CONF_PATH)"; \
	  sudo -k install -o root -g root -m 0644 "$$tmp" "$(USERS_CONF_PATH)"; \
	  rm -f "$$tmp"; \
	fi

# setup-bridge-helper-setuid — `qemu-bridge-helper` must be setuid
# root to create TAP devices on a bridge as a non-privileged caller.
# Linux distros ship it 0755 by default; we re-apply u+s only if
# missing.
setup-bridge-helper-setuid:
	@if [ ! -e "$(QEMU_BRIDGE_HELPER_PATH)" ]; then \
	  echo "ERROR: $(QEMU_BRIDGE_HELPER_PATH) does not exist."; \
	  echo "Install QEMU first: see docs/start/installation.md § 'Install QEMU and KVM'."; \
	  exit 1; \
	fi
	@if [ -u "$(QEMU_BRIDGE_HELPER_PATH)" ]; then \
	  mode=$$(stat -c '%a' "$(QEMU_BRIDGE_HELPER_PATH)"); \
	  echo "$(GREEN)✓ already configured: $(QEMU_BRIDGE_HELPER_PATH) is setuid (mode $$mode)$(RESET)"; \
	else \
	  echo "[sudo] chmod u+s $(QEMU_BRIDGE_HELPER_PATH)  (qemu-bridge-helper must be setuid for unprivileged TAP creation)"; \
	  sudo -k chmod u+s "$(QEMU_BRIDGE_HELPER_PATH)"; \
	fi
