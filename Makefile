.PHONY: build fmt fmt-check test test-integration test-e2e test-e2e-container test-e2e-matrix gateway-image lite-image docs-dev docs-build clean \
	setup-dev-env install-route-helper-prod-cap install-route-helper-test-cap setup-bridge-conf setup-users-conf setup-bridge-helper-setuid

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
	cd sandboxd && cargo build --workspace

fmt:
	cd sandboxd && cargo fmt --all

fmt-check:
	cd sandboxd && cargo fmt --all -- --check

# Hermetic unit tests: in-process, no Docker / Lima / nftables. The
# default nextest profile (`sandboxd/.config/nextest.toml`) filters out
# every test named `integration_*`, so this target stays fast and
# deterministic even as the workspace grows more integration tests.
test:
	cd sandboxd && cargo nextest run --workspace

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
test-integration: gateway-image install-route-helper-test-cap
	cd sandboxd && \
	    cargo build --workspace --features sandbox-route-helper/test-env-override && \
	    cargo nextest run --workspace --profile integration --features sandbox-route-helper/test-env-override

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
# CI policy (spec § "CI policy", lines ~1060-1070):
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
test-e2e-container: $(VENV_STAMP) gateway-image lite-image install-route-helper-prod-cap
	cd tests/e2e && . .venv/bin/activate && \
	  python -m pytest -v -rs --timeout=600 \
	  -m "not lima" -k "not [lima]" $(TEST)

# Merge-to-main: full matrix -- Lima + container parametrizations plus
# the Lima-only and container-only test files. Wall clock ~30-45 min.
# Single-backend tests (`@pytest.mark.lima` / `@pytest.mark.
# container`) run once on their applicable backend; cross-backend
# tests run twice. Lima-marked tests on a host without limactl /
# qemu-bridge-helper / bridge.conf emit per-test skips via the
# `_lima_required_for_lima_tests` fixture; everything else runs.
test-e2e-matrix: $(VENV_STAMP) gateway-image lite-image install-route-helper-prod-cap
	cd tests/e2e && . .venv/bin/activate && \
	  python -m pytest -v -rs --timeout=600 $(TEST)

# Back-compat alias. `make test-e2e` continues to run the full matrix.
test-e2e: test-e2e-matrix

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
gateway-image:
	docker build -t sandbox-gateway -f networking/gateway/Dockerfile .

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
USERS_CONF_PATH             := /etc/sandboxd/users.conf
BRIDGE_CONF_PATH            := /etc/qemu/bridge.conf
QEMU_BRIDGE_HELPER_PATH     := /usr/lib/qemu/qemu-bridge-helper

setup-dev-env: install-route-helper-prod-cap install-route-helper-test-cap setup-bridge-conf setup-users-conf setup-bridge-helper-setuid
	@echo "$(GREEN)✓ make setup-dev-env complete$(RESET)"

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
	    getcap "$(ROUTE_HELPER_PROD_PATH)" 2>/dev/null | grep -q cap_sys_admin; then \
	  echo "$(GREEN)✓ already configured: $(ROUTE_HELPER_PROD_PATH) (cap_net_admin,cap_sys_admin=eip, content matches build)$(RESET)"; \
	else \
	  echo "[sudo] install -m 0755 sandboxd/target/release/sandbox-route-helper $(ROUTE_HELPER_PROD_PATH)"; \
	  echo "[sudo] setcap cap_net_admin,cap_sys_admin=eip $(ROUTE_HELPER_PROD_PATH)"; \
	  sudo -k install -D -m 0755 \
	    sandboxd/target/release/sandbox-route-helper \
	    "$(ROUTE_HELPER_PROD_PATH)"; \
	  sudo -k setcap 'cap_net_admin,cap_sys_admin=eip' "$(ROUTE_HELPER_PROD_PATH)"; \
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
	@if [ -f "$(ROUTE_HELPER_TEST_PATH)" ] && \
	    cmp -s "sandboxd/target/debug/sandbox-route-helper" "$(ROUTE_HELPER_TEST_PATH)" && \
	    getcap "$(ROUTE_HELPER_TEST_PATH)" 2>/dev/null | grep -q cap_net_admin && \
	    getcap "$(ROUTE_HELPER_TEST_PATH)" 2>/dev/null | grep -q cap_sys_admin; then \
	  echo "$(GREEN)✓ already configured: $(ROUTE_HELPER_TEST_PATH) (cap_net_admin,cap_sys_admin=eip, content matches test build)$(RESET)"; \
	else \
	  echo "[sudo] install -m 0755 sandboxd/target/debug/sandbox-route-helper $(ROUTE_HELPER_TEST_PATH)"; \
	  echo "[sudo] setcap cap_net_admin,cap_sys_admin=eip $(ROUTE_HELPER_TEST_PATH)"; \
	  sudo -k install -D -m 0755 \
	    sandboxd/target/debug/sandbox-route-helper \
	    "$(ROUTE_HELPER_TEST_PATH)"; \
	  sudo -k setcap 'cap_net_admin,cap_sys_admin=eip' "$(ROUTE_HELPER_TEST_PATH)"; \
	fi
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
	@if [ -f "$(USERS_CONF_PATH)" ]; then \
	  rendered_test_entry=$$(python3 -c 'import json,os,sys; sys.stdout.write(json.dumps({"comment":"E2E test pool — used by the e2e test daemon launched with SANDBOX_USERS_CONF pointing at a tempfile that contains only this entry. The production route helper continues reading this canonical file, so authorization for this pool'"'"'s gateway IP succeeds.","cidr":"10.220.0.0/20","allow_users":[os.environ["USER"]]}, indent=2))'); \
	  status=$$(python3 -c 'import json,sys; cfg=json.load(open(sys.argv[1])); print("present" if any(s.get("cidr")=="10.220.0.0/20" for s in cfg.get("subnets",[])) else "absent")' "$(USERS_CONF_PATH)" 2>/dev/null) || { \
	    echo "ERROR: $(USERS_CONF_PATH) exists but is not parseable as JSON."; \
	    echo "Refusing to mutate. Inspect the file and re-run after fixing."; \
	    exit 1; \
	  }; \
	  if [ "$$status" = "present" ]; then \
	    echo "$(GREEN)✓ already configured: $(USERS_CONF_PATH) (test pool 10.220.0.0/20 present)$(RESET)"; \
	  else \
	    tmp=$$(mktemp); \
	    USER="$$USER" python3 -c 'import json,os,sys; cfg=json.load(open(sys.argv[1])); cfg.setdefault("subnets", []).append({"comment":"E2E test pool — used by the e2e test daemon launched with SANDBOX_USERS_CONF pointing at a tempfile that contains only this entry. The production route helper continues reading this canonical file, so authorization for this pool'"'"'s gateway IP succeeds.","cidr":"10.220.0.0/20","allow_users":[os.environ["USER"]]}); json.dump(cfg, open(sys.argv[2], "w"), indent=2); open(sys.argv[2], "a").write("\n")' "$(USERS_CONF_PATH)" "$$tmp"; \
	    echo "[sudo] append test pool entry to $(USERS_CONF_PATH):"; \
	    echo "$$rendered_test_entry" | sed 's/^/    /'; \
	    echo "[sudo] install -o root -g root -m 0644 <updated> $(USERS_CONF_PATH)"; \
	    sudo -k install -o root -g root -m 0644 "$$tmp" "$(USERS_CONF_PATH)"; \
	    rm -f "$$tmp"; \
	  fi; \
	else \
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
