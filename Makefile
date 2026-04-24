.PHONY: build fmt fmt-check test test-integration test-e2e gateway-image docs-dev docs-build clean

build: fmt-check
	cd sandboxd && cargo build --workspace

fmt:
	cd sandboxd && cargo fmt --all

fmt-check:
	cd sandboxd && cargo fmt --all -- --check

# Hermetic unit tests: in-process, no Docker / Lima / nftables. Every test
# that needs out-of-process state (real gateway container, external validator
# binaries like `nft -c` / `envoy --mode validate`, Lima VMs) is marked
# `#[ignore]` at the test site so this target stays fast and deterministic.
test:
	cd sandboxd && cargo nextest run --workspace

# Integration tests: every `#[ignore]`d test in the workspace. This runs both
# (a) the gateway-container lifecycle tests in `sandbox-core/tests/gateway_integration.rs`
# (need Docker + the sandbox-gateway image), and (b) the external-validator
# tests in `sandbox-core/tests/validators.rs` (policy-compiler outputs run
# through real `nft -c` / `envoy --mode validate` / mitmproxy JSON round-trip).
# Validator tests additionally short-circuit in-body unless SANDBOX_TEST_VALIDATORS=1
# is set — we always set it here because this Make target implies Docker is
# present. Use `cargo nextest run --run-ignored only -E '<filter>'` directly
# for finer selection when iterating.
test-integration: gateway-image
	cd sandboxd && SANDBOX_TEST_VALIDATORS=1 cargo nextest run \
		--workspace --run-ignored only

tests/e2e/.venv/.installed: tests/e2e/pyproject.toml
	python3 -m venv tests/e2e/.venv
	tests/e2e/.venv/bin/python -c \
		"import tomllib, subprocess, sys; \
		deps = tomllib.load(open('tests/e2e/pyproject.toml', 'rb'))['project']['dependencies']; \
		subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + deps)"
	touch tests/e2e/.venv/.installed

TEST ?=
# test-e2e depends on gateway-image so the container running mitmproxy /
# Envoy / CoreDNS always reflects the current `networking/` sources.
# Forgetting to rebuild baked stale addon code into the image and produced
# silent semantic drift between sandboxd (Rust) and the enforcement layer.
test-e2e: tests/e2e/.venv/.installed gateway-image
	cd tests/e2e && . .venv/bin/activate && python -m pytest -v -rs $(TEST)

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

docs-dev:
	cd site && npm install && npm run dev

docs-build:
	cd site && npm ci && npm run build

clean:
	cd sandboxd && cargo clean
	rm -rf tests/e2e/.venv/
	rm -rf site/node_modules site/dist
