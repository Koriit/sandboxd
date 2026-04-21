.PHONY: build fmt fmt-check test test-integration test-validators test-e2e gateway-image docs-dev docs-build clean

build: fmt-check
	cd sandboxd && cargo build --workspace

fmt:
	cd sandboxd && cargo fmt --all

fmt-check:
	cd sandboxd && cargo fmt --all -- --check

test:
	cd sandboxd && cargo nextest run --workspace

test-integration: test
	cd sandboxd && cargo nextest run --package sandbox-core --test '*'

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

# External-validator harness: feeds the policy compiler's outputs
# through the real tools that consume them in production — `nft -c`
# inside a CAP_NET_ADMIN container, `envoy --mode validate` against
# the pinned Envoy version, and a `serde_json` round-trip of the
# mitmproxy config. Each test is `#[ignore]`d and additionally gates
# on `SANDBOX_TEST_VALIDATORS=1`, so the default `make test` /
# `cargo nextest run --workspace` path stays hermetic (no Docker
# dependency). Depends on `gateway-image` so the container tooling
# reflects current `networking/` sources.
test-validators: gateway-image
	cd sandboxd && SANDBOX_TEST_VALIDATORS=1 cargo nextest run \
		--workspace --run-ignored only -E 'test(/validator_/)'

# Stamp-driven rebuild: only rebuild the docker image when one of its
# inputs (Dockerfile, addon, entrypoint, Envoy/CoreDNS configs) changes.
# The phony `gateway-image` target remains as an unconditional rebuild
# entry point for callers who want to force a rebuild.
GATEWAY_INPUTS := $(shell find networking -type f \
	\( -name '*.py' -o -name '*.sh' -o -name 'Dockerfile' \
	   -o -name '*.yaml' -o -name '*.yml' -o -name 'Corefile' \) \
	-not -path '*/__pycache__/*')

.gateway-image.stamp: $(GATEWAY_INPUTS)
	docker build -t sandbox-gateway -f networking/gateway/Dockerfile networking/
	@touch $@

gateway-image: .gateway-image.stamp

docs-dev:
	cd site && npm install && npm run dev

docs-build:
	cd site && npm install && npm run build

clean:
	cd sandboxd && cargo clean
	rm -rf tests/e2e/.venv/
	rm -f .gateway-image.stamp
	rm -rf site/node_modules site/dist
