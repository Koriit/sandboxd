.PHONY: build test test-integration test-e2e gateway-image clean

build:
	cd sandboxd && cargo build --workspace

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
PARALLEL ?= 1
# --dist=loadfile keeps all tests in a single file on one xdist worker.
# This is important for tests that share file-scoped state
# (e.g. test_m85_golden_image.py's destructive tests must run in-order
# on one worker; splitting them across workers would race on
# ~/.lima/sandbox-base mutations).
test-e2e: tests/e2e/.venv/.installed
	cd tests/e2e && . .venv/bin/activate && python -m pytest -v -rs -n $(PARALLEL) --dist=loadfile $(TEST)

gateway-image:
	docker build -t sandbox-gateway -f networking/gateway/Dockerfile networking/

clean:
	cd sandboxd && cargo clean
	rm -rf tests/e2e/.venv/
