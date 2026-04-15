.PHONY: build test test-integration test-e2e gateway-image clean

build:
	cd sandboxd && cargo build --workspace

test:
	cd sandboxd && cargo test --workspace --quiet

test-integration: test
	cd sandboxd && cargo test --package sandbox-core --test '*'

tests/e2e/.venv/.installed: tests/e2e/pyproject.toml
	python3 -m venv tests/e2e/.venv
	tests/e2e/.venv/bin/python -c \
		"import tomllib, subprocess, sys; \
		deps = tomllib.load(open('tests/e2e/pyproject.toml', 'rb'))['project']['dependencies']; \
		subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + deps)"
	touch tests/e2e/.venv/.installed

test-e2e: tests/e2e/.venv/.installed
	cd tests/e2e && . .venv/bin/activate && python -m pytest -v -rs

gateway-image:
	docker build -t sandbox-gateway -f networking/gateway/Dockerfile networking/

clean:
	cd sandboxd && cargo clean
	rm -rf tests/e2e/.venv/
