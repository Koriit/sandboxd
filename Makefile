.PHONY: build test test-e2e gateway-image clean

build:
	cd sandboxd && cargo build --workspace

test:
	cd sandboxd && cargo test --workspace

test-e2e:
	cd tests/e2e && . .venv/bin/activate && python -m pytest -v

gateway-image:
	docker build -t sandbox-gateway networking/gateway/

clean:
	cd sandboxd && cargo clean
