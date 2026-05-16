"""Smoke test for the local Sigstore stack.

Brings up the seven-container stack at
``tests/install-e2e/sigstore-stack/`` and exercises ``cosign sign-blob``
+ ``cosign verify-blob`` against it. Both commands use the production
OIDC issuer string (``https://token.actions.githubusercontent.com``)
verbatim, which the stack impersonates via:

- nginx-served discovery doc + JWKS at the production hostname (the
  Fulcio container's ``extra_hosts`` alias plus a TLS cert whose SAN
  includes the production hostname);
- Fulcio's per-issuer ``ca-cert`` field embedding the local CA so its
  go-oidc client trusts the impersonated TLS endpoint;
- a JWT minted ahead of time in Python with the same private half of
  the key whose public half is served at the JWKS endpoint.

This test is the acceptance criterion for the stack's bring-up. The
install-e2e integration (replacing the ``cosign_bootstrap`` +
``sigstore_verify`` patches in conftest.py with a real sigstore-bundle
flow) is a separate downstream task.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
STACK_DIR = HERE / "sigstore-stack"

COSIGN_BIN = os.environ.get("COSIGN_BIN", shutil.which("cosign") or "/tmp/cosign")


# ---------------------------------------------------------------------------
# Module-scope: bring the stack up once, tear down at the end.
# ---------------------------------------------------------------------------


def _docker_compose_available() -> bool:
    if not shutil.which("docker"):
        return False
    rc = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True, text=True,
    )
    return rc.returncode == 0


def _wait_http(url: str, deadline_seconds: float, accept_404: bool = False) -> None:
    """Poll *url* until it returns 200 (or 404 if ``accept_404``)."""
    deadline = time.monotonic() + deadline_seconds
    last_err = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
                if accept_404 and resp.status == 404:
                    return
        except Exception as e:  # noqa: BLE001 — best-effort retry
            last_err = e
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {url}: {last_err}")


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=STACK_DIR,
        check=check,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def sigstore_stack():
    """Bring the stack up; yield a handle; tear down at module-end."""
    if not _docker_compose_available():
        pytest.skip("docker compose not available")
    if not Path(COSIGN_BIN).is_file():
        pytest.skip(f"cosign binary not found at {COSIGN_BIN}")

    # Generate stack state on disk (idempotent).
    init_rc = subprocess.run(
        [str(STACK_DIR / "init.sh")],
        capture_output=True,
        text=True,
    )
    assert init_rc.returncode == 0, (
        f"init.sh failed: rc={init_rc.returncode}\n"
        f"stdout:\n{init_rc.stdout}\nstderr:\n{init_rc.stderr}"
    )

    # Bring the stack up. We don't pass --wait because most of our
    # downstream services are distroless and have no in-container
    # healthcheck; we readiness-probe from the host below.
    bringup = _compose("up", "-d", check=False)
    if bringup.returncode != 0:
        teardown = _compose("down", "-v", check=False)
        raise RuntimeError(
            f"docker compose up failed: rc={bringup.returncode}\n"
            f"stdout:\n{bringup.stdout}\nstderr:\n{bringup.stderr}\n"
            f"teardown stdout:\n{teardown.stdout}\n"
            f"teardown stderr:\n{teardown.stderr}"
        )

    try:
        # Probe each host-exposed endpoint. Fulcio's /healthz handler
        # returns SERVING only once its downstream dependencies (CT log
        # included) are reachable, so we don't need a separate
        # tesseract probe — and tesseract isn't host-port-exposed.
        _wait_http("http://127.0.0.1:5555/healthz", deadline_seconds=120.0)
        _wait_http("http://127.0.0.1:3000/ping", deadline_seconds=60.0)

        # Cache the Rekor public key so the verify step can pass it
        # via SIGSTORE_REKOR_PUBLIC_KEY.
        rekor_pub_path = STACK_DIR / "state" / "rekor.pub.cached.pem"
        with urllib.request.urlopen(
            "http://127.0.0.1:3000/api/v1/log/publicKey", timeout=5,
        ) as resp:
            rekor_pub_path.write_bytes(resp.read())

        yield {
            "fulcio_url": "http://127.0.0.1:5555",
            "rekor_url": "http://127.0.0.1:3000",
            "ct_log_public_key": STACK_DIR / "state" / "ct-log" / "pubkey.pem",
            "fulcio_root_chain": STACK_DIR / "state" / "fulcio-root" / "root.pem",
            "rekor_public_key": rekor_pub_path,
            "oidc_signing_key": STACK_DIR / "state" / "oidc" / "signing.key.pem",
            "mint_token_script": STACK_DIR / "mint_token.py",
        }
    finally:
        _compose("down", "-v", check=False)


# ---------------------------------------------------------------------------
# Tesseract publishes a checkpoint every ~1.5s; SCT issuance is fast but
# Rekor's tree-init can take a couple of seconds on a cold MySQL.
# Bump tolerances accordingly via pytest-timeout.
# ---------------------------------------------------------------------------


@pytest.mark.timeout(180)
def test_cosign_sign_and_verify_blob_end_to_end(sigstore_stack, tmp_path):
    """sign-blob + verify-blob round-trip against the local stack.

    Exercises the full chain that install.sh's ``sigstore_verify`` step
    runs at operator install time, including the production OIDC issuer
    string (literal ``https://token.actions.githubusercontent.com``) and
    the production-shaped subject identity regex.
    """
    venv_python = HERE / ".venv" / "bin" / "python"
    python = str(venv_python) if venv_python.is_file() else sys.executable

    blob = tmp_path / "release.tar.gz"
    blob.write_bytes(b"hello sigstore\n" * 1024)
    sig = tmp_path / "release.sig"
    cert = tmp_path / "release.cert"

    # Mint the JWT.
    mint_rc = subprocess.run(
        [python, str(sigstore_stack["mint_token_script"])],
        check=True, capture_output=True, text=True,
    )
    token = mint_rc.stdout.strip()
    assert token, "minted JWT was empty"

    # cosign sign-blob.
    sign_env = {
        **os.environ,
        "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE": str(sigstore_stack["ct_log_public_key"]),
    }
    sign_rc = subprocess.run(
        [
            COSIGN_BIN, "sign-blob",
            "--identity-token", token,
            "--fulcio-url", sigstore_stack["fulcio_url"],
            "--rekor-url", sigstore_stack["rekor_url"],
            "--output-signature", str(sig),
            "--output-certificate", str(cert),
            "--yes",
            str(blob),
        ],
        env=sign_env, capture_output=True, text=True,
    )
    assert sign_rc.returncode == 0, (
        f"cosign sign-blob failed: rc={sign_rc.returncode}\n"
        f"stdout:\n{sign_rc.stdout}\nstderr:\n{sign_rc.stderr}"
    )
    assert sig.exists() and sig.stat().st_size > 0
    assert cert.exists() and cert.stat().st_size > 0

    # cosign verify-blob with the production identity flags.
    verify_env = {
        **os.environ,
        "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE": str(sigstore_stack["ct_log_public_key"]),
        "SIGSTORE_REKOR_PUBLIC_KEY": str(sigstore_stack["rekor_public_key"]),
    }
    verify_rc = subprocess.run(
        [
            COSIGN_BIN, "verify-blob",
            "--certificate-identity-regexp",
            r"^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@.*",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--certificate-chain", str(sigstore_stack["fulcio_root_chain"]),
            "--rekor-url", sigstore_stack["rekor_url"],
            "--signature", str(sig),
            "--certificate", str(cert),
            str(blob),
        ],
        env=verify_env, capture_output=True, text=True,
    )
    assert verify_rc.returncode == 0, (
        f"cosign verify-blob failed: rc={verify_rc.returncode}\n"
        f"stdout:\n{verify_rc.stdout}\nstderr:\n{verify_rc.stderr}"
    )
    assert "Verified OK" in verify_rc.stderr or "Verified OK" in verify_rc.stdout
