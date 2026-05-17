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
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent

COSIGN_BIN = os.environ.get("COSIGN_BIN", shutil.which("cosign") or "/tmp/cosign")


# The stack itself is brought up by the session-scope ``sigstore_stack``
# fixture in conftest.py. This module-scope wrapper is a thin filter
# that adds a cosign-binary skip on top of the session fixture's
# docker-compose skip — the smoke test calls cosign directly on the
# host, so a missing cosign binary means we cannot exercise the
# acceptance contract regardless of whether the stack is up.


@pytest.fixture(scope="module")
def stack_with_cosign(sigstore_stack):
    if not Path(COSIGN_BIN).is_file():
        pytest.skip(f"cosign binary not found at {COSIGN_BIN}")
    return sigstore_stack


# ---------------------------------------------------------------------------
# Tesseract publishes a checkpoint every ~1.5s; SCT issuance is fast but
# Rekor's tree-init can take a couple of seconds on a cold MySQL.
# Bump tolerances accordingly via pytest-timeout.
# ---------------------------------------------------------------------------


@pytest.mark.timeout(180)
def test_cosign_sign_and_verify_blob_end_to_end(stack_with_cosign, tmp_path):
    """sign-blob + verify-blob round-trip against the local stack.

    Exercises the full chain that install.sh's ``sigstore_verify`` step
    runs at operator install time, including the production OIDC issuer
    string (literal ``https://token.actions.githubusercontent.com``) and
    the production-shaped subject identity regex.
    """
    stack = stack_with_cosign
    venv_python = HERE / ".venv" / "bin" / "python"
    python = str(venv_python) if venv_python.is_file() else sys.executable

    blob = tmp_path / "release.tar.gz"
    blob.write_bytes(b"hello sigstore\n" * 1024)
    sig = tmp_path / "release.sig"
    cert = tmp_path / "release.cert"

    # Mint the JWT.
    mint_rc = subprocess.run(
        [python, str(stack.mint_token_script)],
        check=True, capture_output=True, text=True,
    )
    token = mint_rc.stdout.strip()
    assert token, "minted JWT was empty"

    # cosign sign-blob.
    sign_env = {
        **os.environ,
        "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE": str(stack.ct_log_public_key_path),
    }
    sign_rc = subprocess.run(
        [
            COSIGN_BIN, "sign-blob",
            "--identity-token", token,
            "--fulcio-url", stack.fulcio_url,
            "--rekor-url", stack.rekor_url,
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
        "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE": str(stack.ct_log_public_key_path),
        "SIGSTORE_REKOR_PUBLIC_KEY": str(stack.rekor_public_key_path),
    }
    verify_rc = subprocess.run(
        [
            COSIGN_BIN, "verify-blob",
            "--certificate-identity-regexp",
            r"^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@.*",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--certificate-chain", str(stack.fulcio_root_path),
            "--rekor-url", stack.rekor_url,
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
