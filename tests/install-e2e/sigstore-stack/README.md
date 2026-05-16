# Local Sigstore stack (install-e2e)

Hand-rolled docker-compose recipe that brings up a local Fulcio + Rekor
+ Trillian + MySQL + Tesseract CT-log + nginx-OIDC stack for
``tests/install-e2e/``.

The stack lets ``cosign sign-blob`` and ``cosign verify-blob`` run
against a fully local trust chain while honouring the production
identity values that install.sh hardcodes:

- ``--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'``
- ``--certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@.*'``

The stack impersonates the production OIDC issuer URL via:
- a Docker-network alias mapping ``token.actions.githubusercontent.com``
  to the local nginx-OIDC container;
- a TLS leaf cert whose SAN includes the production hostname, signed by
  a local CA whose PEM is injected inline into Fulcio's
  ``ca-cert`` field;
- a static JWKS document served from the same nginx, with the
  matching private key used to mint test JWTs in ``mint_token.py``.

## Layout

```
sigstore-stack/
  README.md                       this file
  .gitignore                      ignores state/
  docker-compose.yml              seven-container stack
  init.sh                         generates state/ (idempotent)
  mint_token.py                   mints a Fulcio-compatible JWT
  fulcio/
    config.yaml.template          rendered to state/fulcio/config.yaml
  oidc/
    nginx.conf
  state/                          generated; do not commit
    ca/                           local TLS CA + key
    certs/oidc/                   nginx-OIDC TLS leaf
    fulcio-root/                  Fulcio signing CA (root.pem, root.key)
    ct-log/                       Tesseract CT log signing keypair
    oidc/                         OIDC JWT signing key + JWKS + discovery doc
    fulcio/                       rendered Fulcio config.yaml
```

## Manual usage

```bash
# Generate state.
./init.sh

# Bring the stack up.
docker compose up -d

# Wait for Fulcio + Rekor readiness.
until curl -sf http://127.0.0.1:5555/healthz; do sleep 1; done
until curl -sf http://127.0.0.1:3000/ping;    do sleep 1; done

# Mint a token, sign a blob, verify the signature.
TOKEN=$(python3 mint_token.py)

SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=$(pwd)/state/ct-log/pubkey.pem \
cosign sign-blob \
    --identity-token "$TOKEN" \
    --fulcio-url http://127.0.0.1:5555 \
    --rekor-url  http://127.0.0.1:3000 \
    --output-signature   /tmp/blob.sig \
    --output-certificate /tmp/blob.cert \
    --yes /tmp/blob.txt

curl -sf http://127.0.0.1:3000/api/v1/log/publicKey > /tmp/rekor.pub

SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=$(pwd)/state/ct-log/pubkey.pem \
SIGSTORE_REKOR_PUBLIC_KEY=/tmp/rekor.pub \
cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/Koriit/sandboxd/\.github/workflows/release\.yml@.*' \
    --certificate-oidc-issuer    'https://token.actions.githubusercontent.com' \
    --certificate-chain $(pwd)/state/fulcio-root/root.pem \
    --rekor-url http://127.0.0.1:3000 \
    --signature   /tmp/blob.sig \
    --certificate /tmp/blob.cert \
    /tmp/blob.txt

# Tear down.
docker compose down -v
```

## Acceptance test

``tests/install-e2e/test_sigstore_stack_smoke.py`` runs the same flow
under pytest; it brings the stack up at module scope, executes
sign-blob + verify-blob, and tears the stack down at the end.

## Resource use

Seven containers; cold bring-up ~30s, tear-down ~12s. Resident memory
~1-1.5 GB. The smoke test runs in ~35s wall time on a 9.7 GB host.

## Architectural notes

See ``.tasks/handoffs/20260516-161203-m16-s11-sigstore-stack-design.md``
for the design doc covering DNS interception, TLS/CA strategy, cosign
trust-root reroute, and dex bypass via static JWKS.
