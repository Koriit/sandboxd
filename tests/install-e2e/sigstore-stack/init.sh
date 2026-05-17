#!/usr/bin/env bash
# Generate the local Sigstore stack's state on disk (idempotent).
#
# Produces, under tests/install-e2e/sigstore-stack/state/:
#
#   ca/ca.{key,pem}             Local TLS CA (signs leaf certs for the
#                               HTTPS endpoints the stack serves).
#   certs/oidc/{cert,key}.pem   TLS leaf for the static-JWKS server,
#                               SAN includes 'token.actions.githubusercontent.com'.
#   fulcio-root/root.{pem,key}  The Fulcio signing CA (issues the
#                               end-entity certs cosign uses).
#   ct-log/{privkey,pubkey}.pem CT log signing key.
#   rekor/signing.key           PEM-encoded ECDSA P-256 private key used
#                               as Rekor's transparency-log signer (passed
#                               via --rekor_server.signer=<path>). Persists
#                               across stack restarts so cached .sigstore
#                               bundles remain valid for their lifetime.
#   oidc/signing.{key,pub}.pem  RSA-2048 keypair used to mint OIDC JWTs.
#   oidc/jwks.json              JWKS document derived from signing.pub.pem.
#   oidc/discovery.json         OIDC well-known discovery document.
#
# Rerunning the script is a no-op when all artefacts exist. Delete the
# state/ directory to regenerate.

set -euo pipefail

STACK_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="$STACK_DIR/state"

CA_DIR="$STATE_DIR/ca"
CERTS_DIR="$STATE_DIR/certs"
FULCIO_ROOT_DIR="$STATE_DIR/fulcio-root"
CT_LOG_DIR="$STATE_DIR/ct-log"
REKOR_DIR="$STATE_DIR/rekor"
OIDC_DIR="$STATE_DIR/oidc"

OIDC_ISSUER="${OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
FULCIO_ROOT_PASSWD="${FULCIO_ROOT_PASSWD:-sandboxd-test}"

mkdir -p "$CA_DIR" "$CERTS_DIR/oidc" "$FULCIO_ROOT_DIR" "$CT_LOG_DIR" "$REKOR_DIR" "$OIDC_DIR"

# --- TLS CA --------------------------------------------------------------

if [ ! -s "$CA_DIR/ca.pem" ]; then
    echo "[init.sh] generating TLS CA"
    openssl ecparam -name prime256v1 -genkey -noout -out "$CA_DIR/ca.key"
    openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days 3650 \
        -subj "/CN=sandboxd local sigstore CA" \
        -out "$CA_DIR/ca.pem"
fi

# Helper to issue a leaf cert with arbitrary SANs.
# Args: <name> <subj-cn> <san-list>
issue_leaf() {
    local name="$1" cn="$2" sans="$3"
    local out="$CERTS_DIR/$name"
    mkdir -p "$out"
    if [ -s "$out/cert.pem" ] && [ -s "$out/key.pem" ]; then
        return 0
    fi
    echo "[init.sh] issuing leaf cert for $name (SANs: $sans)"
    openssl ecparam -name prime256v1 -genkey -noout -out "$out/key.pem"
    cat > "$out/req.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = $cn
[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $sans
EOF
    openssl req -new -key "$out/key.pem" -config "$out/req.cnf" -out "$out/csr.pem"
    openssl x509 -req -in "$out/csr.pem" -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" \
        -CAcreateserial -days 365 -sha256 -extfile "$out/req.cnf" -extensions v3_req \
        -out "$out/cert.pem" 2>/dev/null
    rm -f "$out/csr.pem" "$out/req.cnf" "$CA_DIR/ca.srl"
}

# --- OIDC server leaf cert ----------------------------------------------
# Must include 'token.actions.githubusercontent.com' so Fulcio's go-oidc
# discovery accepts the cert when the production hostname resolves to
# the local oidc nginx via extra_hosts.
issue_leaf oidc "oidc.local" \
    "DNS:oidc,DNS:oidc.local,DNS:token.actions.githubusercontent.com"

# --- Fulcio signing CA --------------------------------------------------

if [ ! -s "$FULCIO_ROOT_DIR/root.pem" ]; then
    echo "[init.sh] generating Fulcio signing CA"
    # Encrypted EC private key (Fulcio's fileca expects a passphrase).
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$FULCIO_ROOT_DIR/root.key.unenc"
    openssl ec -in "$FULCIO_ROOT_DIR/root.key.unenc" \
        -aes256 -passout "pass:$FULCIO_ROOT_PASSWD" \
        -out "$FULCIO_ROOT_DIR/root.key" 2>/dev/null
    rm -f "$FULCIO_ROOT_DIR/root.key.unenc"
    openssl req -x509 -new -nodes -key "$FULCIO_ROOT_DIR/root.key" \
        -passin "pass:$FULCIO_ROOT_PASSWD" \
        -sha256 -days 3650 \
        -subj "/O=sandboxd local sigstore/CN=sandboxd local fulcio root" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
        -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign" \
        -out "$FULCIO_ROOT_DIR/root.pem"
    # Fulcio container runs as a non-root user — make the key world-readable
    # so the mounted volume is accessible. This is a test-only stack with no
    # real-world trust implications.
    chmod 0644 "$FULCIO_ROOT_DIR/root.key"
fi

# --- CT log signing key -------------------------------------------------

if [ ! -s "$CT_LOG_DIR/privkey.pem" ]; then
    echo "[init.sh] generating CT log signing key"
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$CT_LOG_DIR/privkey.pem"
    openssl ec -in "$CT_LOG_DIR/privkey.pem" -pubout \
        -out "$CT_LOG_DIR/pubkey.pem" 2>/dev/null
fi

# --- Rekor transparency-log signing key ---------------------------------
# Rekor v1.5.1's --rekor_server.signer accepts a path to a PEM-encoded
# private key (parsed via go.step.sm/crypto/pemutil — accepts SEC1
# `EC PRIVATE KEY` and PKCS8 `PRIVATE KEY` blocks). The in-memory signer
# matches NewECDSASignerVerifier(P256, SHA256); mirror that here so the
# public key Rekor publishes at /api/v1/log/publicKey is byte-identical
# across container restarts. Without this, every `docker compose up`
# minted a fresh key and invalidated cached .sigstore bundles.

if [ ! -s "$REKOR_DIR/signing.key" ]; then
    echo "[init.sh] generating Rekor signing key (ECDSA P-256, SEC1 PEM)"
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "$REKOR_DIR/signing.key"
    # The Rekor container runs as a non-root user; make the file
    # world-readable (test-only stack, no real-world trust implication).
    chmod 0644 "$REKOR_DIR/signing.key"
fi

# --- OIDC signing key + JWKS + discovery doc ----------------------------

if [ ! -s "$OIDC_DIR/signing.key.pem" ]; then
    echo "[init.sh] generating OIDC signing key (RSA-2048)"
    openssl genrsa -out "$OIDC_DIR/signing.key.pem" 2048
    openssl rsa -in "$OIDC_DIR/signing.key.pem" -pubout \
        -out "$OIDC_DIR/signing.pub.pem" 2>/dev/null
fi

# Generate JWKS from the public key. We use python3 (already a hard
# dependency of the tests/install-e2e venv) — no need for additional
# tooling on the host.
if [ ! -s "$OIDC_DIR/jwks.json" ] || [ "$OIDC_DIR/signing.pub.pem" -nt "$OIDC_DIR/jwks.json" ]; then
    echo "[init.sh] writing JWKS"
    python3 - <<PYEOF
import base64
import json
import re
import sys

# Parse PEM RSA public key into (n, e) using only stdlib (no
# cryptography import — keep the bootstrap dep-free).
pem = open("$OIDC_DIR/signing.pub.pem", "rb").read()

# Try cryptography first if available; fall back to stdlib ASN.1 parse.
try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    key = load_pem_public_key(pem)
    nums = key.public_numbers()
    n_int, e_int = nums.n, nums.e
except ImportError:
    sys.stderr.write("[init.sh] cryptography unavailable; "
                     "ensure tests/install-e2e/.venv is activated\n")
    sys.exit(2)


def b64u(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "sandboxd-local-oidc",
        "n": b64u(n_int),
        "e": b64u(e_int),
    }]
}
json.dump(jwks, open("$OIDC_DIR/jwks.json", "w"), indent=2)
PYEOF
fi

# Discovery doc. The 'issuer' field must match the issuer URL literally
# (cosign + go-oidc both validate this).
if [ ! -s "$OIDC_DIR/discovery.json" ]; then
    echo "[init.sh] writing OIDC discovery document"
    cat > "$OIDC_DIR/discovery.json" <<EOF
{
  "issuer": "$OIDC_ISSUER",
  "jwks_uri": "$OIDC_ISSUER/keys",
  "authorization_endpoint": "$OIDC_ISSUER/auth",
  "token_endpoint": "$OIDC_ISSUER/token",
  "response_types_supported": ["id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "claims_supported": [
    "iss", "sub", "aud", "exp", "iat", "job_workflow_ref",
    "repository", "repository_owner", "ref", "sha",
    "event_name", "workflow", "workflow_ref", "workflow_sha",
    "run_id", "run_attempt", "repository_id", "repository_owner_id",
    "repository_visibility", "runner_environment"
  ]
}
EOF
fi

# --- Render Fulcio config (CA cert embedded inline) ---------------------

mkdir -p "$STATE_DIR/fulcio"
if [ ! -s "$STATE_DIR/fulcio/config.yaml" ] \
        || [ "$STACK_DIR/fulcio/config.yaml.template" -nt "$STATE_DIR/fulcio/config.yaml" ] \
        || [ "$CA_DIR/ca.pem" -nt "$STATE_DIR/fulcio/config.yaml" ]; then
    echo "[init.sh] rendering Fulcio config"
    # Indent the CA pem two spaces so it sits inside the YAML block scalar.
    ca_indented=$(sed 's/^/  /' "$CA_DIR/ca.pem")
    python3 - <<PYEOF
import pathlib

tmpl = pathlib.Path("$STACK_DIR/fulcio/config.yaml.template").read_text()
ca = pathlib.Path("$CA_DIR/ca.pem").read_text()
# YAML block scalar under 'ca-cert:' (indented 4 spaces in the
# template) requires content lines indented strictly deeper — 6 spaces.
indented = "\n".join("      " + line if line else "" for line in ca.splitlines())
out = tmpl.replace("@@CA_CERT_PEM@@", indented)
pathlib.Path("$STATE_DIR/fulcio/config.yaml").write_text(out)
PYEOF
fi

echo "[init.sh] state ready under $STATE_DIR"
