#!/usr/bin/env python3
"""Mint an OIDC JWT signed with the local stack's signing key.

The token impersonates a GitHub Actions workflow run, claim-for-claim
compatible with Fulcio's `github-workflow` ci-provider type:

    iss: https://token.actions.githubusercontent.com
    aud: sigstore
    sub: https://github.com/<owner>/<repo>/.github/workflows/<wf>@<ref>
    job_workflow_ref: <owner>/<repo>/.github/workflows/<wf>@<ref>
    ref: <ref>
    sha: <some-sha>
    repository: <owner>/<repo>
    repository_owner: <owner>
    repository_id, repository_owner_id, repository_visibility,
    workflow, workflow_ref, workflow_sha, run_id, run_attempt,
    event_name, runner_environment

Usage::

    python3 mint_token.py [--owner OWNER] [--repo REPO]
                          [--workflow PATH]
                          [--ref REF]

Writes the JWT to stdout. Reads the signing key from
``state/oidc/signing.key.pem`` (resolved relative to the script's
directory).
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import time

import jwt as pyjwt  # pyjwt[crypto]


def mint(
    signing_key_path: pathlib.Path,
    owner: str = "Koriit",
    repo: str = "sandboxd",
    workflow: str = ".github/workflows/release.yml",
    ref: str = "refs/heads/main",
    issuer: str = "https://token.actions.githubusercontent.com",
    audience: str = "sigstore",
    ttl_seconds: int = 600,
) -> str:
    """Return a JWT that Fulcio's github-workflow ci-provider will accept."""

    job_workflow_ref = f"{owner}/{repo}/{workflow}@{ref}"
    sub = f"https://github.com/{job_workflow_ref}"

    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        # github-workflow extension claims (see Fulcio config.yaml,
        # ci-issuer-metadata.github-workflow.extension-templates).
        "job_workflow_ref": job_workflow_ref,
        "job_workflow_sha": "0000000000000000000000000000000000000000",
        "workflow_ref": job_workflow_ref,
        "workflow_sha": "0000000000000000000000000000000000000000",
        "workflow": "release",
        "ref": ref,
        "sha": "0000000000000000000000000000000000000000",
        "repository": f"{owner}/{repo}",
        "repository_owner": owner,
        "repository_id": "1",
        "repository_owner_id": "1",
        "repository_visibility": "public",
        "event_name": "push",
        "run_id": "1",
        "run_attempt": "1",
        "runner_environment": "github-hosted",
    }

    key_pem = signing_key_path.read_bytes()
    return pyjwt.encode(
        claims, key_pem, algorithm="RS256",
        headers={"kid": "sandboxd-local-oidc"},
    )


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent
    default_key = here / "state" / "oidc" / "signing.key.pem"

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key", type=pathlib.Path, default=default_key,
                    help=f"signing key PEM (default: {default_key})")
    ap.add_argument("--owner", default="Koriit")
    ap.add_argument("--repo", default="sandboxd")
    ap.add_argument("--workflow", default=".github/workflows/release.yml")
    ap.add_argument("--ref", default="refs/heads/main")
    ap.add_argument("--issuer", default="https://token.actions.githubusercontent.com")
    ap.add_argument("--audience", default="sigstore")
    ap.add_argument("--ttl-seconds", type=int, default=600)
    args = ap.parse_args()

    if not args.key.exists():
        sys.stderr.write(
            f"signing key not found: {args.key}\n"
            "Run init.sh first to generate stack state.\n"
        )
        return 2

    print(mint(
        signing_key_path=args.key,
        owner=args.owner,
        repo=args.repo,
        workflow=args.workflow,
        ref=args.ref,
        issuer=args.issuer,
        audience=args.audience,
        ttl_seconds=args.ttl_seconds,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
