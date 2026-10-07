#!/usr/bin/env python3
"""Verify a real Keycloak `id_token` with the API's own verification code.

Fix pass 4.1. Driven by `.github/workflows/sso-live.yml`.

Read the caveat before citing this
-----------------------------------
This does **not** prove "a user signed in through Keycloak". There is no
browser here, so the authorization hop — redirect, consent, callback — is
not exercised; `tests/isolation/test_sso_live.py` covers that against a
provider this repository controls.

What it does prove is the half a self-authored provider cannot: that
`app.auth.oidc._verify_id_token` accepts a token minted by a real identity
provider, resolved through that provider's real discovery document and
real JWKS, with a real `kid`. Every defect of the "our fake was more
capable than the vendor" family lives in that gap.

The negative control is in the file rather than the workflow because it
needs the same realm: after the positive check, the same token is
re-verified against a *different* expected audience and must be refused.
A verifier that accepted anything would pass the positive check alone.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import httpx

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
REALM = "aisoc-ci"
CLIENT_ID = "aisoc-console"
CLIENT_SECRET = "aisoc-ci-secret"
USERNAME = "alice"
PASSWORD = "alice-ci-password"
EMAIL = "alice@example.com"

# `services/api` is the import root for `app.*`.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api"))


def _admin_token() -> str:
    response = httpx.post(
        f"{KEYCLOAK}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        timeout=30,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


def bootstrap() -> str:
    """A realm, a confidential client and a user. Returns the client secret.

    The secret is **read back** rather than assumed. Keycloak generates one
    when a confidential client is created and does not necessarily honour a
    `secret` supplied in the creation payload, so sending one and then using
    it is a coin flip that answers `400 unauthorized_client` — a message
    about the grant, for a problem in the registration.
    """
    headers = {"Authorization": f"Bearer {_admin_token()}"}
    base = f"{KEYCLOAK}/admin/realms"

    # 409 is success: the workflow may retry a step, and a realm that
    # already exists is the state this wants.
    for url, payload in (
        (base, {"realm": REALM, "enabled": True}),
        (
            f"{base}/{REALM}/clients",
            {
                "clientId": CLIENT_ID,
                "secret": CLIENT_SECRET,
                "publicClient": False,
                "clientAuthenticatorType": "client-secret",
                "standardFlowEnabled": True,
                # The resource-owner grant is how this script obtains a
                # token without a browser. It is enabled on the CI realm
                # only and is not something AiSOC asks a deployment for.
                "directAccessGrantsEnabled": True,
                "redirectUris": ["http://localhost:8000/auth/oidc/callback"],
            },
        ),
        (
            f"{base}/{REALM}/users",
            {
                "username": USERNAME,
                "email": EMAIL,
                "emailVerified": True,
                "enabled": True,
                "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
            },
        ),
    ):
        response = httpx.post(url, json=payload, headers=headers, timeout=30)
        if response.status_code not in (201, 204, 409):
            raise SystemExit(f"Keycloak bootstrap failed at {url}: {response.status_code} {response.text[:400]}")

    listed = httpx.get(f"{base}/{REALM}/clients", params={"clientId": CLIENT_ID}, headers=headers, timeout=30)
    listed.raise_for_status()
    entries = listed.json()
    if not entries:
        raise SystemExit(f"Keycloak has no client {CLIENT_ID!r} after bootstrap")
    internal_id = entries[0]["id"]
    secret = httpx.get(f"{base}/{REALM}/clients/{internal_id}/client-secret", headers=headers, timeout=30)
    secret.raise_for_status()
    return str(secret.json().get("value") or CLIENT_SECRET)


def issue_id_token(client_secret: str) -> str:
    response = httpx.post(
        f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_secret": client_secret,
            "username": USERNAME,
            "password": PASSWORD,
            "scope": "openid email profile",
        },
        timeout=30,
    )
    if not response.is_success:
        # Keycloak's own `error_description` names the cause — a disabled
        # grant, a bad secret, a user who cannot log in. Raising
        # `HTTPStatusError` instead would print the URL and the status and
        # leave an operator guessing, which is the diagnostic failure this
        # repository keeps rediscovering.
        raise SystemExit(f"Keycloak refused the token request: {response.status_code} {response.text[:500]}")
    token = response.json().get("id_token")
    if not token:
        raise SystemExit("Keycloak returned no id_token; the client is not configured for the openid scope")
    return str(token)


async def main() -> int:
    client_secret = bootstrap()
    id_token = issue_id_token(client_secret)
    issuer = f"{KEYCLOAK}/realms/{REALM}"

    os.environ["OIDC_CLIENT_ID"] = CLIENT_ID
    from app.auth.oidc import _discover, _IdTokenInvalid, _verify_id_token  # noqa: PLC0415

    provider = await _discover(issuer)
    for key in ("jwks_uri", "token_endpoint", "authorization_endpoint"):
        if not provider.get(key):
            raise SystemExit(f"Keycloak's discovery document declares no {key}")

    claims = await _verify_id_token(id_token, issuer=issuer, provider=provider)
    if claims.get("email") != EMAIL:
        raise SystemExit(f"verified a token for {claims.get('email')!r}, expected {EMAIL!r}")
    print(f"OK: a real Keycloak id_token verified against its published JWKS (sub={claims.get('sub')})")

    # The negative control. Same token, an audience this deployment is not
    # configured for: a verifier that checked nothing would have passed
    # above for the wrong reason.
    os.environ["OIDC_CLIENT_ID"] = "some-other-client"
    try:
        await _verify_id_token(id_token, issuer=issuer, provider=provider)
    except _IdTokenInvalid:
        print("OK: the same token is refused when it names another audience.")
        return 0
    print("FAIL: an id_token minted for a different client was accepted.")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
