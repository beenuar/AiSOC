#!/usr/bin/env python3
"""Bootstrap one Keycloak realm that both containerised-IdP probes share.

Depth 8.1. Driven by `.github/workflows/sso-live.yml`.

One realm, one user, two clients — an OIDC one and a SAML one — because the
alternative is two probes each standing up their own Keycloak, which doubles
the slowest step in the workflow to prove the same provider twice.

Everything here is idempotent: a `409` from Keycloak means the object this
wanted already exists, which is the state the caller asked for. A workflow
step that is retried, or a second probe running against the realm the first
one created, must not fail for having arrived second.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

REALM = "aisoc-ci"

# OIDC half.
OIDC_CLIENT_ID = "aisoc-console"
OIDC_REDIRECT_URI = "http://localhost:8000/auth/oidc/callback"

# SAML half. The client id *is* the SP entity id — that is how Keycloak
# identifies a service provider, and it is what the `Audience` of every
# assertion will name, so it has to equal what `_saml_settings()` builds
# from `SAML_SP_ENTITY_ID`.
SP_ORIGIN = "http://sp.aisoc-ci.test"
SP_ENTITY_ID = f"{SP_ORIGIN}/auth/saml/metadata"
SP_ACS_URL = f"{SP_ORIGIN}/auth/saml/acs"

USERNAME = "alice"
PASSWORD = "alice-ci-password"
EMAIL = "alice@example.com"

# The group the SAML and OIDC connections both map to a role. Mapping a
# group to a role is the half of provisioning a self-authored provider
# cannot exercise honestly, because the group has to survive a real
# provider's own attribute pipeline to arrive.
GROUP = "soc-analysts"


class KeycloakError(RuntimeError):
    """Keycloak refused a bootstrap step, with its own message attached."""


def admin_token(keycloak: str) -> str:
    response = httpx.post(
        f"{keycloak}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
        timeout=30,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


def _create(url: str, payload: dict[str, Any], headers: dict[str, str]) -> None:
    """POST an object, treating "it already exists" as success."""
    response = httpx.post(url, json=payload, headers=headers, timeout=30)
    if response.status_code not in (201, 204, 409):
        raise KeycloakError(f"Keycloak bootstrap failed at {url}: {response.status_code} {response.text[:400]}")


def bootstrap(keycloak: str) -> dict[str, str]:
    """A realm, two clients, a group and a user. Returns the OIDC secret.

    The OIDC client secret is **read back** rather than assumed. Keycloak
    generates one when a confidential client is created and does not
    necessarily honour a `secret` supplied in the creation payload, so
    sending one and then using it is a coin flip that answers
    `400 unauthorized_client` — a message about the grant, for a problem
    in the registration.
    """
    headers = {"Authorization": f"Bearer {admin_token(keycloak)}"}
    base = f"{keycloak}/admin/realms"

    _create(base, {"realm": REALM, "enabled": True}, headers)
    _create(f"{base}/{REALM}/groups", {"name": GROUP}, headers)

    _create(
        f"{base}/{REALM}/clients",
        {
            "clientId": OIDC_CLIENT_ID,
            "publicClient": False,
            "clientAuthenticatorType": "client-secret",
            "standardFlowEnabled": True,
            # The resource-owner grant is how the OIDC probe obtains a
            # token without a browser. It is enabled on the CI realm only
            # and is not something AiSOC asks a deployment for.
            "directAccessGrantsEnabled": True,
            "redirectUris": [OIDC_REDIRECT_URI],
        },
        headers,
    )

    _create(
        f"{base}/{REALM}/clients",
        {
            "clientId": SP_ENTITY_ID,
            "protocol": "saml",
            "enabled": True,
            "redirectUris": [SP_ACS_URL, f"{SP_ORIGIN}/*"],
            "attributes": {
                # Sign both the response and the assertion. python3-saml
                # is configured `strict`, and the signature is the only
                # thing standing between an assertion and a session.
                "saml.server.signature": "true",
                "saml.assertion.signature": "true",
                "saml.signature.algorithm": "RSA_SHA256",
                # The SP holds no signing key in CI, so Keycloak must not
                # insist that the AuthnRequest carry one. This is the one
                # setting here that a production deployment should invert.
                "saml.client.signature": "false",
                "saml.authnstatement": "true",
                "saml_name_id_format": "email",
                "saml_force_name_id_format": "true",
                "saml_assertion_consumer_url_post": SP_ACS_URL,
            },
            # `saml_acs` reads `attributes["email"]` before it falls back
            # to the NameID, and reads `groups` for the role mapping.
            # Neither arrives without a mapper.
            "protocolMappers": [
                {
                    "name": "email",
                    "protocol": "saml",
                    "protocolMapper": "saml-user-property-mapper",
                    "config": {
                        "user.attribute": "email",
                        "attribute.name": "email",
                        "attribute.nameformat": "Basic",
                    },
                },
                {
                    "name": "groups",
                    "protocol": "saml",
                    "protocolMapper": "saml-group-membership-mapper",
                    "config": {
                        "attribute.name": "groups",
                        "attribute.nameformat": "Basic",
                        "single": "false",
                        "full.path": "false",
                    },
                },
            ],
        },
        headers,
    )

    _create(
        f"{base}/{REALM}/users",
        {
            "username": USERNAME,
            "email": EMAIL,
            "emailVerified": True,
            "enabled": True,
            # Keycloak's `VERIFY_PROFILE` required action is on by default
            # and is evaluated against profile completeness at token time
            # rather than stored on the user, so the account reads as
            # `requiredActions: []` and still refuses the password grant
            # with `invalid_grant: "Account is not fully set up"`. A name
            # is what it is waiting for; without these two fields no probe
            # here can obtain a token at all.
            "firstName": "Alice",
            "lastName": "Analyst",
            "groups": [GROUP],
            "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
        },
        headers,
    )

    listed = httpx.get(
        f"{base}/{REALM}/clients",
        params={"clientId": OIDC_CLIENT_ID},
        headers=headers,
        timeout=30,
    )
    listed.raise_for_status()
    entries = listed.json()
    if not entries:
        raise KeycloakError(f"Keycloak has no client {OIDC_CLIENT_ID!r} after bootstrap")
    secret = httpx.get(
        f"{base}/{REALM}/clients/{entries[0]['id']}/client-secret",
        headers=headers,
        timeout=30,
    )
    secret.raise_for_status()
    return {"oidc_client_secret": str(secret.json().get("value") or "")}


def saml_descriptor(keycloak: str) -> str:
    """The realm's SAML IdP metadata, as an operator would paste it.

    This is the document `aisoc_sso_connections.metadata_xml` holds, and
    reading it from the provider rather than writing it by hand is the
    point: a self-authored metadata document agrees with a self-authored
    assertion by construction.
    """
    response = httpx.get(f"{keycloak}/realms/{REALM}/protocol/saml/descriptor", timeout=30)
    response.raise_for_status()
    body = response.text
    if "IDPSSODescriptor" not in body or "X509Certificate" not in body:
        raise KeycloakError("Keycloak's SAML descriptor carries no IdP descriptor or no certificate")
    return body


def saml_entity_id(descriptor: str) -> str:
    match = re.search(r'entityID="([^"]+)"', descriptor)
    if not match:
        raise KeycloakError("Keycloak's SAML descriptor declares no entityID")
    return match.group(1)
