"""Where a SAML deployment's trust in an identity provider comes from.

Fix pass 4.1.

The defect
----------
`_saml_settings()` built the `idp` block from `SAML_IDP_ENTITY_ID`,
`SAML_IDP_SSO_URL` and `SAML_IDP_CERT` — process-wide environment
variables — while `aisoc_sso_connections.metadata_url` and `.metadata_xml`
were written by `POST /sso-connections`, returned by `GET /sso-connections`
and read by nothing. So an administrator could configure a connection in
the console, watch it come back from the API, and have the deployment go on
trusting whatever the environment said. On a deployment that sets no SAML
environment at all — the default, and what `.env.example` ships — the IdP
block is empty, so every assertion is refused and the console reports a
configuration that is doing nothing.

It also capped the deployment at exactly one identity provider, which the
connection table was designed not to be: the unique index is on
`(provider, issuer)` precisely so several tenants can each bring their own.

Selecting a connection by the issuer an assertion names
--------------------------------------------------------
`/acs` reads the `<saml:Issuer>` out of the POSTed response *before*
anything has been verified, and uses it to pick which connection's
certificate to verify against. That is safe, and the reason is worth
stating because it looks like the thing this feature refuses to do
everywhere else:

the asserted issuer selects a **trust anchor**, it does not confer trust.
An assertion naming an issuer whose private key the sender does not hold
fails signature verification and authenticates nobody. The tenant still
comes from the connection row an administrator configured, never from the
assertion — that property is unchanged and is what
`complete_sso_login` enforces.

A `metadata_url` is fetched by this service from an address a tenant
administrator supplied, which is the shape `_vendor/ssrf_guard.py` exists
for, so the fetch goes through it and the response is size-capped.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import time
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app._vendor.ssrf_guard import SSRFError, validate_outbound_url

logger = logging.getLogger(__name__)

#: A metadata document is a handful of kilobytes. The cap is here because
#: the URL is operator-supplied and the response is not: a redirect to
#: something enormous should fail rather than be streamed into memory.
_MAX_METADATA_BYTES = 2 * 1024 * 1024

#: IdP metadata is public, idempotent and changes when a certificate rolls.
#: Re-fetching it on every sign-in would put the identity provider's
#: availability in front of every login, so it is cached per replica.
_METADATA_TTL_SECONDS = 600
_metadata_cache: dict[str, tuple[float, str]] = {}


def _sanitize(value: object, limit: int = 160) -> str:
    return str(value).replace("\r", "").replace("\n", " ")[:limit]


class SamlTrustError(Exception):
    """No usable IdP trust material could be assembled for this sign-in."""


def parse_idp_metadata(xml: str, *, entity_id: str | None = None) -> dict[str, Any]:
    """The `idp` settings block a SAML metadata document declares.

    Delegates to `python3-saml`'s own parser rather than reading the XML
    here: it already resolves bindings, picks the `IDPSSODescriptor` and
    collects multiple signing certificates into `x509certMulti`, and it
    parses with `forbid_dtd=True, forbid_entities=True`, so a metadata
    document cannot carry an external-entity reference.
    """
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser  # noqa: PLC0415

    try:
        parsed = OneLogin_Saml2_IdPMetadataParser.parse(xml, entity_id=entity_id)
    except Exception as exc:  # noqa: BLE001 - any parse failure is a refusal
        raise SamlTrustError(f"the IdP metadata could not be parsed: {exc}") from exc

    idp = dict((parsed or {}).get("idp") or {})
    if not idp.get("entityId"):
        raise SamlTrustError("the IdP metadata declares no entityID")
    if not (idp.get("singleSignOnService") or {}).get("url"):
        raise SamlTrustError("the IdP metadata declares no HTTP-Redirect SingleSignOnService")
    if not (idp.get("x509cert") or idp.get("x509certMulti")):
        # Without a certificate there is nothing to verify a signature
        # against, and `strict` mode would refuse every assertion later with
        # a message about the response rather than about the configuration.
        raise SamlTrustError("the IdP metadata publishes no signing certificate")
    return idp


async def fetch_idp_metadata(url: str) -> str:
    """Fetch a metadata document over HTTP, through the SSRF guard.

    The URL is supplied by a tenant administrator through
    `POST /sso-connections`, and this service fetches it, so it is exactly
    the shape the guard exists for: a loopback or link-local target would
    make the SSO configuration form a reader of this host's own metadata
    service.
    """
    cached = _metadata_cache.get(url)
    if cached and (time.monotonic() - cached[0]) < _METADATA_TTL_SECONDS:
        return cached[1]

    try:
        validate_outbound_url(url)
    except SSRFError as exc:
        raise SamlTrustError(f"the connection's metadata_url is not allowed: {exc}") from exc

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.get(url, headers={"Accept": "application/samlmetadata+xml, application/xml"})
            response.raise_for_status()
            if len(response.content) > _MAX_METADATA_BYTES:
                raise SamlTrustError("the metadata document at the connection's metadata_url is implausibly large")
            body = response.text
    except SamlTrustError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SamlTrustError(f"the connection's metadata_url could not be fetched: {exc}") from exc

    _metadata_cache[url] = (time.monotonic(), body)
    return body


async def idp_settings_for_connection(connection: dict[str, Any]) -> dict[str, Any]:
    """The `idp` block this connection's own configuration declares.

    `metadata_xml` wins over `metadata_url`: a document pasted into the
    console is the operator's explicit statement of the trust material,
    and should not be silently replaced by whatever a URL serves today.
    """
    xml = (connection.get("metadata_xml") or "").strip()
    if not xml:
        url = (connection.get("metadata_url") or "").strip()
        if not url:
            raise SamlTrustError(
                "this SAML connection carries neither metadata_xml nor metadata_url, so there is "
                "no identity provider to trust. Add one with PUT /api/v1/sso-connections/{id}."
            )
        xml = await fetch_idp_metadata(url)
    # The connection's `issuer` is the entity id an administrator claimed.
    # Passing it through means a federation document describing several
    # providers resolves to the one this connection is for.
    return parse_idp_metadata(xml, entity_id=(connection.get("issuer") or None) or None)


async def resolve_saml_connection(db: AsyncSession, *, issuer: str | None = None) -> dict[str, Any] | None:
    """The enabled SAML connection for *issuer*, or the only one there is.

    `issuer` is `None` on `/login`, which the console links to without one:
    a deployment with a single SAML connection has an unambiguous answer
    and should not make an operator paste an entity id into a login link.
    With more than one and no issuer the answer is `None` rather than a
    guess, because picking an arbitrary identity provider for somebody's
    sign-in is worse than refusing.
    """
    try:
        rows = (
            (
                await db.execute(
                    text("""
                    SELECT id, tenant_id, issuer, display_name, metadata_url, metadata_xml
                      FROM aisoc_sso_connections
                     WHERE provider = 'saml' AND enabled = TRUE
                       AND (:i IS NULL OR issuer = :i)
                     ORDER BY created_at
                     LIMIT 2
                """).bindparams(i=issuer)
                )
            )
            .mappings()
            .all()
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("saml.connection_lookup_failed error=%s", _sanitize(exc))
        return None

    if not rows:
        return None
    if len(rows) > 1:
        logger.warning(
            "saml.ambiguous_connection count>1 issuer=%s - link the login button to /auth/saml/login?issuer=<entity id>",
            _sanitize(issuer or "<unset>"),
        )
        return None
    return dict(rows[0])


def issuer_from_saml_response(saml_response_b64: str) -> str | None:
    """The `<Issuer>` an unverified SAML response names.

    A **lookup key only**, and the distinction is the whole security
    argument: it selects which connection's certificate the signature is
    then checked against, and an assertion naming an issuer whose key the
    sender does not hold fails that check. Nothing here is trusted; it
    decides what to distrust it against.
    """
    try:
        raw = base64.b64decode(saml_response_b64, validate=False)
    except (binascii.Error, ValueError):
        return None

    from onelogin.saml2.xml_utils import OneLogin_Saml2_XML  # noqa: PLC0415

    try:
        tree = OneLogin_Saml2_XML.to_etree(raw)
    except Exception:  # noqa: BLE001 - a response we cannot parse names no issuer
        return None

    namespaces = {
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    }
    # The response-level Issuer first, then the assertion's: a provider may
    # sign only the assertion and omit the outer element.
    for path in ("/samlp:Response/saml:Issuer", "/samlp:Response/saml:Assertion/saml:Issuer"):
        found = tree.xpath(path, namespaces=namespaces)
        if found and (found[0].text or "").strip():
            return str(found[0].text).strip()
    return None


def environment_idp_settings() -> dict[str, Any]:
    """The pre-4.1 environment-variable IdP block.

    Kept as a fallback so a deployment that configured SAML through the
    environment before connections were readable keeps working across the
    upgrade. It is not the path a new deployment takes, and
    `saml_trust_source()` reports which one answered so an operator can
    tell.
    """
    return {
        "entityId": os.getenv("SAML_IDP_ENTITY_ID", ""),
        "singleSignOnService": {
            "url": os.getenv("SAML_IDP_SSO_URL", ""),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "singleLogoutService": {
            "url": os.getenv("SAML_IDP_SLO_URL", ""),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "x509cert": os.getenv("SAML_IDP_CERT", "").replace("\\n", "\n"),
    }


def environment_idp_is_configured() -> bool:
    env = environment_idp_settings()
    return bool(env["entityId"] and env["singleSignOnService"]["url"] and env["x509cert"])


__all__ = [
    "SamlTrustError",
    "environment_idp_is_configured",
    "environment_idp_settings",
    "fetch_idp_metadata",
    "idp_settings_for_connection",
    "issuer_from_saml_response",
    "parse_idp_metadata",
    "resolve_saml_connection",
]
