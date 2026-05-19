"""Hosted OAuth one-click connector flow.

Workstream 2 of the AI Stack & Data Integration plan. This module owns the
two endpoints that turn the ``OAuthHints`` scaffolding (already present on
every provider that supports it) into a real "Click 'Connect with Okta',
done" UX.

Endpoint contract
-----------------

* ``GET /api/v1/oauth/start``
    Operator clicks "Connect with <provider>" in the wizard. We mint a
    32-byte URL-safe ``state`` nonce, persist it with all the threading
    context we'll need on callback (tenant, user, connector_type, optional
    connector_id for re-auth, optional PKCE verifier), and 302 the browser
    to the provider's authorize URL.

    Tenant must have already registered an OAuth app for this connector
    class via ``PUT /api/v1/oauth/app/{connector_type}``. We refuse to
    bake in a single shared client_id — that's how SaaS providers get
    revoked at scale.

* ``GET /api/v1/oauth/callback``
    Provider 302s back here with ``?code=…&state=…``. We:

    1. Look up the row in ``oauth_states`` (single-use, expires after
       10 min). If absent / expired, refuse — this is the CSRF gate.
    2. Resolve the tenant's OAuth app credentials.
    3. POST to the provider's token endpoint to swap ``code`` for an
       access_token + refresh_token.
    4. Encrypt both into the connector's ``auth_config`` via the credential
       vault (same path the wizard uses for pasted secrets), set
       ``oauth_provisioned=True`` so Workstream 5's auto-refresh worker
       knows it owns rotation, and either INSERT a new connector row or
       UPDATE an existing one.
    5. Delete the state row (single-use defence in depth).
    6. 302 the operator to ``return_to`` so /onboarding's
       verify-data-flowing screen lights up.

* ``GET / PUT /api/v1/oauth/app/{connector_type}``
    Per-tenant OAuth client management. The PUT body carries client_id +
    client_secret (encrypted-at-rest via the vault). The GET projects
    only ``has_secret: bool`` so an admin can audit that the credential
    is wired without leaking it back to the browser.

Why this lives in services/api
------------------------------

The connectors microservice is intentionally stateless — it owns
``test_connection()`` for each provider but not Postgres. OAuth state
nonces *and* the post-callback connector row update both touch
Postgres, so we keep the whole flow inside the API service. The actual
HTTP bounce to the provider is just an ``httpx`` call; no microservice
hop is needed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import quote, urlencode, urlparse, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.connectors import _validate_connector_type
from app.core.config import settings
from app.core.logging import safe_log_value
from app.models.connector import Connector
from app.models.oauth import OAuthAppCredential, OAuthState
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oauth", tags=["oauth"])


# --------------------------------------------------------------- constants

# Same regex used in connectors.py — we don't want a hostile state row
# ever embedding path traversal / log injection in connector_type.
_CONNECTOR_TYPE_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,100}$")

# OAuth state TTL. The plan calls it 10 minutes; that's tight enough that
# a stolen state cookie is useless before it expires, loose enough that a
# corporate SSO redirect to a long-running consent screen doesn't trip
# over its own laces.
_STATE_TTL = timedelta(minutes=10)

# Providers that mandate PKCE in their 3LO flow. We default to "off"
# because most enterprise OAuth (Okta, Azure AD, Google Workspace) is
# happy with client_secret-only confidential clients, but we always
# generate a PKCE verifier when the provider requires it.
_PKCE_REQUIRED: set[str] = {
    # Atlassian Cloud (Jira / Confluence) requires PKCE for 3LO.
    "jira",
    "confluence",
    "atlassian",
}

# Allow-list of OAuth provider hostnames we will redirect operators to.
#
# CodeQL (py/url-redirection) correctly flags ``RedirectResponse(url=...)``
# when the URL traces back to a database column the tenant can edit
# (``OAuthAppCredential.authorize_url`` / ``token_url``). We close that
# attack surface by *intersecting* the resolved authorize/token URL with
# this allow-list of well-known hostname suffixes — even if a hostile
# tenant admin pastes ``https://attacker.com`` into the OAuth app row,
# we refuse to bounce the operator there. The list is keyed off the
# real authorize/token endpoints documented by each provider whose
# connector ships ``OAuthHints`` (see services/connectors/app/connectors/).
_OAUTH_PROVIDER_HOST_SUFFIXES: tuple[str, ...] = (
    # Atlassian Cloud (Jira / Confluence) 3LO
    "auth.atlassian.com",
    # Auth0 (per-tenant subdomain, e.g. ``acme.auth0.com``)
    ".auth0.com",
    # Microsoft Entra ID / Azure AD / M365 / Defender / Activity / Graph
    "login.microsoftonline.com",
    "login.microsoft.com",
    # Cloudflare dashboard SSO
    "dash.cloudflare.com",
    # GCP / Google Workspace / Gmail / SCC / Cloud Audit
    "accounts.google.com",
    "oauth2.googleapis.com",
    # GitHub
    "github.com",
    # Okta (per-tenant subdomain, e.g. ``acme.okta.com``) and preview tier
    ".okta.com",
    ".oktapreview.com",
    # Salesforce login surface (production + sandbox)
    "login.salesforce.com",
    "test.salesforce.com",
    ".my.salesforce.com",
    # Slack
    "slack.com",
    # Tailscale
    "login.tailscale.com",
)


def _is_allowed_oauth_host(host: str) -> bool:
    """Return ``True`` when ``host`` matches an allow-listed OAuth provider.

    Suffix matches starting with ``.`` (e.g. ``.okta.com``) accept any
    single-or-multi-label subdomain. Exact entries (e.g.
    ``login.microsoftonline.com``) match the host verbatim. We compare
    case-insensitively because hostnames are case-insensitive per RFC 3986.
    """
    if not host:
        return False
    host_lc = host.lower()
    for suffix in _OAUTH_PROVIDER_HOST_SUFFIXES:
        suffix_lc = suffix.lower()
        if suffix_lc.startswith("."):
            if host_lc.endswith(suffix_lc) and len(host_lc) > len(suffix_lc):
                return True
        elif host_lc == suffix_lc:
            return True
    return False


def _validated_provider_url(url: str, *, kind: str) -> str:
    """Return ``url`` unchanged after enforcing the OAuth host allow-list.

    Raises ``HTTPException(400)`` for any of:
      * non-HTTPS scheme — providers reject http:// authorize URLs anyway,
        and refusing them here closes a downgrade vector;
      * embedded credentials (``user:pass@host``) — these can hide a
        hostile origin behind a benign-looking prefix;
      * a host that does not match :data:`_OAUTH_PROVIDER_HOST_SUFFIXES`.

    ``kind`` is interpolated into the error detail so the operator knows
    whether to fix the authorize_url or the token_url field.
    """
    parsed = urlparse(url)
    scheme_ok = parsed.scheme == "https"
    host = parsed.hostname or ""
    no_userinfo = not parsed.username and not parsed.password
    if not (scheme_ok and host and no_userinfo and _is_allowed_oauth_host(host)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Refusing to use OAuth {kind} URL: host is not on the "
                "allow-list of trusted OAuth providers. Update the OAuth "
                "app row to point at the documented provider endpoint."
            ),
        )
    return url


# Some providers expect extra non-standard query params on the authorize
# URL. We thread these through ``OAuthHints``-derived defaults plus
# per-provider overrides keyed by connector_type.
_AUTHORIZE_EXTRA_PARAMS: dict[str, dict[str, str]] = {
    # Atlassian 3LO needs ``audience=api.atlassian.com`` and ``prompt=consent``
    # to surface the consent screen + return a refresh_token.
    "jira": {"audience": "api.atlassian.com", "prompt": "consent"},
    # Google requires access_type=offline + prompt=consent to mint a
    # refresh_token on second-and-subsequent connects from the same user.
    "google_workspace": {"access_type": "offline", "prompt": "consent"},
    # Microsoft Graph wants response_mode=query for consistency with
    # other providers; ``offline_access`` scope (set in OAuthHints) is
    # what actually triggers refresh_token issuance.
    "azure_entra": {"response_mode": "query"},
    "m365_audit": {"response_mode": "query"},
}


# --------------------------------------------------------------- helpers


def _safe_log_val(value: object) -> str:
    """Local alias for the canonical :func:`safe_log_value` helper.

    Kept as a thin wrapper so existing call sites stay untouched while the
    underlying implementation defends against CWE-117 (log injection) by
    escaping CR/LF/NUL/ESC and truncating overly long user-controlled
    values. Routes through :func:`app.core.logging.safe_log_value` so
    every service uses the same sanitisation contract.
    """
    return safe_log_value(value)


def _safe_connector_type(value: str) -> str:
    if not _CONNECTOR_TYPE_RE.match(value or ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="connector_type must be alphanumeric (with - and _)",
        )
    return value


async def _fetch_catalog_entry(connector_type: str) -> dict[str, Any]:
    """Resolve the connector's catalog entry (with OAuthHints) or 422.

    Reuses :func:`_validate_connector_type` so we share one source of
    truth with the wizard's POST flow — the catalog ships the
    ``category`` we'll use on insert + the ``oauth`` hints (authorize
    URL, token URL, scopes) we need for the redirect dance.
    """
    return await _validate_connector_type(connector_type)


def _hints_from_catalog(catalog_entry: dict[str, Any]) -> dict[str, Any]:
    """Pull the ``oauth`` block from a catalog entry (empty when absent)."""
    hints = catalog_entry.get("oauth") or {}
    return hints if isinstance(hints, dict) else {}


def _resolve_redirect_uri() -> str:
    """The exact redirect_uri the tenant must pre-register with the provider.

    Providers reject mismatched redirect_uris for good reason — it's the
    only field that lets them defend against an open-redirect-style
    abuse of their OAuth flow. So we serve a single canonical URL per
    deployment. ``OAUTH_PUBLIC_BASE_URL`` is what operators set in their
    ``.env``; empty disables the flow entirely (start endpoint 503s).
    """
    base = (settings.OAUTH_PUBLIC_BASE_URL or "").rstrip("/")
    if not base:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Hosted OAuth is not configured. Operator must set "
                "OAUTH_PUBLIC_BASE_URL to the public URL of this API "
                "service (e.g. https://api.tryaisoc.com)."
            ),
        )
    return f"{base}/api/v1/oauth/callback"


def _resolve_console_base() -> str:
    """Public base URL of the console for default ``return_to`` redirects."""
    return (settings.CONSOLE_PUBLIC_BASE_URL or "").rstrip("/")


def _validate_return_to(return_to: str | None) -> str:
    """Allow only same-origin (or relative) redirects after callback.

    Critical: if we let the operator pass any URL, a hostile authorize
    flow can steer them to ``return_to=https://attacker.com`` and
    weaponise the OAuth round-trip into a phishing redirect. We accept
    only:
      * Pure paths starting with ``/`` (e.g. ``/onboarding``).
      * Absolute URLs whose origin matches ``CONSOLE_PUBLIC_BASE_URL``.

    Every accepted branch *reconstructs* the URL from validated
    components via ``urlunsplit`` + ``quote`` rather than returning
    the caller's string verbatim. That's the canonical taint break
    CodeQL recognises for ``py/url-redirection`` — it cannot reason
    about ``startswith`` allowlists alone, but it does know that
    rebuilding a URL from individually-quoted parts removes the
    open-redirect class entirely.
    """
    default = "/onboarding"
    if not return_to:
        return default

    parsed = urlsplit(return_to)
    # Path-only (relative) navigation inside the console.
    if not parsed.scheme and not parsed.netloc and parsed.path.startswith("/") and not parsed.path.startswith("//"):
        # ``safe`` keeps URL-meaningful chars; everything else gets
        # percent-encoded, which both hardens the value and gives
        # CodeQL a sanitizer it tracks.
        safe_path = quote(parsed.path, safe="/-._~")
        safe_query = quote(parsed.query, safe="=&-._~")
        safe_fragment = quote(parsed.fragment, safe="-._~")
        return urlunsplit(("", "", safe_path, safe_query, safe_fragment))

    base = _resolve_console_base()
    if base:
        base_parsed = urlsplit(base)
        # Same-origin absolute URL: rebuild from the base scheme/host
        # we trust, plus the path/query/fragment of the input — never
        # echo the raw string. The host check below also guarantees
        # the origin matches before we reconstruct.
        if (
            parsed.scheme == base_parsed.scheme
            and parsed.netloc == base_parsed.netloc
            and (parsed.path == "" or (parsed.path.startswith("/") and not parsed.path.startswith("//")))
        ):
            safe_path = quote(parsed.path or "/", safe="/-._~")
            safe_query = quote(parsed.query, safe="=&-._~")
            safe_fragment = quote(parsed.fragment, safe="-._~")
            return urlunsplit(
                (
                    base_parsed.scheme,
                    base_parsed.netloc,
                    safe_path,
                    safe_query,
                    safe_fragment,
                )
            )

    logger.info(
        "oauth.return_to.rejected",
        extra={
            "raw": _safe_log_val(return_to),
            "falling_back_to": default,
        },
    )
    return default


def _pkce_pair() -> tuple[str, str]:
    """Generate an RFC 7636 PKCE (verifier, S256 challenge) pair."""
    verifier = secrets.token_urlsafe(64)[:128]  # 43..128 chars per RFC
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


async def _resolve_oauth_app(
    db,
    tenant_id: uuid.UUID,
    connector_type: str,
) -> OAuthAppCredential:
    """Fetch the tenant's OAuth app row or 404.

    404s when the tenant hasn't registered an app yet — the wizard will
    redirect to a "register your OAuth app" step.
    """
    app_row = await db.execute(
        select(OAuthAppCredential).where(
            OAuthAppCredential.tenant_id == tenant_id,
            OAuthAppCredential.connector_type == connector_type,
        )
    )
    app_credential: OAuthAppCredential | None = app_row.scalar_one_or_none()
    if app_credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No OAuth app registered for connector_type={connector_type}. "
                f"Register one via PUT /api/v1/oauth/app/{connector_type} "
                "before starting the hosted OAuth flow."
            ),
        )
    return app_credential


def _resolve_authorize_url(
    app_credential: OAuthAppCredential,
    hints: dict[str, Any],
) -> str:
    """Per-tenant override beats schema hint beats hard error.

    The returned URL is also passed through :func:`_validated_provider_url`
    which enforces the OAuth host allow-list. This closes the open-redirect
    surface flagged by CodeQL ``py/url-redirection`` at the redirect call
    site: even if a tenant admin pastes a hostile authorize URL into the
    OAuth app row, we refuse to bounce the operator there.
    """
    url = (app_credential.authorize_url or hints.get("authorize_url") or "").strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Connector schema does not advertise an authorize_url and "
                "tenant did not override it. Edit the OAuth app row to "
                "supply authorize_url."
            ),
        )
    return _validated_provider_url(url, kind="authorize")


def _resolve_token_url(
    app_credential: OAuthAppCredential,
    hints: dict[str, Any],
) -> str:
    """Resolve the OAuth ``token_url`` with the same allow-list guard.

    See :func:`_resolve_authorize_url` for the allow-list rationale. The
    token endpoint is server-to-server (not a redirect), but applying the
    same check defends against a hostile tenant admin redirecting our
    backchannel ``client_secret`` POST to an attacker-controlled host.
    """
    url = (app_credential.token_url or hints.get("token_url") or "").strip()
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=("Connector schema does not advertise a token_url and tenant did not override it."),
        )
    return _validated_provider_url(url, kind="token")


def _resolve_scopes(
    app_credential: OAuthAppCredential,
    hints: dict[str, Any],
) -> list[str]:
    if app_credential.scopes:
        return list(app_credential.scopes)
    raw = hints.get("scopes") or []
    return [str(s) for s in raw if s]


# --------------------------------------------------------------- request models


class OAuthAppRegistration(BaseModel):
    """Payload for ``PUT /api/v1/oauth/app/{connector_type}``."""

    client_id: str = Field(min_length=1, max_length=512)
    client_secret: str = Field(min_length=1, max_length=4096)
    authorize_url: str | None = Field(default=None, max_length=512)
    token_url: str | None = Field(default=None, max_length=512)
    scopes: list[str] | None = Field(default=None, max_length=64)


class OAuthAppView(BaseModel):
    """Read-only projection of an :class:`OAuthAppCredential`.

    Never round-trips the secret — only ``has_secret: bool`` so the UI
    can render a "credential present, last updated X days ago" badge.
    """

    connector_type: str
    client_id: str
    has_secret: bool
    authorize_url: str | None
    token_url: str | None
    scopes: list[str] | None
    created_at: datetime
    updated_at: datetime


class OAuthStartResponse(BaseModel):
    """Returned when the caller asks for JSON instead of a 302.

    Useful for SPAs that want to handle the redirect themselves.
    """

    authorize_url: str
    state: str


# --------------------------------------------------------------- OAuth app management


@router.get("/app/{connector_type}", response_model=OAuthAppView)
async def get_oauth_app(
    connector_type: str,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> OAuthAppView:
    """Return the tenant's registered OAuth app (without the secret)."""
    safe_type = _safe_connector_type(connector_type)
    res = await db.execute(
        select(OAuthAppCredential).where(
            OAuthAppCredential.tenant_id == current_user.tenant_id,
            OAuthAppCredential.connector_type == safe_type,
        )
    )
    row: OAuthAppCredential | None = res.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No OAuth app registered for this connector_type",
        )
    return OAuthAppView(
        connector_type=row.connector_type,
        client_id=row.client_id,
        has_secret=bool(row.client_secret_vault),
        authorize_url=row.authorize_url,
        token_url=row.token_url,
        scopes=list(row.scopes) if row.scopes else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.put("/app/{connector_type}", response_model=OAuthAppView)
async def upsert_oauth_app(
    connector_type: str,
    payload: OAuthAppRegistration,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> OAuthAppView:
    """Register or rotate the tenant's OAuth client for this connector class."""
    safe_type = _safe_connector_type(connector_type)
    try:
        encrypted_secret = get_vault().encrypt(payload.client_secret)
    except CredentialVaultError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to encrypt OAuth client secret",
        ) from exc

    res = await db.execute(
        select(OAuthAppCredential).where(
            OAuthAppCredential.tenant_id == current_user.tenant_id,
            OAuthAppCredential.connector_type == safe_type,
        )
    )
    existing: OAuthAppCredential | None = res.scalar_one_or_none()
    now = datetime.now(UTC)
    if existing is None:
        row = OAuthAppCredential(
            tenant_id=current_user.tenant_id,
            connector_type=safe_type,
            client_id=payload.client_id,
            client_secret_vault=encrypted_secret,
            authorize_url=payload.authorize_url,
            token_url=payload.token_url,
            scopes=payload.scopes,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
    else:
        existing.client_id = payload.client_id
        existing.client_secret_vault = encrypted_secret
        existing.authorize_url = payload.authorize_url
        existing.token_url = payload.token_url
        existing.scopes = payload.scopes
        existing.updated_at = now
        row = existing
    await db.commit()
    await db.refresh(row)

    logger.info(
        "oauth.app.upsert",
        extra={
            "tenant": current_user.tenant_id,
            "connector_type": _safe_log_val(safe_type),
            "created": existing is None,
        },
    )
    return OAuthAppView(
        connector_type=row.connector_type,
        client_id=row.client_id,
        has_secret=bool(row.client_secret_vault),
        authorize_url=row.authorize_url,
        token_url=row.token_url,
        scopes=list(row.scopes) if row.scopes else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.delete("/app/{connector_type}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_oauth_app(
    connector_type: str,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> None:
    """Unregister the tenant's OAuth app for this connector class."""
    safe_type = _safe_connector_type(connector_type)
    await db.execute(
        delete(OAuthAppCredential).where(
            OAuthAppCredential.tenant_id == current_user.tenant_id,
            OAuthAppCredential.connector_type == safe_type,
        )
    )
    await db.commit()
    logger.info(
        "oauth.app.delete",
        extra={
            "tenant": current_user.tenant_id,
            "connector_type": _safe_log_val(safe_type),
        },
    )


# --------------------------------------------------------------- /oauth/start


@router.get("/start")
async def oauth_start(
    connector_type: Annotated[str, Query(description="Connector class to OAuth into")],
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
    connector_id: Annotated[uuid.UUID | None, Query(description="Re-auth target; omit to mint a new connector")] = None,
    return_to: Annotated[str | None, Query(description="Where to land after callback (defaults to /onboarding)")] = None,
    name: Annotated[str | None, Query(description="Operator-supplied display name for new connectors")] = None,
    extras: Annotated[str | None, Query(description="JSON dict of provider-specific extras (e.g. organization for GitHub)")] = None,
    response_mode: Annotated[str, Query(pattern=r"^(redirect|json)$")] = "redirect",
):
    """Mint a state nonce and bounce the operator to the provider's authorize URL."""
    safe_type = _safe_connector_type(connector_type)
    redirect_uri = _resolve_redirect_uri()  # 503s if not configured

    # Validate against the live catalog (defense in depth — same gate
    # the POST /connectors path uses) and pull OAuth hints in one shot.
    catalog_entry = await _fetch_catalog_entry(safe_type)
    hints = _hints_from_catalog(catalog_entry)

    # Schema is the source of truth for whether hosted OAuth is wired
    # for this provider. supported_in_hosted=False (or missing) means
    # the connector's class hasn't opted into the flow yet.
    if not bool(hints.get("supported_in_hosted")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Connector {safe_type} has not opted into hosted OAuth.",
        )

    app_credential = await _resolve_oauth_app(db, current_user.tenant_id, safe_type)

    # Parse extras JSON safely; reject anything that's not a flat dict.
    extras_payload: dict[str, Any] = {}
    if extras:
        try:
            parsed = json.loads(extras)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"extras must be valid JSON: {exc}",
            ) from exc
        if not isinstance(parsed, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="extras must decode to a JSON object",
            )
        extras_payload = parsed
    if name:
        extras_payload.setdefault("display_name", name[:200])

    if connector_id is not None:
        # Re-auth path: confirm the connector exists and belongs to this
        # tenant so a hostile state row can't pivot to another tenant's
        # connector by guessing UUIDs.
        existing = await db.execute(
            select(Connector).where(
                Connector.id == connector_id,
                Connector.tenant_id == current_user.tenant_id,
            )
        )
        if existing.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Connector not found for re-auth",
            )

    state = secrets.token_urlsafe(32)
    needs_pkce = safe_type in _PKCE_REQUIRED
    code_verifier: str | None = None
    code_challenge: str | None = None
    if needs_pkce:
        code_verifier, code_challenge = _pkce_pair()

    state_row = OAuthState(
        state=state,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        connector_type=safe_type,
        connector_id=connector_id,
        code_verifier=code_verifier,
        extras=extras_payload,
        return_to=_validate_return_to(return_to),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + _STATE_TTL,
    )
    db.add(state_row)
    await db.commit()

    authorize_url = _resolve_authorize_url(app_credential, hints)
    scopes = _resolve_scopes(app_credential, hints)

    qs: dict[str, str] = {
        "client_id": app_credential.client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": state,
    }
    if scopes:
        qs["scope"] = " ".join(scopes)
    if needs_pkce and code_challenge:
        qs["code_challenge"] = code_challenge
        qs["code_challenge_method"] = "S256"
    qs.update(_AUTHORIZE_EXTRA_PARAMS.get(safe_type, {}))

    sep = "&" if "?" in authorize_url else "?"
    full_authorize = f"{authorize_url}{sep}{urlencode(qs, safe=':+/?#@!$&()*+,;=')}"

    # Defence in depth: the authorize_url base was already validated by
    # ``_resolve_authorize_url`` -> ``_validated_provider_url``, but we
    # re-parse the *fully composed* redirect target here so the host
    # check is locally visible at the ``RedirectResponse`` call site.
    # This also gives CodeQL (py/url-redirection) a sanitizer it can see
    # without needing inter-procedural taint tracking through helpers.
    parsed_full = urlparse(full_authorize)
    if not _is_allowed_oauth_host(parsed_full.hostname or ""):
        # Should be unreachable because _resolve_authorize_url already
        # rejected non-allowlisted hosts, but we treat any drift as a
        # 500 rather than silently redirecting somewhere unexpected.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error: composed OAuth authorize URL failed host allow-list re-check.",
        )

    logger.info(
        "oauth.start",
        extra={
            "tenant": current_user.tenant_id,
            "connector_type": _safe_log_val(safe_type),
            "reauth": connector_id is not None,
            "pkce": needs_pkce,
        },
    )

    if response_mode == "json":
        return OAuthStartResponse(authorize_url=full_authorize, state=state)
    return RedirectResponse(url=full_authorize, status_code=302)


# --------------------------------------------------------------- /oauth/callback


def _callback_error_redirect(return_to: str, code: str, detail: str) -> RedirectResponse:
    """Bounce back to the console with a structured error payload.

    We never render an error page in the API service itself — the console
    owns the operator UX, and the verify-data-flowing screen already
    knows how to surface ``oauth_error=…&oauth_message=…`` on
    /onboarding.

    ``return_to`` is re-validated here even though every caller pulls it
    from a state row that was itself sanitised at /oauth/start.  CodeQL
    cannot follow that round-trip through the database, so re-asserting
    the whitelist at the sink keeps the taint analysis quiet *and*
    closes the door on a future caller that forgets to validate.
    """
    safe_return = _validate_return_to(return_to)
    sep = "&" if "?" in safe_return else "?"
    qs = urlencode({"oauth_error": code, "oauth_message": detail[:200]})
    return RedirectResponse(url=f"{safe_return}{sep}{qs}", status_code=302)


@router.get("/callback")
async def oauth_callback(
    db: DBSession,
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
    error_description: Annotated[str | None, Query()] = None,
):
    """Handle the provider's redirect after the operator consents.

    No auth dependency: this endpoint is invoked by the *browser* after
    a third-party redirect, not by an authenticated console session.
    The CSRF defence is the ``state`` nonce, which we issued ourselves
    at /oauth/start under an authenticated session.
    """
    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing OAuth state parameter",
        )

    state_res = await db.execute(select(OAuthState).where(OAuthState.state == state))
    state_row: OAuthState | None = state_res.scalar_one_or_none()
    if state_row is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unknown or already-consumed OAuth state",
        )
    if state_row.expires_at < datetime.now(UTC):
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state has expired; restart the connector flow",
        )

    return_to = _validate_return_to(state_row.return_to)

    # Provider returned an error short of a code. Common cases: operator
    # clicked "Deny", IdP refused the scope set, redirect_uri mismatch.
    if error:
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        logger.warning(
            "oauth.callback.provider_error",
            extra={
                "tenant": state_row.tenant_id,
                "connector_type": _safe_log_val(state_row.connector_type),
                "err": _safe_log_val(error),
            },
        )
        return _callback_error_redirect(
            return_to,
            error,
            error_description or "Provider rejected the OAuth request.",
        )

    if not code:
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing authorization code on callback",
        )

    # Resolve the per-tenant OAuth app and decrypt its client_secret for
    # the token exchange. The vault round-trip is the only place we ever
    # touch the secret in cleartext.
    app_res = await db.execute(
        select(OAuthAppCredential).where(
            OAuthAppCredential.tenant_id == state_row.tenant_id,
            OAuthAppCredential.connector_type == state_row.connector_type,
        )
    )
    app_credential: OAuthAppCredential | None = app_res.scalar_one_or_none()
    if app_credential is None:
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "missing_app_credential",
            "OAuth app credential disappeared mid-flow.",
        )
    try:
        client_secret = get_vault().decrypt(app_credential.client_secret_vault)
    except CredentialVaultError as exc:
        logger.error(
            "oauth.callback.secret_decrypt_failed tenant=%s connector_type=%s err=%s",
            state_row.tenant_id,
            _safe_log_val(state_row.connector_type),
            type(exc).__name__,
        )
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "vault_failure",
            "Could not decrypt OAuth client secret; operator must rotate it.",
        )

    # Re-fetch the catalog entry on callback so we (a) get fresh OAuth
    # hints for the token exchange and (b) recover the connector category
    # to stamp on the new row — same gate as POST /connectors.
    try:
        catalog_entry = await _fetch_catalog_entry(state_row.connector_type)
    except HTTPException:
        # Connector class disappeared from the catalog between start and
        # callback (deployment in flight). Bail with a clear error.
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "connector_type_unknown",
            f"Connector type {state_row.connector_type} is no longer available.",
        )
    hints = _hints_from_catalog(catalog_entry)
    catalog_category = catalog_entry.get("category") or "uncategorized"
    token_url = _resolve_token_url(app_credential, hints)
    redirect_uri = _resolve_redirect_uri()

    body: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": app_credential.client_id,
        "client_secret": client_secret,
    }
    if state_row.code_verifier:
        body["code_verifier"] = state_row.code_verifier

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            token_resp = await client.post(
                token_url,
                data=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            token_resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # Bubble up the provider's error body to operator logs (truncated)
        # but only a generic message to the browser. The provider's body
        # is often the gotcha (e.g. "redirect_uri mismatch").
        detail = ""
        try:
            detail = exc.response.text[:512]
        except Exception:  # pragma: no cover - response.text rarely fails
            pass
        logger.warning(
            "oauth.callback.token_exchange_failed tenant=%s connector_type=%s status=%s body=%s",
            state_row.tenant_id,
            _safe_log_val(state_row.connector_type),
            exc.response.status_code,
            _safe_log_val(detail),
        )
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "token_exchange_failed",
            f"Provider returned {exc.response.status_code}.",
        )
    except httpx.HTTPError as exc:
        logger.warning(
            "oauth.callback.token_exchange_unreachable tenant=%s connector_type=%s err=%s",
            state_row.tenant_id,
            _safe_log_val(state_row.connector_type),
            type(exc).__name__,
        )
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "token_exchange_unreachable",
            "Could not reach the OAuth provider's token endpoint.",
        )

    try:
        token_payload = token_resp.json()
    except ValueError:
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "token_response_malformed",
            "Provider returned a non-JSON token response.",
        )

    access_token = token_payload.get("access_token")
    if not access_token:
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "no_access_token",
            "Provider response did not include an access_token.",
        )

    # Build the auth_config payload the connector classes already
    # understand. We always include the access_token; refresh_token /
    # expires_in are optional but cheap to thread through. Provider-
    # specific extras (Atlassian site_id, GitHub installation_id, etc.)
    # ride in connector_config so downstream pollers can read them
    # without decrypting auth_config.
    auth_payload: dict[str, Any] = {"access_token": access_token}
    if "refresh_token" in token_payload:
        auth_payload["refresh_token"] = token_payload["refresh_token"]
    if "id_token" in token_payload:
        auth_payload["id_token"] = token_payload["id_token"]
    if "token_type" in token_payload:
        auth_payload["token_type"] = token_payload["token_type"]

    # Compute an absolute expires_at so the auto-refresh worker
    # (Workstream 5) doesn't have to track when we received the token.
    expires_in = token_payload.get("expires_in")
    if isinstance(expires_in, int | float) and expires_in > 0:
        auth_payload["expires_at"] = (datetime.now(UTC) + timedelta(seconds=int(expires_in))).isoformat()

    try:
        encrypted_auth = get_vault().encrypt_dict(auth_payload)
    except CredentialVaultError as exc:
        logger.error(
            "oauth.callback.vault_encrypt_failed tenant=%s connector_type=%s err=%s",
            state_row.tenant_id,
            _safe_log_val(state_row.connector_type),
            type(exc).__name__,
        )
        await db.execute(delete(OAuthState).where(OAuthState.state == state))
        await db.commit()
        return _callback_error_redirect(
            return_to,
            "vault_failure",
            "Could not encrypt new OAuth tokens.",
        )

    connector_config = dict(state_row.extras or {})
    display_name = connector_config.pop("display_name", None) or state_row.connector_type

    if state_row.connector_id is None:
        # New connector — operator just clicked "Connect with X" for the
        # first time. We INSERT with status='configuring' and let the
        # poller flip it to 'active' on the next successful run.
        connector = Connector(
            id=uuid.uuid4(),
            tenant_id=state_row.tenant_id,
            name=display_name,
            connector_type=state_row.connector_type,
            category=catalog_category,
            auth_config=encrypted_auth,
            connector_config=connector_config,
            tags=[],
            health_status="configuring",
            oauth_provisioned=True,
            is_enabled=True,
        )
        db.add(connector)
        await db.flush()
        target_id = connector.id
    else:
        # Re-auth: rotate auth_config in place and bounce health back to
        # 'configuring' so the poller will re-test on next sweep.
        existing_res = await db.execute(
            select(Connector).where(
                Connector.id == state_row.connector_id,
                Connector.tenant_id == state_row.tenant_id,
            )
        )
        existing_connector = existing_res.scalar_one_or_none()
        if existing_connector is None:
            await db.execute(delete(OAuthState).where(OAuthState.state == state))
            await db.commit()
            return _callback_error_redirect(
                return_to,
                "connector_disappeared",
                "Connector instance disappeared mid-flow.",
            )
        connector = existing_connector
        connector.auth_config = encrypted_auth
        merged_config = dict(connector.connector_config or {})
        merged_config.update(connector_config)
        connector.connector_config = merged_config
        connector.oauth_provisioned = True
        connector.health_status = "configuring"
        target_id = connector.id

    # Single-use: delete the state row only after the connector write
    # succeeded, to keep the flow restartable on transient DB errors.
    await db.execute(delete(OAuthState).where(OAuthState.state == state))
    await db.commit()

    logger.info(
        "oauth.callback.complete tenant=%s connector_type=%s connector_id=%s reauth=%s",
        state_row.tenant_id,
        _safe_log_val(state_row.connector_type),
        target_id,
        state_row.connector_id is not None,
    )

    sep = "&" if "?" in return_to else "?"
    qs = urlencode(
        {
            "oauth_success": "1",
            "connector_id": str(target_id),
            "connector_type": state_row.connector_type,
        }
    )
    return RedirectResponse(url=f"{return_to}{sep}{qs}", status_code=302)
