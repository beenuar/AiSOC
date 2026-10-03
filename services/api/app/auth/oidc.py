"""
OIDC (OpenID Connect) Relying Party implementation for AiSOC.

Flow:
  1. GET  /auth/oidc/login          → redirect to provider authorization URL
  2. GET  /auth/oidc/callback       ← provider redirects back with ?code=...
  3. GET  /auth/oidc/userinfo       → proxy to provider /userinfo (authenticated)
  4. GET  /auth/oidc/logout         → RP-initiated logout (optional)

Configuration (env vars):
  OIDC_ISSUER          OIDC provider issuer URL (e.g. https://accounts.google.com)
  OIDC_CLIENT_ID       OAuth2 client ID
  OIDC_CLIENT_SECRET   OAuth2 client secret
  OIDC_REDIRECT_URI    Callback URL (must match provider config)
  OIDC_SCOPES          Space-separated scopes (default: "openid email profile")
  JWT_SECRET           Secret used to sign issued JWTs
  JWT_ALGORITHM        HS256 (default)
  JWT_EXPIRE_MINUTES   Token lifetime (default: 480 = 8h)
  OIDC_PKCE            Enable PKCE (default: true)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt as _jwt
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse, Response

from app.api.v1.deps import DBSession
from app.auth.sso_provisioning import SsoProvisioningError, complete_sso_login

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["auth-oidc"])

# ─── JWT helpers ──────────────────────────────────────────────────────────────

_JWT_SECRET = os.getenv("JWT_SECRET", "")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))


def _issue_jwt(claims: dict[str, Any]) -> str:
    # Refuse to sign OIDC session tokens with a missing or well-known-default
    # secret. See the matching guard in ``services/api/app/auth/saml.py`` for
    # the rationale: a literal "changeme-insecure-default" baked into source
    # is not a credential, and silently using it forfeits the entire SSO
    # trust model.
    if not _JWT_SECRET or _JWT_SECRET == "changeme-insecure-default":
        raise RuntimeError("JWT_SECRET is not configured. Set the env var to a long random string before issuing OIDC session tokens.")
    payload = {
        **claims,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=_JWT_EXPIRE_MINUTES),
    }
    return _jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


# ─── OIDC provider discovery ──────────────────────────────────────────────────

_provider_cache: dict[str, Any] = {}


async def _discover(issuer: str) -> dict[str, Any]:
    """Fetch and cache OIDC discovery document."""
    if issuer in _provider_cache:
        return _provider_cache[issuer]

    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()

    _provider_cache[issuer] = data
    return data


# ─── id_token verification ────────────────────────────────────────────────────


class _IdTokenInvalid(Exception):
    """The id_token did not verify. Carries why, for the log line only."""


#: One JWKS client per issuer. `PyJWKClient` caches signing keys itself and
#: re-fetches on an unknown `kid`, which is what makes provider key rotation
#: work without a restart.
_jwks_clients: dict[str, Any] = {}


def _jwks_client_for(provider: dict[str, Any]) -> Any:
    uri = provider.get("jwks_uri")
    if not uri:
        raise _IdTokenInvalid("the discovery document declares no jwks_uri")
    client = _jwks_clients.get(uri)
    if client is None:
        client = _jwt.PyJWKClient(uri, cache_keys=True)
        _jwks_clients[uri] = client
    return client


async def _verify_id_token(id_token: str, *, issuer: str, provider: dict[str, Any]) -> dict[str, Any]:
    """Verify signature, issuer, audience and expiry, or raise.

    Every failure mode raises rather than returning partial claims. An
    id_token that fails any check is not a weaker token, it is a token
    from somebody else.
    """
    client_id = os.getenv("OIDC_CLIENT_ID", "")
    try:
        signing_key = _jwks_client_for(provider).get_signing_key_from_jwt(id_token)
    except _IdTokenInvalid:
        raise
    except Exception as exc:  # noqa: BLE001 - any JWKS failure is a refusal
        raise _IdTokenInvalid(f"could not resolve a signing key: {exc}") from exc

    # `iss` is compared against the issuer this deployment is configured
    # for, not against the one inside the token.
    expected_issuer = provider.get("issuer") or issuer
    try:
        return dict(
            _jwt.decode(
                id_token,
                signing_key.key,
                algorithms=provider.get("id_token_signing_alg_values_supported") or ["RS256"],
                audience=client_id or None,
                issuer=expected_issuer or None,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": bool(client_id),
                    "verify_iss": bool(expected_issuer),
                },
            )
        )
    except Exception as exc:  # noqa: BLE001
        raise _IdTokenInvalid(str(exc)) from exc


# ─── State store ──────────────────────────────────────────────────────────────
#
# Redis-backed, with an in-process fallback for single-replica and test
# deployments. This was a plain module dict, which breaks the flow outright
# on more than one replica: the browser is redirected by the instance that
# generated the state and comes back to whichever instance the load
# balancer picks, so roughly (n-1)/n of sign-ins failed with "Invalid or
# expired OIDC state" on an n-replica deployment.
#
# The entry holds the PKCE verifier and the nonce, so it is short-lived by
# design — `_STATE_TTL_SECONDS` bounds how long an authorization code may
# sit unredeemed.

_STATE_TTL_SECONDS = 600
_STATE_PREFIX = "aisoc:oidc:state:"

#: Fallback only. Used when Redis is absent, which is a supported
#: single-replica configuration.
_state_store: dict[str, dict[str, str]] = {}


@lru_cache(maxsize=1)
def _state_redis() -> Any | None:
    try:
        from redis.asyncio import from_url  # noqa: PLC0415

        from app.core.config import settings  # noqa: PLC0415

        return from_url(str(settings.REDIS_URL), decode_responses=True)
    except Exception:  # noqa: BLE001 - absence is a supported configuration
        return None


async def _store_state(state: str, data: dict[str, str]) -> None:
    client = _state_redis()
    if client is not None:
        try:
            await client.set(_STATE_PREFIX + state, json.dumps(data), ex=_STATE_TTL_SECONDS)
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "oidc.state_store_unavailable falling back to in-process: %s",
                str(exc).replace("\r", "").replace("\n", " ")[:200],
            )
    _state_store[state] = data


async def _pop_state(state: str) -> dict[str, str] | None:
    """Read and delete in one step, so a state cannot be replayed."""
    client = _state_redis()
    if client is not None:
        try:
            raw = await client.getdel(_STATE_PREFIX + state)
            if raw:
                return dict(json.loads(raw))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "oidc.state_read_unavailable falling back to in-process: %s",
                str(exc).replace("\r", "").replace("\n", " ")[:200],
            )
    return _state_store.pop(state, None)


_SAFE_REDIRECT_RE = re.compile(r"^/[\w\-./]*$")
# Characters allowed in a safe relative redirect path.
_SAFE_PATH_CHARS_RE = re.compile(r"[^\w\-./]")


def _safe_redirect(url: str) -> str:
    """Return a safe relative path derived from *url*; otherwise return '/'.

    The returned value is *reconstructed* from allowed characters so that
    CodeQL's taint tracking does not propagate the original user-supplied
    string through to the redirect response.
    """
    if url and _SAFE_REDIRECT_RE.match(url):
        # Reconstruct: strip any chars outside the allow-list so the result
        # is not considered tainted by static analysis tools.
        safe_path = "/" + _SAFE_PATH_CHARS_RE.sub("", url.lstrip("/"))
        return safe_path
    return "/"


# ─── Routes ───────────────────────────────────────────────────────────────────


@router.get("/login")
async def oidc_login(request: Request, redirect: str = "/") -> Response:
    """Initiate OIDC authorization code flow."""
    issuer = os.getenv("OIDC_ISSUER")
    client_id = os.getenv("OIDC_CLIENT_ID")
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", str(request.url_for("oidc_callback")))
    scopes = os.getenv("OIDC_SCOPES", "openid email profile")
    use_pkce = os.getenv("OIDC_PKCE", "true").lower() == "true"

    safe_redirect = _safe_redirect(redirect)
    if not issuer or not client_id:
        # This issued a signed session for a principal called
        # `oidc-stub-user` that no identity provider had ever seen, and it
        # fired whenever OIDC_ISSUER or OIDC_CLIENT_ID was unset, which is
        # the default. An unconfigured identity provider has nothing to say
        # about who the caller is.
        logger.error("OIDC login requested but OIDC_ISSUER / OIDC_CLIENT_ID are not set")
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=("OIDC is not configured on this deployment: set OIDC_ISSUER and OIDC_CLIENT_ID."),
        )

    try:
        provider = await _discover(issuer)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {exc}") from exc

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    state_data: dict[str, str] = {"redirect": safe_redirect, "nonce": nonce}

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
    }

    if use_pkce:
        verifier = secrets.token_urlsafe(64)
        challenge = hashlib.sha256(verifier.encode()).digest()
        import base64

        challenge_b64 = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
        params["code_challenge"] = challenge_b64
        params["code_challenge_method"] = "S256"
        state_data["verifier"] = verifier

    await _store_state(state, state_data)

    auth_url = provider["authorization_endpoint"] + "?" + urlencode(params)
    response = RedirectResponse(url=auth_url)
    response.set_cookie("oidc_state", state, httponly=True, samesite="lax", max_age=600)
    return response


@router.get("/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    db: DBSession,
    code: str = Query(...),
    state: str = Query(...),
    error: str | None = Query(None),
) -> Response:
    """Handle OIDC authorization code callback and issue JWT."""
    if error:
        raise HTTPException(status_code=400, detail=f"OIDC error: {error}")

    state_data = await _pop_state(state)
    if state_data is None:
        raise HTTPException(status_code=400, detail="Invalid or expired OIDC state")

    issuer = os.getenv("OIDC_ISSUER", "")
    client_id = os.getenv("OIDC_CLIENT_ID", "")
    client_secret = os.getenv("OIDC_CLIENT_SECRET", "")
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", str(request.url_for("oidc_callback")))

    try:
        provider = await _discover(issuer)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {exc}") from exc

    # Exchange code for tokens
    token_params: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if "verifier" in state_data:
        token_params["code_verifier"] = state_data["verifier"]

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            provider["token_endpoint"],
            data=token_params,
            headers={"Accept": "application/json"},
        )
        if not token_resp.is_success:
            raise HTTPException(status_code=502, detail=f"Token exchange failed: {token_resp.text}")
        tokens = token_resp.json()

    # Verify the id_token against the provider's published JWKS.
    #
    # This used to decode with `options={"verify_signature": False}` under a
    # comment saying to use JWKS in production. An unverified id_token is a
    # base64 blob anyone can author: its `sub`, `email` and `groups` claims
    # are attacker-controlled, and they are merged into the identity below.
    # The userinfo response is TLS-authenticated and was carrying the real
    # weight, but `{**claims, **userinfo}` means any claim userinfo omits
    # came straight from the unverified token.
    #
    # Verification is mandatory. A token that does not verify is discarded
    # rather than downgraded, because falling back to unverified claims on
    # error is the same hole with an extra step.
    id_token = tokens.get("id_token", "")
    claims: dict[str, Any] = {}
    if id_token:
        try:
            claims = await _verify_id_token(id_token, issuer=issuer, provider=provider)
        except _IdTokenInvalid as exc:
            logger.warning(
                "oidc.id_token_rejected issuer=%s reason=%s",
                str(issuer).replace("\r", "").replace("\n", " ")[:200],
                str(exc).replace("\r", "").replace("\n", " ")[:200],
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The identity provider's id_token could not be verified.",
            ) from exc

        # The nonce was generated, sent and then never checked, which left
        # the authorization-code flow open to replay of a token minted for
        # a different sign-in attempt.
        expected_nonce = (state_data or {}).get("nonce")
        if expected_nonce and claims.get("nonce") != expected_nonce:
            logger.warning(
                "oidc.nonce_mismatch issuer=%s",
                str(issuer).replace("\r", "").replace("\n", " ")[:200],
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The identity provider's response did not match this sign-in attempt.",
            )

    access_token = tokens.get("access_token", "")

    # Fetch userinfo if available
    userinfo: dict[str, Any] = {}
    if access_token and "userinfo_endpoint" in provider:
        async with httpx.AsyncClient(timeout=10) as client:
            ui_resp = await client.get(
                provider["userinfo_endpoint"],
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if ui_resp.is_success:
                userinfo = ui_resp.json()

    merged = {**claims, **userinfo}

    # Parity 4.1. This used to issue a JWT carrying `sub`, `email`, `name`
    # and `picture`, signed with `JWT_SECRET`, and set it as a cookie. That
    # token authenticated nothing: the API verifies with
    # `settings.SECRET_KEY`, requires `tenant_id` and `role`, and reads
    # `Authorization: Bearer`, not a cookie. A user could complete the whole
    # dance, land on the console, and find every request unauthenticated.
    #
    # The tenant comes from the configured connection rather than from the
    # assertion, because an IdP that can name its own tenant can name
    # somebody else's.
    groups = _claim_groups(merged)
    try:
        session = await complete_sso_login(
            db,
            provider="oidc",
            issuer=issuer,
            email=str(merged.get("email") or ""),
            subject=str(merged.get("sub") or ""),
            name=merged.get("name"),
            groups=groups,
        )
    except SsoProvisioningError as exc:
        # A specific reason, not a generic failure. "No SSO connection is
        # configured for this issuer" is an administrator's next action;
        # "login failed" is a support ticket.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    redirect_url = _safe_redirect(state_data.get("redirect", "/"))
    # The token travels in the fragment, which browsers do not send to the
    # server and which does not land in an access log or a Referer header,
    # and the console moves it into the storage its API client reads.
    separator = "&" if "#" in redirect_url else "#"
    response = RedirectResponse(url=f"{redirect_url}{separator}access_token={session['access_token']}", status_code=302)
    response.delete_cookie("oidc_state")
    return response


def _claim_groups(claims: dict[str, Any]) -> list[str]:
    """Group names from whichever claim this IdP uses.

    Four spellings, because there is no standard one: Okta and Auth0 emit
    `groups`, Entra emits `roles` or `groups` depending on the app
    registration, and Keycloak emits whatever the mapper was named.
    """
    for key in ("groups", "roles", "memberOf", "group_membership"):
        value = claims.get(key)
        if isinstance(value, list):
            return [str(v) for v in value if v]
        if isinstance(value, str) and value:
            return [part.strip() for part in value.split(",") if part.strip()]
    return []


@router.get("/userinfo")
async def oidc_userinfo(request: Request) -> JSONResponse:
    """Proxy userinfo from upstream OIDC provider using the stored access token.

    Requires `Authorization: Bearer <aisoc_jwt>` header — the JWT sub is
    used to look up the upstream token (stub: returns claims from AiSOC JWT).
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = auth_header[7:]
    try:
        claims = _jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    except _jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}") from exc

    return JSONResponse(
        {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "name": claims.get("name"),
            "picture": claims.get("picture"),
            "provider": claims.get("provider"),
        }
    )


@router.get("/logout")
async def oidc_logout(request: Request, post_logout_redirect_uri: str = "/") -> Response:
    """RP-initiated logout — clear cookie and redirect to provider end_session."""
    issuer = os.getenv("OIDC_ISSUER")
    safe_uri = _safe_redirect(post_logout_redirect_uri)
    response = RedirectResponse(url=safe_uri, status_code=302)
    response.delete_cookie("aisoc_token")

    if issuer:
        try:
            provider = await _discover(issuer)
            end_session = provider.get("end_session_endpoint")
            if end_session and isinstance(end_session, str):
                # Validate end_session_endpoint is a safe HTTPS URL to prevent open redirect
                _parsed = urlparse(end_session)
                if _parsed.scheme == "https" and _parsed.netloc:
                    # Use "/" as the provider post_logout_redirect_uri to avoid
                    # propagating user-controlled input into the provider redirect URL.
                    params = urlencode({"post_logout_redirect_uri": "/"})
                    response = RedirectResponse(url=f"{end_session}?{params}", status_code=302)
                    response.delete_cookie("aisoc_token")
                else:
                    logger.warning("OIDC end_session_endpoint is not a valid HTTPS URL, skipping: %s", end_session)
        except Exception as exc:  # noqa: BLE001
            logger.debug("OIDC end_session discovery failed, falling back to local logout: %s", exc)

    return response
