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
import logging
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt as _jwt
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["auth-oidc"])

# ─── JWT helpers ──────────────────────────────────────────────────────────────

_JWT_SECRET = os.getenv("JWT_SECRET", "changeme-insecure-default")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))


def _issue_jwt(claims: dict[str, Any]) -> str:
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


# ─── In-memory state store (replace with Redis in production) ─────────────────

_state_store: dict[str, dict[str, str]] = {}


def _store_state(state: str, data: dict[str, str]) -> None:
    _state_store[state] = data


def _pop_state(state: str) -> dict[str, str] | None:
    return _state_store.pop(state, None)


_SAFE_REDIRECT_RE = re.compile(r"^/[\w\-./]*$")


def _safe_redirect(url: str) -> str:
    """Return *url* only if it is a safe relative path; otherwise return '/'."""
    if url and _SAFE_REDIRECT_RE.match(url):
        return url
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
        # Stub mode
        logger.warning("OIDC not configured (OIDC_ISSUER / OIDC_CLIENT_ID missing) — issuing stub token")
        token = _issue_jwt({"sub": "oidc-stub-user", "email": "oidc@stub.local", "provider": "oidc-stub"})
        resp = RedirectResponse(url=safe_redirect, status_code=302)
        resp.set_cookie("aisoc_token", token, httponly=True, samesite="lax")
        return resp

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

    _store_state(state, state_data)

    auth_url = provider["authorization_endpoint"] + "?" + urlencode(params)
    response = RedirectResponse(url=auth_url)
    response.set_cookie("oidc_state", state, httponly=True, samesite="lax", max_age=600)
    return response


@router.get("/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    error: str | None = Query(None),
) -> Response:
    """Handle OIDC authorization code callback and issue JWT."""
    if error:
        raise HTTPException(status_code=400, detail=f"OIDC error: {error}")

    state_data = _pop_state(state)
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

    # Decode id_token (no signature verification here — use provider JWKS in production)
    id_token = tokens.get("id_token", "")
    claims: dict[str, Any] = {}
    if id_token:
        try:
            claims = _jwt.decode(id_token, options={"verify_signature": False})
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to decode id_token claims: %s", exc)

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
    token = _issue_jwt(
        {
            "sub": merged.get("sub", ""),
            "email": merged.get("email", ""),
            "name": merged.get("name", ""),
            "picture": merged.get("picture", ""),
            "provider": "oidc",
            "iss_upstream": issuer,
        }
    )

    redirect_url = state_data.get("redirect", "/")
    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie("aisoc_token", token, httponly=True, samesite="lax", secure=request.url.scheme == "https")
    response.delete_cookie("oidc_state")
    return response


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
            if end_session:
                params = urlencode({"post_logout_redirect_uri": safe_uri})
                response = RedirectResponse(url=f"{end_session}?{params}", status_code=302)
                response.delete_cookie("aisoc_token")
        except Exception as exc:  # noqa: BLE001
            logger.debug("OIDC end_session discovery failed, falling back to local logout: %s", exc)

    return response
