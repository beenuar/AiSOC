"""
SAML 2.0 Service Provider implementation for AiSOC.

Flow:
  1. GET  /auth/saml/login          → redirect to IdP SSO URL
  2. POST /auth/saml/acs            ← IdP posts assertion here (ACS)
  3. GET  /auth/saml/metadata       → SP metadata (share with IdP)
  4. GET  /auth/saml/logout         → SLO initiation (optional)

Dependencies (optional):
  - python3-saml (onelogin/python3-saml) if available
  - Falls back to stub mode when not installed

Configuration (env vars):
  SAML_IDP_ENTITY_ID       IdP Entity ID (issuer)
  SAML_IDP_SSO_URL         IdP SSO redirect URL
  SAML_IDP_SLO_URL         IdP SLO URL (optional)
  SAML_IDP_CERT            IdP X.509 certificate (PEM, single line base64 or multi-line)
  SAML_SP_ENTITY_ID        SP Entity ID (defaults to ACS URL)
  SAML_SP_ACS_URL          Assertion Consumer Service URL
  SAML_SP_PRIVATE_KEY      SP private key PEM (optional, for signed requests)
  SAML_SP_CERT             SP certificate PEM (optional)
  JWT_SECRET               Secret used to sign issued JWTs
  JWT_ALGORITHM            HS256 (default)
  JWT_EXPIRE_MINUTES       Token lifetime (default: 480 = 8h)
"""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt as _jwt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

logger = logging.getLogger(__name__)

_SAFE_REDIRECT_RE = re.compile(r"^/[\w\-./]*$")
_SAFE_PATH_CHARS_RE = re.compile(r"[^\w\-./]")


def _safe_redirect(url: str) -> str:
    """Return a safe relative path derived from *url*; otherwise return '/'.

    The path is *reconstructed* from allowed characters so that CodeQL's
    taint tracking does not propagate the original user-supplied string
    through to the redirect response.
    """
    if url and _SAFE_REDIRECT_RE.match(url):
        safe_path = "/" + _SAFE_PATH_CHARS_RE.sub("", url.lstrip("/"))
        return safe_path
    return "/"


router = APIRouter(prefix="/auth/saml", tags=["auth-saml"])

# ─── JWT helpers ──────────────────────────────────────────────────────────────

_JWT_SECRET = os.getenv("JWT_SECRET", "")
_JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
_JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))


def _issue_jwt(claims: dict[str, Any]) -> str:
    # Refuse to mint a token signed with a missing or well-known-default
    # secret. Previously this defaulted to ``"changeme-insecure-default"``,
    # so a misconfigured deployment would happily sign session tokens with
    # a value that's literally checked into source. We now fail closed and
    # let the caller surface a 503/500 — operators must wire ``JWT_SECRET``
    # explicitly (e.g. via Fly/k8s secrets).
    if not _JWT_SECRET or _JWT_SECRET == "changeme-insecure-default":
        raise RuntimeError("JWT_SECRET is not configured. Set the env var to a long random string before issuing SAML session tokens.")
    payload = {
        **claims,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=_JWT_EXPIRE_MINUTES),
    }
    return _jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


# ─── SAML settings builder ────────────────────────────────────────────────────


def _saml_settings() -> dict[str, Any]:
    sp_acs = os.getenv("SAML_SP_ACS_URL", "http://localhost:8000/auth/saml/acs")
    sp_entity = os.getenv("SAML_SP_ENTITY_ID", sp_acs)
    sp_key = os.getenv("SAML_SP_PRIVATE_KEY", "")
    sp_cert = os.getenv("SAML_SP_CERT", "")

    idp_entity = os.getenv("SAML_IDP_ENTITY_ID", "")
    idp_sso = os.getenv("SAML_IDP_SSO_URL", "")
    idp_slo = os.getenv("SAML_IDP_SLO_URL", "")
    idp_cert = os.getenv("SAML_IDP_CERT", "").replace("\\n", "\n")

    return {
        "strict": True,
        "debug": os.getenv("SAML_DEBUG", "false").lower() == "true",
        "sp": {
            "entityId": sp_entity,
            "assertionConsumerService": {
                "url": sp_acs,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sp_acs.replace("/acs", "/slo"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "privateKey": sp_key,
            "x509cert": sp_cert,
        },
        "idp": {
            "entityId": idp_entity,
            "singleSignOnService": {
                "url": idp_sso,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": idp_slo,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": idp_cert,
        },
    }


# ─── Routes ───────────────────────────────────────────────────────────────────


@router.get("/login")
async def saml_login(request: Request, redirect: str = "/") -> Response:
    """Initiate SAML SSO — redirect to IdP."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]

        req = await _build_saml_request(request)
        auth = OneLogin_Saml2_Auth(req, _saml_settings())
        login_url: str = auth.login(return_to=redirect)
        return RedirectResponse(url=login_url)
    except ImportError:
        logger.warning("python3-saml not installed — SAML login stub active")
        return HTMLResponse(
            _stub_page("SAML Login (Stub)", "python3-saml is not installed. Configure SAML_IDP_SSO_URL and install python3-saml."),
            status_code=200,
        )
    except Exception as exc:
        logger.exception("SAML login error")
        raise HTTPException(status_code=500, detail=f"SAML error: {exc}") from exc


@router.post("/acs")
async def saml_acs(request: Request) -> Response:
    """Assertion Consumer Service — process IdP POST-back and issue JWT."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]

        req = await _build_saml_request(request)
        auth = OneLogin_Saml2_Auth(req, _saml_settings())
        auth.process_response()
        errors = auth.get_errors()

        if errors:
            raise HTTPException(status_code=400, detail=f"SAML errors: {errors}")

        if not auth.is_authenticated():
            raise HTTPException(status_code=401, detail="SAML authentication failed")

        attrs = auth.get_attributes()
        name_id = auth.get_nameid()

        email_claim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        name_claim = "http://schemas.microsoft.com/identity/claims/displayname"
        token = _issue_jwt(
            {
                "sub": name_id,
                "email": _first(attrs.get("email") or attrs.get(email_claim, [name_id])),
                "name": _first(attrs.get("displayName") or attrs.get(name_claim, [])),
                "provider": "saml",
            }
        )

        relay_state = _safe_redirect(str((await request.form()).get("RelayState", "/")))
        response = RedirectResponse(url=relay_state, status_code=302)
        response.set_cookie("aisoc_token", token, httponly=True, samesite="lax", secure=request.url.scheme == "https")
        return response

    except ImportError:
        logger.warning("python3-saml not installed — ACS stub active")
        token = _issue_jwt({"sub": "stub-saml-user", "email": "saml@stub.local", "provider": "saml-stub"})
        resp = RedirectResponse(url="/", status_code=302)
        resp.set_cookie("aisoc_token", token, httponly=True, samesite="lax")
        return resp


@router.get("/metadata")
async def saml_metadata() -> Response:
    """Return SP SAML metadata XML."""
    try:
        from onelogin.saml2.settings import OneLogin_Saml2_Settings  # type: ignore[import]

        settings_obj = OneLogin_Saml2_Settings(settings=_saml_settings(), sp_validation_only=True)
        metadata, _errors = settings_obj.get_sp_metadata(), []
        return Response(content=metadata, media_type="application/xml")
    except ImportError:
        sp_acs = os.getenv("SAML_SP_ACS_URL", "http://localhost:8000/auth/saml/acs")
        sp_entity = os.getenv("SAML_SP_ENTITY_ID", sp_acs)
        xml = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{sp_entity}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{sp_acs}" index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
        return Response(content=xml, media_type="application/xml")


@router.get("/logout")
async def saml_logout(request: Request) -> Response:
    """Initiate SAML SLO."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]

        req = await _build_saml_request(request)
        auth = OneLogin_Saml2_Auth(req, _saml_settings())
        name_id = request.cookies.get("saml_name_id", "")
        logout_url: str = auth.logout(name_id=name_id)
        response = RedirectResponse(url=logout_url)
        response.delete_cookie("aisoc_token")
        response.delete_cookie("saml_name_id")
        return response
    except ImportError:
        response = RedirectResponse(url="/login")
        response.delete_cookie("aisoc_token")
        return response


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _first(lst: list[str]) -> str:
    return lst[0] if lst else ""


def _stub_page(title: str, message: str) -> str:
    return f"""<!DOCTYPE html><html><head><title>{title}</title></head>
<body style="font-family:sans-serif;padding:2rem">
<h2>{title}</h2><p style="color:#666">{message}</p>
</body></html>"""


async def _build_saml_request(request: Request) -> dict[str, Any]:
    """Convert FastAPI request to the dict expected by python3-saml."""
    body = await request.body()
    form = await request.form() if request.method == "POST" else {}
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", request.url.netloc),
        "server_port": str(request.url.port or (443 if request.url.scheme == "https" else 80)),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": dict(form),
        "body": body,
    }
