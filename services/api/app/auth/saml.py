"""
SAML 2.0 Service Provider implementation for AiSOC.

Flow:
  1. GET  /auth/saml/login          → redirect to IdP SSO URL
  2. POST /auth/saml/acs            ← IdP posts assertion here (ACS)
  3. GET  /auth/saml/metadata       → SP metadata (share with IdP)
  4. GET  /auth/saml/logout         → SLO initiation (optional)

Dependencies (optional):
  - python3-saml (onelogin/python3-saml) if available
  - Refuses with 501 when not installed, rather than inventing an identity

Where the identity provider comes from (fix pass 4.1)
-----------------------------------------------------
The **connection row**, not the environment. `aisoc_sso_connections`
carries `metadata_url` and `metadata_xml` per connection; both were
written by `POST /sso-connections` and read by nothing, so an
administrator could configure an IdP in the console and the deployment
would go on trusting whatever `SAML_IDP_*` said — which on a stock install
is nothing, so every assertion was refused. See
`app/auth/saml_metadata.py`.

The `SAML_IDP_*` variables below remain as a fallback for deployments that
configured SAML before connections were readable. A connection wins over
them whenever one resolves.

Configuration (env vars):
  SAML_SP_ENTITY_ID        SP Entity ID (defaults to ACS URL)
  SAML_SP_ACS_URL          Assertion Consumer Service URL
  SAML_SP_PRIVATE_KEY      SP private key PEM (optional, for signed requests)
  SAML_SP_CERT             SP certificate PEM (optional)
  SAML_IDP_ENTITY_ID       Fallback IdP Entity ID (issuer)
  SAML_IDP_SSO_URL         Fallback IdP SSO redirect URL
  SAML_IDP_SLO_URL         Fallback IdP SLO URL (optional)
  SAML_IDP_CERT            Fallback IdP X.509 certificate (PEM or single-line base64)
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
from urllib.parse import quote

import jwt as _jwt
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response

from app.api.v1.deps import DBSession
from app.auth.saml_metadata import (
    SamlTrustError,
    environment_idp_is_configured,
    environment_idp_settings,
    idp_settings_for_connection,
    issuer_from_saml_response,
    resolve_saml_connection,
)
from app.auth.sso_provisioning import SsoProvisioningError, complete_sso_login

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


def _saml_settings(idp: dict[str, Any] | None = None) -> dict[str, Any]:
    """The python3-saml settings for this service provider.

    The SP half is deployment-wide: one service, one ACS URL, one
    certificate. The **IdP half is per connection** and is passed in —
    `idp=None` falls back to `SAML_IDP_*`, which is how a pre-4.1
    deployment was configured and the only thing that used to be possible.
    """
    sp_acs = os.getenv("SAML_SP_ACS_URL", "http://localhost:8000/auth/saml/acs")
    sp_entity = os.getenv("SAML_SP_ENTITY_ID", sp_acs)
    sp_key = os.getenv("SAML_SP_PRIVATE_KEY", "")
    sp_cert = os.getenv("SAML_SP_CERT", "")

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
        "idp": idp if idp is not None else environment_idp_settings(),
    }


async def _resolve_idp(db: DBSession, *, issuer: str | None) -> tuple[dict[str, Any], str]:
    """The IdP settings block and the issuer that keys its connection.

    Returns `(idp_settings, issuer)`. The issuer returned is the one the
    **connection** declares, never the one an assertion claimed: the
    assertion's issuer only selected which connection to look at, and
    `complete_sso_login` resolves the tenant from the row this returns the
    key of.
    """
    connection = await resolve_saml_connection(db, issuer=issuer)
    if connection is not None:
        return await idp_settings_for_connection(connection), str(connection["issuer"])

    if environment_idp_is_configured():
        env = environment_idp_settings()
        logger.info("saml.trust_from_environment no connection row matched; using SAML_IDP_* ")
        return env, str(env["entityId"])

    raise SamlTrustError(
        "no enabled SAML connection is configured for this deployment. Create one with "
        "POST /api/v1/sso-connections carrying the identity provider's metadata_url or metadata_xml."
    )


# ─── Routes ───────────────────────────────────────────────────────────────────


@router.get("/login")
async def saml_login(request: Request, db: DBSession, redirect: str = "/", issuer: str | None = None) -> Response:
    """Initiate SAML SSO — redirect to the IdP this connection names.

    `issuer` is optional and the console does not send one: a deployment
    with a single enabled SAML connection has an unambiguous answer. It
    exists so a deployment with several can link one button per provider.
    """
    from app.auth.oidc import _require_sso_enabled  # noqa: PLC0415

    _require_sso_enabled()
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]

        idp, _issuer = await _resolve_idp(db, issuer=issuer)
        req = await _build_saml_request(request)
        auth = OneLogin_Saml2_Auth(req, _saml_settings(idp))
        login_url: str = auth.login(return_to=redirect)
        return RedirectResponse(url=login_url)
    except SamlTrustError as exc:
        # A configuration problem, named. "SAML error: Invalid dict
        # settings: idp_sso_url_invalid" sent an operator to read
        # python3-saml's source; this sends them to the connection they
        # thought they had configured.
        logger.warning("saml.login_unconfigured reason=%s", str(exc).replace("\r", "").replace("\n", " ")[:300])
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except ImportError as exc:
        # 501, not a page that looks like a login. This branch used to render
        # a stub and the one below it used to mint a token, and since
        # python3-saml was declared in no manifest, the stub was the only
        # reachable path on a stock install.
        logger.error("SAML is enabled but python3-saml is not installed")
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=("SAML is not available on this deployment: python3-saml is not installed. Install it, or use OIDC."),
        ) from exc
    except Exception as exc:
        logger.exception("SAML login error")
        raise HTTPException(status_code=500, detail=f"SAML error: {exc}") from exc


@router.post("/acs")
async def saml_acs(request: Request, db: DBSession) -> Response:
    """Assertion Consumer Service — process IdP POST-back and issue JWT."""
    from app.auth.oidc import _require_sso_enabled

    _require_sso_enabled()
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]

        req = await _build_saml_request(request)
        # The issuer the response names picks which connection's
        # certificate to verify against. It confers nothing: an assertion
        # naming an issuer whose private key the sender does not hold fails
        # `process_response()` two lines below, and the tenant comes from
        # the connection row either way.
        claimed_issuer = issuer_from_saml_response(str(req.get("post_data", {}).get("SAMLResponse") or ""))
        idp, connection_issuer = await _resolve_idp(db, issuer=claimed_issuer)
        auth = OneLogin_Saml2_Auth(req, _saml_settings(idp))
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
        group_claim = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"

        # Parity 4.1. Same change as the OIDC callback, and for the same
        # reason: this issued a JWT with no tenant, no role and no local
        # user, signed with `JWT_SECRET` rather than the key the API
        # verifies with, into a cookie the API does not read.
        groups = [str(g) for g in (attrs.get("groups") or attrs.get(group_claim) or attrs.get("memberOf") or []) if g]
        try:
            session = await complete_sso_login(
                db,
                provider="saml",
                # The entity id the *connection* declares, not the one the
                # assertion claimed. They are equal on the path that got
                # here — the signature verified against that connection's
                # certificate — and passing the connection's value means a
                # future change to selection cannot turn the assertion into
                # the thing that chooses the tenant.
                issuer=connection_issuer,
                email=str(_first(attrs.get("email") or attrs.get(email_claim, [name_id]))),
                subject=str(name_id or ""),
                name=_first(attrs.get("displayName") or attrs.get(name_claim, [])),
                groups=groups,
                # A SAML assertion is signed by the identity provider, and the
                # address it asserts *is* the provider's statement about the
                # user -- there is no separate `email_verified` claim to
                # consult, and the signature is the assurance OIDC uses that
                # claim to provide. Stated here rather than defaulted inside
                # `complete_sso_login`, so a reader of either caller can see
                # which assurance applies.
                email_verified=True,
            )
        except SsoProvisioningError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

        # Land on the login page, not on the RelayState destination, and
        # carry the refresh token too. Both halves were defects:
        #
        # `handleUnauthorized` in `apps/web/src/lib/api.ts` builds its
        # bounce target from `pathname + search`, so an auth guard on
        # `/alerts` redirects to `/login?next=/alerts` and **drops the
        # fragment** — taking the only copy of the token with it. The OIDC
        # callback already lands on /login for exactly this reason; this
        # one did not, so a SAML sign-in could not complete in the console
        # however valid the assertion.
        #
        # And the console's fragment consumer persists `refresh_token`
        # alongside the access token; omitting it logged the user out
        # silently when the access token expired.
        relay_state = _safe_redirect(str((await request.form()).get("RelayState", "/")))
        redirect_url = f"/login?next={quote(relay_state, safe='')}"
        # In the fragment, which browsers do not send to the server and
        # which does not land in an access log or a Referer header.
        return RedirectResponse(
            url=(f"{redirect_url}#access_token={session['access_token']}&refresh_token={session['refresh_token']}"),
            status_code=302,
        )

    except SamlTrustError as exc:
        logger.warning("saml.acs_unconfigured reason=%s", str(exc).replace("\r", "").replace("\n", " ")[:300])
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except ImportError as exc:
        # This issued a signed session for a principal called
        # `stub-saml-user` that no identity provider had ever seen, from an
        # exception handler that had verified nothing. It is a 501 now: an
        # assertion consumer with no library to consume assertions has
        # nothing to say about who the caller is.
        logger.error("SAML ACS reached but python3-saml is not installed")
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=("SAML is not available on this deployment: python3-saml is not installed."),
        ) from exc


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
async def saml_logout(request: Request, db: DBSession, issuer: str | None = None) -> Response:
    """Initiate SAML SLO, at the SingleLogoutService the connection names.

    Resolved the same way `/login` is. A deployment whose IdP comes from a
    connection has no `SAML_IDP_SLO_URL`, so this used to build a logout
    request against an empty endpoint and 500 on the way out of a session.
    An SLO that cannot be initiated is a local logout, not an error.
    """
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import]

        idp, _issuer = await _resolve_idp(db, issuer=issuer)
        req = await _build_saml_request(request)
        auth = OneLogin_Saml2_Auth(req, _saml_settings(idp))
        name_id = request.cookies.get("saml_name_id", "")
        logout_url: str = auth.logout(name_id=name_id)
        response = RedirectResponse(url=logout_url)
        response.delete_cookie("aisoc_token")
        response.delete_cookie("saml_name_id")
        return response
    except Exception:  # noqa: BLE001
        # Every failure here ends the same way, so they are not
        # distinguished: python3-saml missing, no connection configured, or
        # an IdP that publishes no SingleLogoutService. The session is
        # already being discarded locally, and refusing to do that because
        # the provider cannot be told would leave the user signed in.
        logger.info("saml.slo_unavailable falling back to local logout")
        response = RedirectResponse(url="/login")
        response.delete_cookie("aisoc_token")
        response.delete_cookie("saml_name_id")
        return response


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _first(lst: list[str]) -> str:
    return lst[0] if lst else ""


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
