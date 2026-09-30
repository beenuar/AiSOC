"""Resolve which tenant a request may read, from the caller's credential.

Vendored byte-identical into each Python service that needs it, following the
same convention as ``app/core/cors.py`` and ``app/security/service_auth.py``.
Keep the copies in sync — ``scripts/sync_vendored_tenant_scope.py --check``
fails the build if they drift.

Why this exists
---------------
``/fusion/entity-risk/*`` took the tenant as a query parameter with no auth
dependency on the route, on both the API gateway and the fusion service. The
console reaches fusion *directly* through a Next rewrite when ``FUSION_URL`` is
set, so that parameter was reachable from any browser on the internet, and
naming somebody else's tenant UUID returned their entity-risk queue.

Validating the parameter's *value* does not fix that. A UUID that parses is
still a UUID the caller chose. The scope has to come from somewhere the caller
does not control, which means the credential.

Two credential shapes reach these services, so this module resolves both:

``console`` — the browser's first-party access token, HS256-signed by
    ``services/api`` (``create_access_token``) and carrying a verified
    ``tenant_id`` claim. That claim is authoritative.
``service`` — the shared service bearer token used for service-to-service
    calls. It identifies *a trusted service*, not a tenant, so a caller
    presenting it must also assert which tenant it is acting for, on the
    ``X-AiSOC-Tenant-ID`` header. The assertion is explicit and required: a
    service token with no tenant header resolves to an **empty** scope, and an
    empty scope refuses rather than widening.

That last sentence is the whole design. Every cross-tenant leak this codebase
has had took the same shape — a scope that was absent rather than narrow, and
a read that treated absent as "no filter".

We verify HS256 by hand with the standard library rather than adding a JWT
dependency to five services, exactly as ``services/realtime/src/auth.ts`` does
for the same reason on the Node side. ``services/api`` remains the sole issuer;
this is a read path, like the vendored ``decrypt_dict()`` that lets the
connector scheduler decrypt without owning the write path.

Configuration
-------------
``SECRET_KEY``
    The HS256 secret ``services/api`` signs console tokens with. Without it
    this service cannot verify a console session and will only accept service
    tokens.
``AISOC_SERVICE_TOKEN`` / ``AISOC_<SERVICE>_SERVICE_TOKEN``
    Shared secret for service-to-service calls, resolved by
    ``app.security.service_auth.resolve_token`` where that module exists.
``AISOC_DEV_MODE``
    When set and *no* credential material is configured at all, requests
    resolve to the demo tenant so a local ``docker compose up`` works. This is
    the single canonical dev-mode flag;
    ``services/api/tests/test_security_defaults.py`` asserts no shortcut is
    reachable when it is unset.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field

from fastapi import Header, HTTPException, status

#: Set by each vendored copy so the per-service token override resolves.
SERVICE_NAME = "THREATINTEL"

logger = logging.getLogger("aisoc.tenant_scope")

_TRUTHY = {"1", "true", "yes", "on"}

#: Mirrors ``INSECURE_SECRET_KEY_DEFAULTS`` in services/api/app/core/config.py
#: so a placeholder secret is treated as "unset" on this side too. Verifying a
#: token signed with a well-known literal would authenticate anybody who read
#: the repository.
INSECURE_SECRET_DEFAULTS = frozenset(
    {
        "change-me-in-production-at-least-32-chars",
        "dev_secret_key_change_in_production",
        "changeme",
        "secret",
    }
)

#: Deterministic demo tenant, matching ``DEMO_TENANT_ID`` in
#: services/api/app/api/v1/dev_auth.py. Only ever reached when
#: :func:`auth_bypass_refusal` returns ``None``.
#:
#: This used to be ``…0001``, the canonical tenant that migration 001 seeds
#: and that ``bootstrap_admin`` puts the real administrator into, so an
#: unauthenticated caller was scoped to the operator's own data. The canonical
#: id stays where it is because ten modules pin it; the demo identity moved.
DEV_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-0000000000de")

#: The environment variable whose only job is to enable the anonymous shim.
#:
#: Deliberately not ``AISOC_DEV_MODE``. That flag already selects table
#: autocreate, docs URLs, the metrics gate, log formatting, the GraphiQL UI
#: and an ephemeral vault key, and ``docker-compose.yml`` defaults it to ``1``
#: on ten services. A flag that means nine things cannot be refused for one
#: of them, so the bypass gets a variable that means exactly one thing and
#: that no compose file or template sets.
DEV_AUTH_BYPASS_VAR = "AISOC_DEV_AUTH_BYPASS"

#: Where the deployment publishes this service, comma-separated. Supplied by
#: compose, because a container binds ``0.0.0.0`` and cannot otherwise know
#: whether anyone but the operator's own machine can reach it.
PUBLISHED_BIND_VAR = "AISOC_PUBLISHED_BIND_ADDRS"

#: Header a trusted service uses to declare which tenant it is acting for.
TENANT_HEADER = "X-AiSOC-Tenant-ID"

#: 30s clock-skew leeway, matching the Node verifier and common JWT defaults.
_CLOCK_SKEW_SECONDS = 30

#: Refs that mean "the caller did not name a tenant" rather than naming one.
#: Several request models default ``tenant_id`` to the string ``"default"``,
#: which is a placeholder, not a tenant — migration 001 seeds the canonical
#: tenant with that *slug* and the demo seed renames it, so the literal
#: identifies nothing anywhere. Treating it as a request for a tenant called
#: "default" would refuse every caller who simply left the field alone.
PLACEHOLDER_TENANT_REFS = frozenset({"", "default", "none", "null"})


class TenantScopeError(Exception):
    """A read was attempted without a resolved tenant scope.

    Raised by :func:`resolve_scoped_tenant`. Routes let it surface as a 403;
    it means a query was about to run with no tenant filter, or with one the
    caller is not authorised for.
    """


@dataclass(frozen=True)
class TenantPrincipal:
    """The tenants one credential may read, and what kind of credential it is.

    ``tenant_ids`` is authoritative and exhaustive. Nothing downstream may
    widen it, and no code path may substitute "all tenants" for an empty one.
    """

    tenant_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)
    subject: str = "anonymous"
    #: True when a service token asserted the tenant rather than a verified
    #: console claim carrying it. Surfaced so logs can tell the two apart.
    delegated: bool = False

    @property
    def is_empty(self) -> bool:
        return not self.tenant_ids

    def covers(self, tenant_id: uuid.UUID) -> bool:
        return tenant_id in self.tenant_ids

    def ordered_ids(self) -> list[uuid.UUID]:
        return sorted(self.tenant_ids)


EMPTY_PRINCIPAL = TenantPrincipal()


def resolve_scoped_tenant(
    principal: TenantPrincipal,
    requested: uuid.UUID | str | None = None,
) -> uuid.UUID:
    """The one tenant this request may read, or refuse to name one.

    Intersection only. A ``requested`` tenant inside the principal's scope is
    honoured — that is an MSSP operator narrowing to one managed customer. A
    ``requested`` tenant outside it narrows to nothing and raises, rather than
    reaching outside. Passing ``None`` means "the caller's own tenant", which
    is the common case and the safe default.
    """
    if principal.is_empty:
        raise TenantScopeError("refusing to read with an empty tenant scope")

    if isinstance(requested, str) and requested.strip().lower() in PLACEHOLDER_TENANT_REFS:
        requested = None

    if requested is None:
        if len(principal.tenant_ids) != 1:
            raise TenantScopeError(f"caller reaches {len(principal.tenant_ids)} tenants; the request must name one")
        return next(iter(principal.tenant_ids))

    try:
        wanted = requested if isinstance(requested, uuid.UUID) else uuid.UUID(str(requested))
    except (ValueError, AttributeError, TypeError) as exc:
        raise TenantScopeError("requested tenant is not a UUID") from exc

    if not principal.covers(wanted):
        # Logged at warning with the subject, because a caller reaching for a
        # tenant they do not hold is a security event, not routine noise.
        logger.warning(
            "tenant_scope.refused subject=%s requested=%s scope_size=%d",
            # Sanitised inline rather than through a helper: CodeQL does not
            # track a helper across the call boundary, and `subject` really is
            # attacker-influenced — it carries the JWT `sub` claim.
            str(principal.subject).replace("\r", "").replace("\n", " ")[:128],
            str(wanted).replace("\r", "").replace("\n", " ")[:64],
            len(principal.tenant_ids),
        )
        raise TenantScopeError("requested tenant is outside the caller's authorised scope")
    return wanted


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------


def _dev_mode() -> bool:
    return os.getenv("AISOC_DEV_MODE", "").strip().lower() in _TRUTHY


def _is_loopback(address: str) -> bool:
    """Whether ``address`` reaches only the machine this service runs on."""
    host = address.strip().lower()
    if not host:
        return True
    if host.startswith("["):
        host = host.partition("]")[0].lstrip("[")
    elif host.count(":") == 1:
        host = host.partition(":")[0]
    if host in {"localhost", "::1", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # A hostname that is not obviously loopback. When the question cannot
        # be decided, the safe answer is the one that refuses the bypass.
        return False


def auth_bypass_refusal() -> str | None:
    """Why an uncredentialed caller must not be admitted, or ``None``.

    Three conditions, where there used to be one. ``AISOC_DEV_MODE`` alone
    admitted a caller with no credential at all whenever neither a console
    secret nor a service token was configured — and ``docker-compose.yml``
    defaults that flag to ``1`` on ten services while generating no service
    token, so a hand-copied ``.env`` and a plain ``docker compose up`` left
    this open.

    Returns a sentence for the log, so an operator who expected the bypass
    learns which condition withheld it instead of seeing an unexplained 503.
    """
    if not _dev_mode():
        return "AISOC_DEV_MODE is not set"
    if os.getenv(DEV_AUTH_BYPASS_VAR, "").strip().lower() not in _TRUTHY:
        return (
            f"{DEV_AUTH_BYPASS_VAR} is not set. AISOC_DEV_MODE selects several "
            "unrelated development behaviours and defaults to 1 in compose, so "
            "it no longer enables the anonymous path on its own. Set "
            f"{DEV_AUTH_BYPASS_VAR}=1 deliberately, or use "
            "infra/compose/docker-compose.dev.yml, which sets it"
        )
    published = [a for a in os.getenv(PUBLISHED_BIND_VAR, "").split(",") if a.strip()]
    reachable = [a.strip() for a in published if not _is_loopback(a)]
    if reachable:
        return (
            f"{DEV_AUTH_BYPASS_VAR} is set, but this deployment publishes "
            f"{', '.join(reachable)}, which is not loopback. Bind to 127.0.0.1, "
            "or configure SECRET_KEY and a service token"
        )
    return None


#: Refusals and activations already logged, so a hot path does not emit one
#: line per request. Keyed on the reason rather than counted, so a deployment
#: whose refusal *changes* still says so once.
_BYPASS_LOGGED: set[str] = set()


def _bypass_permitted() -> bool:
    """Whether to admit an uncredentialed caller, logging the decision once."""
    refusal = auth_bypass_refusal()
    if refusal is None:
        if "__active__" not in _BYPASS_LOGGED:
            _BYPASS_LOGGED.add("__active__")
            logger.warning(
                "ANONYMOUS ACCESS IS ENABLED on %s. Requests with no credential "
                "resolve to the demo tenant %s. This is a development "
                "convenience and must not be used where anyone else can reach "
                "this host.",
                SERVICE_NAME,
                DEV_TENANT_ID,
            )
        return True
    if refusal not in _BYPASS_LOGGED:
        _BYPASS_LOGGED.add(refusal)
        logger.info("anonymous access refused on %s: %s", SERVICE_NAME, refusal)
    return False


def resolve_console_secret() -> str:
    """The HS256 secret console tokens are signed with, or "" when unusable."""
    secret = (os.getenv("SECRET_KEY") or "").strip()
    if not secret or secret in INSECURE_SECRET_DEFAULTS:
        return ""
    return secret


def resolve_service_token() -> str:
    """Per-service override wins, then the shared platform token."""
    specific = os.getenv(f"AISOC_{SERVICE_NAME}_SERVICE_TOKEN", "").strip()
    if specific:
        return specific
    return os.getenv("AISOC_SERVICE_TOKEN", "").strip()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def verify_console_token(token: str, secret: str) -> dict | None:
    """Verify a first-party HS256 access token. Return claims, or None.

    Mirrors ``verifyRealtimeTicket`` in services/realtime/src/auth.ts. The
    signing side is ``create_access_token`` in services/api/app/core/security.py
    and must stay in sync with the claims checked here.
    """
    if not token or not secret:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    # Reject "alg: none" and asymmetric algorithms so a caller cannot downgrade
    # the verification into no verification at all.
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        return None

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256,
    ).digest()
    try:
        provided = _b64url_decode(sig_b64)
    except (ValueError, binascii.Error):
        return None
    if not hmac.compare_digest(expected, provided):
        return None

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(claims, dict):
        return None

    # A refresh token must not buy access; the API sets type="access" on the
    # short-lived one and type="refresh" on the long-lived one.
    if claims.get("type") != "access":
        return None
    exp = claims.get("exp")
    if not isinstance(exp, int | float):
        return None
    if exp + _CLOCK_SKEW_SECONDS < time.time():
        return None
    if not claims.get("tenant_id"):
        return None
    return claims


def _principal_from_claims(claims: dict) -> TenantPrincipal | None:
    try:
        tenant = uuid.UUID(str(claims["tenant_id"]))
    except (KeyError, ValueError, TypeError):
        return None
    return TenantPrincipal(
        tenant_ids=frozenset({tenant}),
        subject=f"console:{claims.get('sub', 'unknown')}",
        delegated=False,
    )


async def require_console_or_service_auth(
    authorization: str | None = Header(default=None),
    x_aisoc_tenant_id: str | None = Header(default=None, alias=TENANT_HEADER),
) -> TenantPrincipal:
    """FastAPI dependency. Resolve the caller's tenant scope, or fail closed.

    Order matters only for clarity — the two credential shapes are disjoint. A
    console token carries its own tenant; a service token must declare one.
    """
    console_secret = resolve_console_secret()
    service_token = resolve_service_token()

    if not console_secret and not service_token:
        if _bypass_permitted():
            return TenantPrincipal(
                tenant_ids=frozenset({DEV_TENANT_ID}),
                subject="dev",
                delegated=False,
            )
        # No credential material configured at all: refuse to serve rather
        # than serve openly. This is the same fail-closed posture as
        # ``require_service_auth``.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "tenant-scoped auth is not configured; set SECRET_KEY and/or "
                f"AISOC_SERVICE_TOKEN (or AISOC_{SERVICE_NAME}_SERVICE_TOKEN) "
                "before exposing this service"
            ),
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer credential",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[len("Bearer ") :].strip()

    # --- console session ---
    if console_secret:
        claims = verify_console_token(token, console_secret)
        if claims is not None:
            principal = _principal_from_claims(claims)
            if principal is not None:
                return principal

    # --- trusted service acting for a declared tenant ---
    if service_token and hmac.compare_digest(token, service_token):
        if not x_aisoc_tenant_id or not x_aisoc_tenant_id.strip():
            # An absent tenant is an empty scope, never every scope.
            logger.warning(
                "tenant_scope.service_token_without_tenant service=%s header=%s",
                SERVICE_NAME,
                TENANT_HEADER,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"service token must declare the tenant it acts for on {TENANT_HEADER}",
            )
        try:
            tenant = uuid.UUID(x_aisoc_tenant_id.strip())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{TENANT_HEADER} must be a UUID",
            ) from None
        return TenantPrincipal(
            tenant_ids=frozenset({tenant}),
            subject="service",
            delegated=True,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing credential",
        headers={"WWW-Authenticate": "Bearer"},
    )


def scoped_tenant_or_403(
    principal: TenantPrincipal,
    requested: uuid.UUID | str | None = None,
) -> uuid.UUID:
    """:func:`resolve_scoped_tenant`, surfaced to HTTP as 403.

    Routes call this so the refusal reaches the client as a refusal rather
    than a 500, without every route repeating the try/except.
    """
    try:
        return resolve_scoped_tenant(principal, requested)
    except TenantScopeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
