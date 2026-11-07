"""FastAPI dependency injection.

Authentication supports two credential types:
  1. JWT Bearer token   – issued by /auth/login
  2. API key Bearer     – prefixed with "aisoc_", validated against the api_keys table

API key auth carries explicit ``scopes``; JWT auth derives permissions from the
user's role via ``ROLE_PERMISSIONS``.

Multi-tenant Row-Level Security (RLS)
--------------------------------------
Use ``TenantDBSession`` (from ``app.db.rls``) instead of ``DBSession`` for
endpoints that must be tenant-isolated at the database level.  It sets the
Postgres session variable ``app.current_tenant_id`` before yielding, which
activates the RLS policies defined in ``migrations/002_rls.sql``.

    from app.db.rls import TenantDBSession

    @router.get("/cases")
    async def list_cases(db: TenantDBSession, user: AuthUser):
        ...
"""

import hmac
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dev_auth import (
    DEMO_TENANT_ID,
    DEMO_USER_EMAIL,
    DEMO_USER_ID,
    DEMO_USER_ROLE,
    is_dev_mode,
)
from app.core.permission_cache import (
    grants,
    resolve_conditions,
    resolve_elevation,
    resolve_permissions,
)
from app.core.role_grants import narrow_by_conditions
from app.core.security import (
    ROLE_PERMISSIONS,
    decode_token,
    has_permission,
    hash_api_key,
    token_is_revoked,
)
from app.core.trusted_proxy import resolve_client_ip
from app.db.database import get_db
from app.models.tenant import ApiKey, Tenant, User
from app.security import abac
from app.security.abac import PrivilegeGrant
from app.services import workload_identity as workload_identity_service
from app.services.workload_identity import authenticate_workload, is_workload_secret

logger = logging.getLogger("aisoc.deps")

bearer_scheme = HTTPBearer(auto_error=False)

_API_KEY_PREFIX = "aisoc_"


def _condition_applies(row: dict[str, Any], permission: str, role: str) -> bool:
    """Whether one stored condition governs this check.

    Scoped to the permission it names, with the same ``resource:*`` form
    the permission check itself understands so an operator can constrain a
    whole resource in one row. A condition applied to every permission
    would turn one narrow rule into a tenant-wide outage; a condition that
    did not understand the wildcard would silently not apply where an
    operator expected it to.

    ``role`` is an optional narrowing: ``NULL`` means every role.
    """
    target = row.get("permission")
    if target not in (permission, f"{permission.split(':')[0]}:*", "*"):
        return False
    scoped_to = row.get("role")
    return scoped_to in (None, "", role)


class CurrentUser:
    """Resolved authenticated user context.

    ``scopes`` is only populated when authenticated via an API key; it
    holds the explicit permission strings granted to that key.  When ``None``
    the user's role-based permissions apply.

    Permission resolution order:
      1. API-key scopes (explicit list)
      2. RBAC ``user_roles`` → ``role_permissions`` (database-backed)
      3. Static ``ROLE_PERMISSIONS`` fallback (legacy / bootstrap)

    …then, for every one of those three, any attribute condition the tenant
    configured, which can only narrow. See :meth:`require_permission`.
    """

    def __init__(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        role: str,
        email: str,
        scopes: list[str] | None = None,
        api_key_prefix: str | None = None,
        resolved_permissions: frozenset[str] | None = None,
        elevation: tuple[PrivilegeGrant, ...] = (),
        conditions: tuple[dict[str, Any], ...] = (),
        attributes: dict[str, Any] | None = None,
        workload_service: str | None = None,
    ) -> None:
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role
        self.email = email
        self.scopes = scopes  # None → role-based; list → API-key scoped
        # Set only on the API-key path, and only so the audit log can say so.
        #
        # A key owned by a user resolves to that user's email, so an audit
        # entry read "alice@corp.com deleted the rule" whether Alice did it
        # at the console or a key she minted a year ago did it from a script
        # she no longer runs. Those call for different responses — revoke a
        # key, or disable a person — and the log could not tell an
        # investigator which one had happened.
        self.api_key_prefix = api_key_prefix
        # What the RBAC tables say this principal holds, resolved once at
        # authentication. `None` means "nothing resolved it", which is the
        # case for a directly-constructed principal in a test and for the
        # dev-mode user, and falls through to the static map.
        #
        # The whole reason this field exists: 275 route dependencies checked
        # the hardcoded `ROLE_PERMISSIONS` map while 27 checked the tables
        # the console's RBAC screen writes to, so an operator could grant a
        # permission, watch it appear in the UI, and have 275 of 302 routes
        # ignore it.
        self.resolved_permissions = resolved_permissions
        # Approved, unexpired `privilege_grants` rows. Held as grants rather
        # than merged into the set above so expiry is decided at *use*: a
        # background sweep is a job that can be down, and a grant outliving
        # its window because a worker crashed is the failure mode JIT
        # elevation exists to remove.
        self.elevation = elevation
        # `permission_conditions` rows for the tenant. They narrow, never
        # grant, and are applied after whichever branch above allowed.
        self.conditions = conditions
        # What the conditions are judged against. Every key here is derived
        # by the server from the verified request — never read from a body
        # or from a header the caller controls — because an attribute a
        # caller can set is not a constraint on that caller.
        self.attributes = attributes or {}
        # Which internal service a workload credential belongs to, so an
        # audit row names `agents` rather than "a service". `None` for
        # every human and API-key principal.
        self.workload_service = workload_service

    def __repr__(self) -> str:
        # Without this a stray `str(user)` persists `<...CurrentUser object at
        # 0x...>` into whatever column it was bound to, which is what happened
        # to three actor columns. `email` is deliberately omitted: this value
        # reaches logs and tracebacks, and the address of the person holding
        # the session is not something a stack trace should carry.
        return f"CurrentUser(user_id={self.user_id}, tenant_id={self.tenant_id}, role={self.role})"

    def elevated_permissions(self) -> frozenset[str]:
        """The resolved set widened by elevation that is live *right now*.

        Evaluated on every call rather than folded in at authentication,
        which is what makes expiry automatic: a grant whose `expires_at`
        passed mid-session stops applying on the next check, with no sweep
        job in the path.
        """
        base = self.resolved_permissions or frozenset()
        if not self.elevation:
            return base
        return abac.effective_permissions(base, list(self.elevation))

    def require_permission(self, permission: str) -> None:
        """The one permission check. Everything authorization does is here.

        Three ways to be allowed and one way to be narrowed, in this order:

        1. an API key's explicit scopes,
        2. the RBAC tables, widened by live elevation,
        3. the static role map, when nothing resolved a set;

        then, whichever allowed, any attribute condition the tenant
        configured for this permission. Conditions run **after** and can
        only deny. A condition that could grant would be a second
        authorization system reaching a different answer from the first,
        and the two would disagree on the day it mattered — which is the
        shape that produced GHSA-pm3f-h6gc-rvgp here.

        Elevation deliberately does **not** widen an API key. A key's
        scopes are a narrower grant chosen at mint time; letting a person's
        temporary elevation flow into a bearer credential they minted
        earlier would make the elevation outlive its own window.
        """
        if self.scopes is not None:
            # API-key path: check explicit scopes list
            allowed = "*" in self.scopes or permission in self.scopes or f"{permission.split(':')[0]}:*" in self.scopes
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key missing scope: {permission}",
                )
        elif self.resolved_permissions is not None:
            # Database-backed: what the RBAC tables actually grant, plus
            # any elevation live at this instant.
            if not grants(self.elevated_permissions(), permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission}",
                )
        elif not has_permission(self.role, permission):
            # Nothing resolved a set for this principal, so the static map
            # is the only answer available.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )

        self._narrow_by_conditions(permission)

    def _narrow_by_conditions(self, permission: str) -> None:
        """Apply the tenant's attribute conditions to an allowed permission.

        Reached from exactly one place, on purpose. A condition evaluated
        *beside* the permission check rather than inside it would be a
        second authority that can disagree with the first, and a route
        added next year would get the role check and miss this one.
        """
        if not self.conditions:
            return
        applicable = [row for row in self.conditions if _condition_applies(row, permission, self.role)]
        if not applicable:
            return

        verdict = narrow_by_conditions(permission, applicable, self.attributes)
        if not verdict.allowed:
            logger.info(
                "deps.condition_denied permission=%s reason=%s",
                str(permission).replace("\r", "").replace("\n", " ")[:64],
                str(verdict.denied_by).replace("\r", "").replace("\n", " ")[:200],
            )
            # Named as a condition rather than a bare "permission denied".
            # An attribute refusal is indistinguishable from a missing role
            # otherwise, and people debug the wrong thing for an hour.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied by an access condition on {permission}: {verdict.denied_by}",
            )

    def effective_permissions(self) -> list[str]:
        """Every permission string this principal holds, in one list.

        `require_permission` above answers "may this principal do X". This
        answers "what may this principal do", which is what a *downstream*
        service needs: `services/actions` re-authorises an approval itself,
        and it cannot ask us one verb at a time.

        Same three-step order as `require_permission`, deliberately. Two
        answers from two orders would mean a caller allowed to approve
        something the same principal is refused for elsewhere, and the
        divergence would show up as an intermittent 403 rather than as a bug.

        This exists because `approvals.py` was reading `user.roles` and
        `user.permissions` -- neither of which this class defines -- through
        `getattr(..., [])`. Both defaults fired silently, the actions service
        received an empty permission list, and since `has_action_permission`
        denies unconditionally on an empty list, **every** approval 502'd while
        the approval row recorded the decision.

        Returns a list rather than a set because it crosses a JSON boundary;
        sorted so two identical principals produce identical request bodies
        and a diff of two audit entries is readable.
        """
        if self.scopes is not None:
            # An API key's scopes are an explicit, deliberately narrower grant
            # than its owner's role. Inheriting the owner's full set here would
            # defeat the point of scoping a key.
            return sorted(set(self.scopes))
        if self.resolved_permissions is not None:
            # Elevation included, for the same reason the order above is
            # shared: `services/actions` re-authorises an approval against
            # this list, and an elevated analyst refused there while
            # allowed here would surface as an intermittent 403 rather
            # than as a bug.
            return sorted(self.elevated_permissions())
        # Static fallback. `ROLE_PERMISSIONS` is read here, in the one module
        # that owns principal resolution, rather than in a route -- a route
        # deciding its own permissions is what `check_one_permission_model`
        # refuses, and it refuses it because a published advisory came from
        # exactly that.
        return sorted(set(ROLE_PERMISSIONS.get(self.role, [])))

    def bind_connection_attributes(self, connection: Any) -> "CurrentUser":
        """Record the facts attribute conditions are judged against.

        Takes a ``Request`` or a ``WebSocket`` — both carry ``.client`` and
        ``.headers``, which is all this reads, and the WebSocket upgrade
        has to be covered or a tenant that configures a condition finds
        their graph stream behaving differently from every HTTP route.

        ``source_ip`` goes through :func:`resolve_client_ip`, which only
        honours ``X-Forwarded-For`` when the direct peer is on the
        configured trusted-proxy allow-list. Reading the header directly
        would let a caller satisfy an address condition by claiming an
        address, which is not a constraint on that caller at all.

        ``auth_method`` and ``role`` are derived here rather than supplied,
        for the same reason.
        """
        self.attributes = {
            "source_ip": resolve_client_ip(connection),
            "role": self.role,
            "auth_method": self.auth_method(),
        }
        return self

    def auth_method(self) -> str:
        """How this principal authenticated: a condition can constrain it.

        "``cases:delete`` from a console session, not from a key somebody
        minted a year ago" is a rule operators ask for, and it needs the
        credential type to be an attribute rather than something inferred
        from the role.
        """
        if self.workload_service is not None:
            return "workload"
        if self.scopes is not None:
            return "api_key"
        if self.role == "api_service":
            return "service_token"
        return "session"

    async def _ensure_resolved(self, db: AsyncSession) -> None:
        """Give this principal a database-backed set if nothing has yet.

        Almost never does any work. ``get_current_user`` resolves one for
        every credential it admits — an API key and a workload carry
        ``scopes``, a service token and a session carry
        ``resolved_permissions`` — so this covers the two cases that reach a
        route without passing through there: a principal constructed directly
        by a test, and a session whose resolution failed and fell open to the
        static map.

        Failing open to the static map, like authentication does. This is not
        the place to invent a stricter posture than the door the caller came
        through.
        """
        if self.scopes is not None or self.resolved_permissions is not None:
            return
        try:
            self.resolved_permissions = await resolve_permissions(db, tenant_id=self.tenant_id, user_id=self.user_id, static_role=self.role)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "late permission resolution failed for user %s; falling back to the static role map: %s",
                str(self.user_id).replace("\r", "").replace("\n", " ")[:64],
                str(exc).replace("\r", "").replace("\n", " ")[:200],
            )

    async def require_permission_db(self, permission: str, db: AsyncSession) -> None:
        """The same check as :meth:`require_permission`, for in-body call sites.

        **It used to be a second permission model, and that is the whole
        reason this docstring is long.** It ran its own ``user_roles`` join,
        read neither the resolved set nor live elevation nor the tenant's
        attribute conditions, and fell back to the static map whenever the
        join came back empty. Three consequences, all measured
        (GHSA-ghpm-vc6j-hp5r):

        * A service token resolves to ``SERVICE_PRINCIPAL_PERMISSIONS`` and
          was then measured against ``ROLE_PERMISSIONS["api_service"]``, so
          the more permissive of the two declarations won on all 27 routes
          that call this.
        * **A deprovisioned user got their static role back.**
          ``resolve_permissions`` distinguishes "this tenant has no RBAC" from
          "this tenant has RBAC and gave this user none" and returns the empty
          set for the second. This method saw the same zero rows the resolver
          does and could not tell the two apart — the exact defect the
          resolver was written to close, still live one layer up, and
          reachable today on every route here.
        * Elevation and conditions applied on one path and not the other, so
          the same principal was allowed or refused depending only on which
          factory a route happened to use.

        So there is one decision function and this delegates to it. ``db``
        stays in the signature and stays used: it is what resolves a set for
        a principal authentication did not resolve one for.
        """
        await self._ensure_resolved(db)
        self.require_permission(permission)

    async def has_permission_db(self, permission: str, db: AsyncSession) -> bool:
        """Whether this principal holds *permission*, by the one model above.

        The boolean form, for the two call sites that branch rather than
        refuse. Only a 403 becomes ``False``; anything else is a fault and
        propagates, because a permission check that swallows an unexpected
        error answers "no" for a reason nobody can see.
        """
        try:
            await self.require_permission_db(permission, db)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_403_FORBIDDEN:
                return False
            raise
        return True


#: Header a trusted service uses to declare which tenant it is acting for.
#: Spelled identically to ``TENANT_HEADER`` in the vendored
#: ``app/security/tenant_scope.py`` that the other services already use, so
#: one service does not have to know which of two names a peer expects.
SERVICE_TENANT_HEADER = "X-AiSOC-Tenant-ID"

#: What a service principal may do, and nothing else.
#:
#: **Derived, not declared.** This was a literal set written here while
#: ``ROLE_PERMISSIONS["api_service"]`` described the same principal in
#: ``app/core/security.py``, and the two disagreed: the role map granted
#: ``alerts:write`` and ``cases:write`` that this list deliberately withheld,
#: and withheld four reads this list granted. Whichever check a route happened
#: to use decided which of the two applied, and the permissive one governed
#: the database-backed path (GHSA-ghpm-vc6j-hp5r).
#:
#: One object now, so they cannot drift. The rationale for each entry lives
#: with the row, in ``app/core/security.py``; this is the frozen view of it
#: that ``_resolve_service_principal`` hands to a principal.
SERVICE_PRINCIPAL_PERMISSIONS: frozenset[str] = frozenset(ROLE_PERMISSIONS["api_service"])

#: Mirrors ``INSECURE_SECRET_KEY_DEFAULTS`` so a placeholder token is treated
#: as unset here too. Accepting a well-known literal would authenticate
#: anybody who read the repository.
_INSECURE_SERVICE_TOKENS = frozenset({"", "changeme", "change-me", "secret", "aisoc_dev_secret"})


def resolve_service_token() -> str:
    """The shared secret a peer service presents, or "" when unusable.

    Per-service override first, then the shared platform token, matching
    ``resolve_service_token`` in the vendored ``app/security/tenant_scope.py``
    that every other service resolves its own token with.
    """
    specific = (os.getenv("AISOC_API_SERVICE_TOKEN") or "").strip()
    token = specific or (os.getenv("AISOC_SERVICE_TOKEN") or "").strip()
    if token.lower() in _INSECURE_SERVICE_TOKENS:
        return ""
    return token


async def _resolve_service_principal(
    token: str,
    declared_tenant: str | None,
    db: AsyncSession,
) -> CurrentUser | None:
    """A trusted peer service acting for one named tenant, or ``None``.

    ``None`` means "this is not a service token", so the caller falls through
    to the JWT path. Every other refusal raises, because once the token has
    matched, a malformed or unknown tenant is a request to refuse rather than
    a different kind of credential to try.

    Why the tenant is a header and not a claim
    ------------------------------------------
    A service token identifies *a trusted service*, not a tenant. The agents
    container triages alerts for every tenant on the deployment, so the tenant
    has to come from the work it is doing. Making that explicit and mandatory
    is the whole design: a service token with no tenant resolves to an
    **empty** scope, and an empty scope refuses rather than widening. Every
    cross-tenant leak this codebase has had took the other shape, a scope that
    was absent rather than narrow and a read that treated absent as "no
    filter".

    The tenant is checked against the table. The header is caller-supplied,
    and ``POST /v1/ingest/batch`` once trusted exactly such a header with
    nothing verifying it existed.
    """
    expected = resolve_service_token()
    if not expected or not hmac.compare_digest(token, expected):
        return None

    tenant_id = await _resolve_tenant_for_service(declared_tenant, db)

    return CurrentUser(
        # A service is not a person. The id is deterministic from the tenant
        # so an audit row says which tenant a service acted for, and the
        # email names the mechanism rather than impersonating an operator.
        user_id=uuid.uuid5(uuid.NAMESPACE_URL, f"aisoc:service:{tenant_id}"),
        tenant_id=tenant_id,
        role="api_service",
        email=f"service@{tenant_id}.internal",
        resolved_permissions=SERVICE_PRINCIPAL_PERMISSIONS,
    )


async def _resolve_tenant_for_service(declared_tenant: str | None, db: AsyncSession) -> uuid.UUID:
    """The tenant a service caller named, verified against the table.

    Shared by the workload path and the shared-token path so there is one
    answer to "which tenant is this service acting for". Two copies of this
    rule would be two chances for one of them to treat a missing tenant as
    "no filter", and every cross-tenant leak in this codebase has taken
    exactly that shape — a scope that was absent rather than narrow.
    """
    if not declared_tenant or not declared_tenant.strip():
        logger.warning("deps.service_caller_named_no_tenant header=%s", SERVICE_TENANT_HEADER)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"service token must declare the tenant it acts for on {SERVICE_TENANT_HEADER}",
        )

    try:
        tenant_id = uuid.UUID(declared_tenant.strip())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{SERVICE_TENANT_HEADER} must be a UUID",
        ) from None

    exists = await db.execute(select(Tenant.id).where(Tenant.id == tenant_id))
    if exists.scalar_one_or_none() is None:
        logger.warning(
            "deps.service_caller_named_an_unknown_tenant tenant=%s",
            str(tenant_id).replace("\r", "").replace("\n", " ")[:64],
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="service token named a tenant that does not exist",
        )
    return tenant_id


async def _resolve_workload_principal(secret: str, declared_tenant: str | None, db: AsyncSession) -> CurrentUser:
    """A named internal service, acting for one declared tenant.

    The replacement for ``AISOC_SERVICE_TOKEN``, which is one string every
    internal caller presents: unattributable, unscopable, and unrotatable
    without restarting everything at once.

    Three differences from the shared token, and they are the whole point.
    The audit trail names the *service*. The scope list is per workload, so
    the ingest pipeline does not carry the agents worker's authority. And
    the credential can be rotated with a grace window instead of a
    simultaneous restart.

    What is identical, deliberately: the tenant is a mandatory header,
    verified against the table. A credential that works for every tenant
    is a cross-tenant read whichever way it was minted.
    """
    identity = await authenticate_workload(db, secret)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked workload credential",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Tenant *after* the credential check, so an unauthenticated caller
    # cannot probe which tenant ids exist by watching 403 against 401.
    tenant_id = await _resolve_tenant_for_service(declared_tenant, db)

    await workload_identity_service.touch(db, identity.id)

    return CurrentUser(
        # Deterministic from the service and tenant, so an audit row names
        # which workload acted for which tenant and two runs of the same
        # service aggregate instead of scattering.
        user_id=uuid.uuid5(uuid.NAMESPACE_URL, f"aisoc:workload:{identity.service}:{tenant_id}"),
        tenant_id=tenant_id,
        role="api_service",
        email=f"workload:{identity.service}@{tenant_id}.internal",
        # Scopes, not a resolved set: a workload's authority is the list on
        # its row, exactly as an API key's is the list on its row. Resolving
        # it to a role would widen it to whatever that role holds.
        scopes=list(identity.scopes or []),
        api_key_prefix=identity.secret_prefix,
        workload_service=identity.service,
    )


async def _resolve_api_key(raw_key: str, db: AsyncSession) -> CurrentUser:
    """Look up and validate an aisoc_ API key; return its CurrentUser."""
    hashed = hash_api_key(raw_key)
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.hashed_key == hashed,
            ApiKey.is_active == True,  # noqa: E712
        )
    )
    api_key: ApiKey | None = result.scalar_one_or_none()
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiry
    if api_key.expires_at is not None and api_key.expires_at < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last_used_at in background (fire-and-forget style — don't await)
    await db.execute(update(ApiKey).where(ApiKey.id == api_key.id).values(last_used_at=datetime.now(UTC)))

    # Fetch the owning user for context (user_id may be NULL for service keys)
    role = "api_service"
    email = f"api-key:{api_key.key_prefix}"
    user_id = api_key.user_id or api_key.tenant_id  # fallback to tenant UUID

    if api_key.user_id is not None:
        user_res = await db.execute(
            select(User).where(User.id == api_key.user_id, User.is_active == True)  # noqa: E712
        )
        user = user_res.scalar_one_or_none()
        if user is None:
            # The key names a principal who is deactivated or gone. Falling
            # through here left the key working under the generic
            # ``api_service`` role, so deprovisioning a user did not end the
            # programmatic access they had minted for themselves. A key
            # belongs to whoever owns it, and an owner who cannot sign in
            # cannot act through it either.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        role = user.role
        email = user.email
        user_id = user.id

    return CurrentUser(
        user_id=user_id,
        tenant_id=api_key.tenant_id,
        role=role,
        email=email,
        scopes=api_key.scopes or [],
        api_key_prefix=api_key.key_prefix,
    )


def _record_authenticated_principal(request: Request, principal: CurrentUser) -> CurrentUser:
    """Record the **verified** principal for the audit middleware, and return it.

    :class:`~app.middleware.audit_middleware.AuditMiddleware` runs outside this
    dependency and used to decode the Authorization header with
    ``verify_signature=False`` to label its rows, which let an unauthenticated
    caller forge entries in the tamper-evident audit chain
    (GHSA-w4r8-969c-67p2). It now reads the actor from this stashed principal
    instead, so only a credential that actually verified is audited, as the
    identity it verified to.

    ``request.state`` is backed by the ASGI ``scope["state"]`` dict — the same
    dict for every ``Request`` built from this scope — which is the channel
    ``app.services.audit`` already uses to signal the middleware across the
    ``BaseHTTPMiddleware`` task boundary. A request that fails authentication
    raises before reaching here, so nothing is recorded for it.

    It is also where every HTTP principal is bound to the request it
    authenticated on, which is what attribute conditions are judged
    against. Doing it here rather than in each of the four credential
    branches is the point: a fifth credential type added later gets the
    binding by passing through the funnel it already has to pass through.
    """
    request.state.aisoc_authenticated_principal = principal
    return principal.bind_connection_attributes(request)


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """Resolve Bearer token to CurrentUser.

    Accepts JWT tokens, aisoc_ API keys, and the shared service token used for
    service-to-service calls.

    The service path exists because the agents service had no usable way to
    reach this API at all. Its tools authenticated with ``AISOC_AGENTS_API_KEY``,
    which no compose file, ``.env.example`` or Helm value ever delivered, so on
    a default deployment every customer tool, the hunting agent and the sandbox
    tool answered "could not check" — a gap in visibility a model reports and an
    operator never sees. Setting that key would not have fixed it either: one
    key belongs to one tenant, so every tenant's investigation would have read
    that tenant's estate.

    In development mode an unauthenticated request resolves to a deterministic
    demo user (see ``app.api.v1.dev_auth``). Production requires a bearer token.

    Every principal this returns is first recorded on ``request.state`` via
    :func:`_record_authenticated_principal` so the audit middleware audits the
    verified identity rather than an unverified token (GHSA-w4r8-969c-67p2).
    """
    if credentials is None:
        if is_dev_mode():
            return _record_authenticated_principal(
                request,
                CurrentUser(
                    user_id=DEMO_USER_ID,
                    tenant_id=DEMO_TENANT_ID,
                    role=DEMO_USER_ROLE,
                    email=DEMO_USER_EMAIL,
                ),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # --- workload identity path ---
    #
    # Ahead of the API-key branch because `aisoc_wl_` is a strict extension
    # of `aisoc_`, so `startswith(_API_KEY_PREFIX)` matches a workload
    # secret too and would resolve it as an unknown API key — a 401 that
    # reads as a bad credential rather than as a misordered branch.
    # `test_workload_identity.py` asserts this ordering so it survives an
    # edit that does not know why it is here.
    declared_tenant = request.headers.get(SERVICE_TENANT_HEADER)
    if is_workload_secret(token):
        return _record_authenticated_principal(request, await _resolve_workload_principal(token, declared_tenant, db))

    # --- API key path ---
    if token.startswith(_API_KEY_PREFIX):
        return _record_authenticated_principal(request, await _resolve_api_key(token, db))

    # --- trusted peer service acting for one declared tenant ---
    #
    # Ahead of the JWT path because a service token is not a JWT and would
    # otherwise be decoded, fail, and answer "Could not validate credentials",
    # which is what it did.
    # `declared_tenant` is read off the request above rather than declared as
    # a `Header` parameter. Declaring it adds a 422 response to all 456
    # operations in the published spec, because a parameter that exists can
    # fail validation -- and this is how a peer *service* names the tenant it
    # acts for, not part of the contract a customer codes against.
    service_principal = await _resolve_service_principal(token, declared_tenant, db)
    if service_principal is not None:
        return _record_authenticated_principal(request, service_principal)

    # --- JWT path ---
    return _record_authenticated_principal(request, await resolve_jwt_principal(token, db))


async def resolve_jwt_principal(token: str, db: AsyncSession) -> CurrentUser:
    """Turn an access token into the principal the API acts for.

    **The one place a JWT becomes a principal.** It was inlined in
    `get_current_user`, and `graph_ws.py` resolved its own copy by hand for the
    WebSocket upgrade -- under a docstring claiming "we reuse the same helpers
    `get_current_user` uses so the auth contract is identical". It did not: the
    copy checked neither session revocation nor database RBAC, so a
    de-provisioned principal kept a live subscription to the tenant graph
    stream while the same token was answered 401 over HTTP
    (GHSA-25fh-rxp8-67j8).

    Two implementations of one security contract diverge, and the question is
    only when. So there is one, and both callers use it.

    Raises `HTTPException(401)` on every rejection; the WebSocket caller
    translates that into a close frame, because an upgrade response cannot
    carry `WWW-Authenticate`.
    """
    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub")  # type: ignore[assignment]
        token_type: str = payload.get("type", "access")
        if user_id is None or token_type != "access":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        ) from e

    try:
        subject_uuid = uuid.UUID(user_id)
    except ValueError as exc:
        # A `sub` that is not a UUID used to raise `ValueError` out of this
        # function and become a 500. It is a malformed credential, which is a
        # 401.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    result = await db.execute(
        select(User).where(User.id == subject_uuid, User.is_active == True)  # noqa: E712
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # A token minted before the principal's sessions were revoked stays
    # refused even after the principal is re-activated. Without this, the
    # `is_active` check above ends a session only for as long as the flag is
    # down, and re-enabling a deprovisioned account resurrects every token
    # still inside its expiry window.
    if token_is_revoked(payload.get("iat"), user.sessions_revoked_at):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Resolved once, here, where a session already exists. Doing it in the
    # permission dependency instead would mean a query per check and would
    # make a database blip deny every request.
    #
    # Fails *open to the static map* rather than closed, deliberately: this
    # is authentication, and a transient database fault must not lock every
    # operator out of the platform mid-incident. The static map is the
    # behaviour that shipped for the last fourteen releases, so falling back
    # to it is no worse than before — whereas failing closed would be a new
    # and much louder outage. The event is logged at error, not debug.
    resolved: frozenset[str] | None = None
    elevation: tuple[PrivilegeGrant, ...] = ()
    try:
        resolved = await resolve_permissions(db, tenant_id=user.tenant_id, user_id=user.id, static_role=user.role)
        elevation = await resolve_elevation(db, tenant_id=user.tenant_id, user_id=user.id)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "permission resolution failed for user %s; falling back to the static role map: %s",
            str(user.id).replace("\r", "").replace("\n", " ")[:64],
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )

    # Conditions fail **closed**, which is the opposite of the line above
    # and is the right direction for each. Permissions failing open to the
    # static map keeps a database blip from locking every operator out
    # mid-incident — it restores the behaviour that shipped for fourteen
    # releases. A condition failing open would *remove* a restriction an
    # operator configured, turning the same blip into a silent widening
    # nobody is paged for.
    conditions = await resolve_conditions(db, tenant_id=user.tenant_id)

    return CurrentUser(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
        resolved_permissions=resolved,
        elevation=elevation,
        conditions=conditions,
    )


async def get_current_active_user(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    return current_user


def require_permission(permission: str):
    """Factory for permission-checking dependencies, database-backed.

    This used to consult the hardcoded `ROLE_PERMISSIONS` map only, while a
    second factory, `require_permission_db`, consulted the `user_roles` /
    `role_permissions` tables the console's RBAC administration surface
    writes to. 275 routes used the first and 27 used the second, so an
    operator could grant a permission, watch it appear in the UI, and have
    275 of 302 routes ignore it.

    The resolution happens once, in `get_current_user`, where a session
    already exists — not here. A query per permission check would mean a
    database blip denies every request, turning a transient fault into a
    platform-wide outage at the authorization layer, and it broke 84 tests
    that legitimately drive routes with a mocked session.

    So this stays synchronous and reads what authentication resolved.

    API keys keep their own path. A key's scopes are an explicit, narrower
    grant chosen at mint time — resolving a key to its owner's full role
    would widen it, which is the opposite of what a scoped key is for.
    """

    async def _check(current_user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        current_user.require_permission(permission)
        return current_user

    return _check


async def require_interactive_session(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    """Refuse any principal that is not a person at a console.

    **What this is for.** Enrolling or removing an authentication factor is
    not an ordinary write. A factor is what *establishes* a session, so a
    bearer credential that can enrol one can mint the thing that outranks it,
    and every scope boundary in the product becomes advisory: a key scoped to
    ``alerts:read`` registered a passkey on its owner's account, signed in
    with it, and got a console session carrying the owner's full role
    (GHSA-jfvq-94hv-4wrj). The enrolled factor then outlived revocation of
    the key, because deprovisioning revokes API keys and not passkeys.

    **Why one dependency rather than a check per route.** The rule is a
    property of the *credential*, not of any route, and the four routes that
    were reported were not the whole surface — ``DELETE
    /passkeys/credentials/{id}`` answered 204 to a key with ``scopes: []``
    and appears in no report. A check written per call site is a list that
    goes stale the next time somebody adds a factor type; this is the funnel
    every one of them already passes through.

    **Why not a permission.** A scope would be mintable onto a key, which is
    exactly the credential this refuses. ``auth_method()`` already
    distinguishes the four kinds — it exists so a tenant can write "from a
    console session, not from a key somebody minted a year ago" as an
    attribute condition — so the property is read from there rather than
    invented a second time.

    Workload and service-token principals are refused for the same reason and
    more bluntly: they are not people, and they have no account to enrol a
    factor onto. ``user_id`` for both is a ``uuid5`` of the service name.

    The enrolment-challenge path in ``mfa.py`` deliberately does **not** come
    through here: a user whose tenant has just turned TOTP enforcement on
    holds no session yet and must enrol to get one. That caller proves
    possession of a purpose-scoped challenge token instead, which is a
    narrower credential than a session rather than a wider one.
    """
    method = current_user.auth_method()
    if method != "session":
        # The account, not the credential. An earlier version logged
        # `api_key_prefix` so an operator could tell which key was refused,
        # and CodeQL was right to flag it (`py/clear-text-logging-sensitive-
        # data`): that value is the first 20 characters of the key itself. It
        # belongs in the audit column it already has and nowhere else, and no
        # other code in this tree logs it. The user id answers the question an
        # operator actually has — whose account was this aimed at — and is not
        # a fragment of a credential.
        #
        # The event is named `non_session_principal_refused` rather than
        # `..._credential_...`: semgrep's `python-logger-credential-disclosure`
        # matches the word in a logger call and raised a WARNING on the earlier
        # spelling. Nothing secret was being logged either way, and the right
        # answer to a heuristic firing on a *name* is to change the name, not
        # to raise the scanner's ceiling.
        logger.warning(
            "deps.non_session_principal_refused_at_auth_state method=%s user=%s",
            str(method).replace("\r", "").replace("\n", " ")[:32],
            str(current_user.user_id).replace("\r", "").replace("\n", " ")[:64],
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This endpoint changes authentication state and requires an interactive session. "
                f"The credential presented authenticated as '{method}'."
            ),
        )
    return current_user


# Type aliases
DBSession = Annotated[AsyncSession, Depends(get_db)]
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
#: A principal that signed in, as opposed to one that presented a key.
#: Required by every route that enrols or removes an authentication factor.
SessionUser = Annotated[CurrentUser, Depends(require_interactive_session)]


# Re-export TenantDBSession for convenience so endpoints can import from one place
# Actual implementation lives in app.db.rls to avoid circular imports.
def _get_tenant_db_session() -> "Annotated[AsyncSession, ...]":  # pragma: no cover
    from app.db.rls import TenantDBSession as _T  # noqa: PLC0415

    return _T  # type: ignore[return-value]
