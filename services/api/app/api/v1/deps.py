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
from typing import Annotated

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
from app.core.permission_cache import grants, resolve_permissions
from app.core.security import decode_token, has_permission, hash_api_key, token_is_revoked
from app.db.database import get_db
from app.models.tenant import ApiKey, Tenant, User

logger = logging.getLogger("aisoc.deps")

bearer_scheme = HTTPBearer(auto_error=False)

_API_KEY_PREFIX = "aisoc_"


class CurrentUser:
    """Resolved authenticated user context.

    ``scopes`` is only populated when authenticated via an API key; it
    holds the explicit permission strings granted to that key.  When ``None``
    the user's role-based permissions apply.

    Permission resolution order:
      1. API-key scopes (explicit list)
      2. RBAC ``user_roles`` → ``role_permissions`` (database-backed)
      3. Static ``ROLE_PERMISSIONS`` fallback (legacy / bootstrap)
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

    def __repr__(self) -> str:
        # Without this a stray `str(user)` persists `<...CurrentUser object at
        # 0x...>` into whatever column it was bound to, which is what happened
        # to three actor columns. `email` is deliberately omitted: this value
        # reaches logs and tracebacks, and the address of the person holding
        # the session is not something a stack trace should carry.
        return f"CurrentUser(user_id={self.user_id}, tenant_id={self.tenant_id}, role={self.role})"

    def require_permission(self, permission: str) -> None:
        if self.scopes is not None:
            # API-key path: check explicit scopes list
            allowed = "*" in self.scopes or permission in self.scopes or f"{permission.split(':')[0]}:*" in self.scopes
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key missing scope: {permission}",
                )
        elif self.resolved_permissions is not None:
            # Database-backed: what the RBAC tables actually grant.
            if not grants(self.resolved_permissions, permission):
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

    async def has_permission_db(self, permission: str, db: AsyncSession) -> bool:
        """Check permission via RBAC tables (granular RBAC).

        Falls back to the static ROLE_PERMISSIONS map when the user has
        no rows in ``user_roles`` (e.g. fresh tenants not yet migrated).
        """
        if self.scopes is not None:
            return "*" in self.scopes or permission in self.scopes or f"{permission.split(':')[0]}:*" in self.scopes

        # Query RBAC tables
        from app.models.rbac import Permission as PermModel  # noqa: PLC0415
        from app.models.rbac import Role, RolePermission, UserRole

        result = await db.execute(
            select(PermModel.name)
            .join(RolePermission, RolePermission.permission_id == PermModel.id)
            .join(Role, Role.id == RolePermission.role_id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == self.user_id, Role.tenant_id == self.tenant_id)
        )
        db_perms: list[str] = [row[0] for row in result.all()]

        if db_perms:
            return "*" in db_perms or permission in db_perms or f"{permission.split(':')[0]}:*" in db_perms

        # Fallback to static map
        return has_permission(self.role, permission)

    async def require_permission_db(self, permission: str, db: AsyncSession) -> None:
        """Async permission check (RBAC tables then static fallback)."""
        if not await self.has_permission_db(permission, db):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )


#: Header a trusted service uses to declare which tenant it is acting for.
#: Spelled identically to ``TENANT_HEADER`` in the vendored
#: ``app/security/tenant_scope.py`` that the other services already use, so
#: one service does not have to know which of two names a peer expects.
SERVICE_TENANT_HEADER = "X-AiSOC-Tenant-ID"

#: What a service principal may do, and nothing else.
#:
#: Deliberately an explicit read-only list rather than the wildcard. The
#: credential reaches every route in the API, so granting it ``*`` would make
#: one shared secret equivalent to ``platform_admin`` on every tenant at once.
#: These are the permissions the agents service's own tools need:
#: ``connectors:read`` for the backend catalogue and the SIEM fan-out,
#: ``actions:read`` for a read-only vendor verb, ``lake:query`` for a hunt
#: plan, ``hunts:read`` for the hunting agent, and ``alerts:read`` for the
#: alert an investigation is about.
#:
#: Anything that changes state at a vendor or in the database is absent on
#: purpose: those go through the live-action contract with its approval
#: matrix, not through a service token.
SERVICE_PRINCIPAL_PERMISSIONS: frozenset[str] = frozenset(
    {
        "alerts:read",
        "cases:read",
        "connectors:read",
        "actions:read",
        "lake:query",
        "hunts:read",
        "threat_intel:read",
    }
)

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
    """
    if credentials is None:
        if is_dev_mode():
            return CurrentUser(
                user_id=DEMO_USER_ID,
                tenant_id=DEMO_TENANT_ID,
                role=DEMO_USER_ROLE,
                email=DEMO_USER_EMAIL,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    # --- API key path ---
    if token.startswith(_API_KEY_PREFIX):
        return await _resolve_api_key(token, db)

    # --- trusted peer service acting for one declared tenant ---
    #
    # Ahead of the JWT path because a service token is not a JWT and would
    # otherwise be decoded, fail, and answer "Could not validate credentials",
    # which is what it did.
    # Read off the request rather than declared as a `Header` parameter.
    # Declaring it adds a 422 response to all 456 operations in the published
    # spec, because a parameter that exists can fail validation -- and this is
    # how a peer *service* names the tenant it acts for, not part of the
    # contract a customer codes against.
    declared_tenant = request.headers.get(SERVICE_TENANT_HEADER)
    service_principal = await _resolve_service_principal(token, declared_tenant, db)
    if service_principal is not None:
        return service_principal

    # --- JWT path ---
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

    result = await db.execute(
        select(User).where(User.id == uuid.UUID(user_id), User.is_active == True)  # noqa: E712
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
    try:
        resolved = await resolve_permissions(db, tenant_id=user.tenant_id, user_id=user.id, static_role=user.role)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "permission resolution failed for user %s; falling back to the static role map: %s",
            str(user.id).replace("\r", "").replace("\n", " ")[:64],
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )

    return CurrentUser(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
        resolved_permissions=resolved,
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


# Type aliases
DBSession = Annotated[AsyncSession, Depends(get_db)]
AuthUser = Annotated[CurrentUser, Depends(get_current_user)]


# Re-export TenantDBSession for convenience so endpoints can import from one place
# Actual implementation lives in app.db.rls to avoid circular imports.
def _get_tenant_db_session() -> "Annotated[AsyncSession, ...]":  # pragma: no cover
    from app.db.rls import TenantDBSession as _T  # noqa: PLC0415

    return _T  # type: ignore[return-value]
