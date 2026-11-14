"""Tenant context propagation.

The contract:
  - Every request that hits a tenant-scoped route MUST resolve to a
    `TenantContext` via the `require_tenant` FastAPI dependency.
  - Every DB query against `Case`, `Alert`, `IOC`, `HitlRequest`,
    `ToolCall`, `AgentTrace`, `EpisodicMemory`, and `ToolOutputAudit`
    MUST be scoped through `apply_tenant_filter()` or by checking
    `ctx.assert_can_view(row.tenant_id)`.
  - Agents and background tasks (orchestrator, HITL watcher) receive an
    explicit `TenantContext` constructor argument — there is no implicit
    "current tenant" global.

For MSSP analysts the same JWT can carry an `mssp_parent_tid` plus an
`allowed_tenants` list; the context exposes `viewable_tenant_ids()` for
list queries that span the MSSP fleet, plus `assert_can_view()` for
single-tenant reads.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings
from app.security.jwt import (
    JwtError,
    TenantClaims,
    claims_from_payload,
    decode_token,
)


class TenantAccessDenied(Exception):
    """Caller is authenticated but not authorized for the requested tenant."""


@dataclass(frozen=True)
class TenantContext:
    """The resolved per-request tenant identity.

    `active_tenant_id` is the tenant whose data the caller is currently
    looking at. For ordinary tenant tokens this equals `claims.tenant_id`.
    For MSSP tokens, the analyst can pivot into a child tenant via the
    `X-AISOC-Tenant` header, in which case `active_tenant_id` reflects the
    pivot target (after authorization).
    """

    claims: TenantClaims
    active_tenant_id: str

    @property
    def subject(self) -> str:
        return self.claims.subject

    @property
    def is_mssp(self) -> bool:
        return self.claims.is_mssp

    @property
    def is_admin(self) -> bool:
        return self.claims.is_admin

    def viewable_tenant_ids(self) -> list[str] | None:
        """For list queries: the set of tenant_ids this caller can read.

        Returns `None` to mean "no filter" (platform admin, or MSSP whose
        token carries no explicit child list). Callers that want a
        defense-in-depth posture should still pass `active_tenant_id`
        rather than skipping the filter.
        """
        if self.is_admin:
            return None
        if self.is_mssp:
            if not self.claims.allowed_tenants:
                # MSSP with no explicit list: list view is restricted to the
                # currently-active tenant to avoid leaking siblings.
                return [self.active_tenant_id]
            return list(self.claims.allowed_tenants) + [self.claims.tenant_id]
        return [self.claims.tenant_id]

    def assert_can_view(self, tenant_id: str | None) -> None:
        """Raise TenantAccessDenied if `tenant_id` is outside this context's reach."""
        if tenant_id is None:
            # Legacy rows without a tenant_id are treated as the default
            # tenant for migration safety.
            tenant_id = settings.default_tenant
        if not self.claims.can_view_tenant(tenant_id):
            raise TenantAccessDenied(
                f"caller {self.subject} (tid={self.claims.tenant_id}) "
                f"not authorized for tenant_id={tenant_id}"
            )


# ── FastAPI plumbing ─────────────────────────────────────────────────────

_bearer_scheme = HTTPBearer(auto_error=False)


def _http_unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": 'Bearer realm="aisoc"'},
    )


def _http_forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _resolve_active_tenant(
    claims: TenantClaims, pivot: str | None
) -> str:
    """Decide which tenant_id the caller is *currently* operating against.

    - No pivot header → use the claims' primary tenant.
    - Pivot to own tenant → fine.
    - MSSP pivot to allowed child → fine.
    - Admin can pivot anywhere.
    """
    if pivot is None or pivot == "":
        return claims.tenant_id
    if claims.can_view_tenant(pivot):
        return pivot
    raise _http_forbidden(
        f"caller not authorized to pivot to tenant_id={pivot}"
    )


def require_tenant(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    x_tenant: str | None = Header(default=None, alias="X-AISOC-Tenant"),
) -> TenantContext:
    """FastAPI dependency: produce a `TenantContext` or raise 401/403.

    Auth precedence:
      1. `Authorization: Bearer <jwt>` header → decoded + validated.
      2. If `AISOC_DEV_ALLOW_ANON_TENANT=true` (default in dev) AND no
         credentials were provided → fall back to a synthetic `default_tenant`
         context. This keeps the demo bootstrap working with no token.
      3. Otherwise → 401.

    Production deployments MUST set `AISOC_DEV_ALLOW_ANON_TENANT=false`.
    """
    if credentials and credentials.scheme.lower() == "bearer" and credentials.credentials:
        try:
            payload = decode_token(credentials.credentials)
            claims = claims_from_payload(payload)
        except JwtError as exc:
            raise _http_unauthorized(f"invalid token: {exc}") from exc
        try:
            active = _resolve_active_tenant(claims, x_tenant)
        except HTTPException:
            raise
        ctx = TenantContext(claims=claims, active_tenant_id=active)
        # Stash on request.state for downstream middleware / loggers.
        request.state.tenant = ctx
        return ctx

    if settings.dev_allow_anon_tenant:
        claims = TenantClaims(
            tenant_id=settings.default_tenant,
            subject="dev-anon",
            roles=("analyst",),
        )
        # In anon mode we still respect the pivot header within the
        # default tenant only — pivoting elsewhere requires a real token.
        if x_tenant and x_tenant != settings.default_tenant:
            raise _http_forbidden(
                "anonymous mode can only access the default tenant"
            )
        ctx = TenantContext(
            claims=claims, active_tenant_id=settings.default_tenant
        )
        request.state.tenant = ctx
        return ctx

    raise _http_unauthorized("missing bearer token")


def require_admin(ctx: TenantContext = Depends(require_tenant)) -> TenantContext:
    """Stronger dependency for routes that mutate platform-wide state."""
    if not ctx.is_admin:
        raise _http_forbidden("admin role required")
    return ctx


# ── Query helpers ────────────────────────────────────────────────────────

def apply_tenant_filter(query, tenant_id_column, ctx: TenantContext):
    """Apply tenant scoping to a SQLModel `select(...)` query.

    Usage:

        q = select(Case)
        q = apply_tenant_filter(q, Case.tenant_id, ctx)

    Platform admins get no filter applied. MSSP analysts get an `IN (...)`
    filter against their viewable set. Regular tenants get an `=` filter
    against the active tenant.
    """
    viewable = ctx.viewable_tenant_ids()
    if viewable is None:
        return query
    if len(viewable) == 1:
        return query.where(tenant_id_column == viewable[0])
    return query.where(tenant_id_column.in_(viewable))


def ensure_row_visible(ctx: TenantContext, row_tenant_id: str | None) -> None:
    """Raise 403 if `row_tenant_id` is outside the caller's reach.

    The query layer is the first line of defense, but row-level reads
    (`session.get(Case, id)`) bypass `.where(...)`. Wrap those with this.
    """
    try:
        ctx.assert_can_view(row_tenant_id)
    except TenantAccessDenied as exc:
        raise _http_forbidden(str(exc)) from exc


def viewable_tenants_or_active(ctx: TenantContext) -> Iterable[str]:
    """Like `viewable_tenant_ids()` but always returns at least `[active]`.

    Useful for places where `None` ("no filter") would be unsafe — e.g.
    seeding scopes or background tasks that must not span every tenant.
    """
    ids = ctx.viewable_tenant_ids()
    if ids is None:
        return [ctx.active_tenant_id]
    return ids
