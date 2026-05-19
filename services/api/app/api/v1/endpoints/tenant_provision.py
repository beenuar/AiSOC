"""Admin tenant-provisioning endpoints — T6.1 (`tryaisoc.com` managed beta).

Exposes the bridge between the waitlist (built in commit 1 of this
work) and the live ``tenants`` table:

* ``POST /v1/admin/tenants/provision`` — given a waitlist entry id,
  promote it into a real tenant via
  :func:`app.services.tenant_provision.provision_from_waitlist`. Returns
  the new tenant's slug plus the initial admin invite URL the operator
  emails out.

* ``GET /v1/admin/tenants`` — list every tenant for the support team's
  triage view. Supports a couple of optional filters (``q=`` on slug or
  name, ``managed_only=`` to scope to managed-instance tenants).

Both endpoints are admin-only. We reuse the same permission resolution
the rest of the API uses (``has_permission_db``) and gate on a new
``admin:tenants`` permission, falling back to ``settings:write`` for
operators whose RBAC rows have not been migrated to the new permission
yet. The fallback keeps existing admins unblocked while the seed-data
migration that introduces ``admin:tenants`` lands separately.

Everything in this file is endpoint glue: validation, auth, response
shaping. The actual provisioning *logic* lives in
:mod:`app.services.tenant_provision.provisioner`, which is what we
unit-test.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession
from app.models.tenant import Tenant
from app.services.tenant_provision import (
    ProvisioningError,
    ProvisionResult,
    SlugCollisionError,
    WaitlistEntryNotFoundError,
    WaitlistEntryNotPromotableError,
    provision_from_waitlist,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/tenants", tags=["admin", "tenants"])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_LIST_LIMIT: int = 500
_DEFAULT_INVITE_BASE_URL: str = "https://tryaisoc.com"


# ---------------------------------------------------------------------------
# Wire shapes
# ---------------------------------------------------------------------------


class TenantProvisionRequest(BaseModel):
    """Body of the provision POST.

    ``waitlist_entry_id`` is the only required field. The optional
    ``seed_demo`` flag lets the operator turn off the starter dataset
    for tenants where the customer wants a clean slate.
    """

    waitlist_entry_id: uuid.UUID
    seed_demo: bool = True
    invite_base_url: str | None = Field(default=None, max_length=512)


class AdminInviteWire(BaseModel):
    token: str
    expires_at: str
    url: str


class InitialAdminUserWire(BaseModel):
    id: str
    email: str
    role: str


class TenantProvisionResponse(BaseModel):
    """JSON projection of :class:`ProvisionResult`.

    ``aisoc_credential_key_fingerprint`` is surfaced so the support
    UI can confirm at a glance which key the tenant is on. The
    *plaintext* key is never returned; it's only readable from the
    process environment where it was minted.
    """

    tenant_id: str
    tenant_slug: str
    tenant_name: str
    waitlist_entry_id: str
    admin_user: InitialAdminUserWire
    admin_invite: AdminInviteWire
    demo_seeded: bool
    aisoc_credential_key_fingerprint: str


class TenantListEntry(BaseModel):
    id: str
    name: str
    slug: str
    plan: str
    is_active: bool
    is_managed: bool
    provisioned_from_waitlist_id: str | None
    provisioned_at: str | None
    created_at: str


class TenantListResponse(BaseModel):
    tenants: list[TenantListEntry]
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _require_admin(user: AuthUser, db: AsyncSession) -> None:
    """Gate on ``admin:tenants`` (preferred) or ``settings:write`` (fallback)."""
    if await user.has_permission_db("admin:tenants", db):
        return
    if await user.has_permission_db("settings:write", db):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="admin:tenants (or settings:write) required",
    )


def _result_to_wire(result: ProvisionResult) -> TenantProvisionResponse:
    return TenantProvisionResponse(
        tenant_id=str(result.tenant_id),
        tenant_slug=result.tenant_slug,
        tenant_name=result.tenant_name,
        waitlist_entry_id=str(result.waitlist_entry_id),
        admin_user=InitialAdminUserWire(
            id=str(result.admin_user.id),
            email=result.admin_user.email,
            role=result.admin_user.role,
        ),
        admin_invite=AdminInviteWire(
            token=result.admin_invite.token,
            expires_at=result.admin_invite.expires_at.isoformat(),
            url=result.admin_invite.url,
        ),
        demo_seeded=result.demo_seeded,
        aisoc_credential_key_fingerprint=result.aisoc_credential_key_fingerprint,
    )


def _tenant_to_wire(row: Tenant) -> TenantListEntry:
    """Project a Tenant ORM row onto the wire shape.

    The provisioning metadata (``provisioned_from_waitlist_id`` /
    ``provisioned_at``) is read from the JSONB ``settings`` mirror
    because the ORM model does not yet declare those columns — see
    the TODO in
    :func:`app.services.tenant_provision.provisioner.provision_from_waitlist`.
    The raw-SQL UPDATE in the provisioner stamps the actual columns
    so direct DB queries still resolve.
    """
    settings_blob: dict[str, Any] = row.settings or {}
    return TenantListEntry(
        id=str(row.id),
        name=row.name,
        slug=row.slug,
        plan=row.plan or "starter",
        is_active=bool(row.is_active),
        is_managed=bool(settings_blob.get("managed", False)),
        provisioned_from_waitlist_id=settings_blob.get("provisioned_from_waitlist_id"),
        provisioned_at=settings_blob.get("provisioned_at"),
        created_at=row.created_at.isoformat() if row.created_at else "",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/provision",
    response_model=TenantProvisionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Promote a waitlist entry into a live managed tenant.",
)
async def provision_tenant(
    payload: TenantProvisionRequest,
    db: DBSession,
    user: AuthUser,
) -> TenantProvisionResponse:
    """Provision a new tenant from a waitlist entry.

    Idempotent on the waitlist entry id: a repeat call for an
    already-provisioned entry returns the existing tenant + a fresh
    invite link (the demo seed is *not* re-run). This keeps the
    support team from creating duplicate tenants if they click the
    button twice on a flaky network.
    """
    await _require_admin(user, db)

    invite_base = (payload.invite_base_url or _DEFAULT_INVITE_BASE_URL).strip()
    if not invite_base:
        invite_base = _DEFAULT_INVITE_BASE_URL

    try:
        result = await provision_from_waitlist(
            db,
            waitlist_entry_id=payload.waitlist_entry_id,
            actor_email=user.email,
            invite_base_url=invite_base,
            seed_demo=payload.seed_demo,
        )
    except WaitlistEntryNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="waitlist_entry_not_found",
        ) from exc
    except WaitlistEntryNotPromotableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except SlugCollisionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="slug_collision",
        ) from exc
    except ProvisioningError as exc:
        logger.exception("tenant_provision unexpected provisioning error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="provisioning_failed",
        ) from exc

    try:
        await db.commit()
    except SQLAlchemyError as exc:
        await db.rollback()
        logger.exception("tenant_provision commit error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="could_not_persist_tenant",
        ) from exc

    return _result_to_wire(result)


@router.get(
    "",
    response_model=TenantListResponse,
    summary="List tenants for the support team.",
)
async def list_tenants(
    db: DBSession,
    user: AuthUser,
    q: str | None = None,
    managed_only: bool = False,
    limit: int = 200,
) -> TenantListResponse:
    """Read-only tenant list, sorted by creation time descending."""
    await _require_admin(user, db)

    capped_limit = max(1, min(int(limit), _MAX_LIST_LIMIT))

    stmt = select(Tenant)
    if q:
        normalized_q = q.strip().lower()
        if normalized_q:
            # Slug is already lower-case; name is mixed-case so we
            # apply a case-insensitive match. ``ILIKE`` ships in
            # Postgres and is the cheapest approach for a small admin
            # surface.
            pattern = f"%{normalized_q}%"
            stmt = stmt.where(
                or_(
                    Tenant.slug.ilike(pattern),
                    Tenant.name.ilike(pattern),
                )
            )
    if managed_only:
        # JSONB path: tenants where settings->>'managed' is true. We
        # use ``text``-free syntax via ``op('->>')`` so the query plays
        # nicely with SQLAlchemy's type-aware binders.
        stmt = stmt.where(Tenant.settings.op("->>")("managed") == "true")

    stmt = stmt.order_by(desc(Tenant.created_at)).limit(capped_limit)
    rows = (await db.execute(stmt)).scalars().all()

    return TenantListResponse(
        tenants=[_tenant_to_wire(r) for r in rows],
        total=len(rows),
    )


__all__: list[str] = [
    "AdminInviteWire",
    "InitialAdminUserWire",
    "TenantListEntry",
    "TenantListResponse",
    "TenantProvisionRequest",
    "TenantProvisionResponse",
    "list_tenants",
    "provision_tenant",
    "router",
]
