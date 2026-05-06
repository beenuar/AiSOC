"""MSSP parent-tenant console endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.mssp import MSSPDelegation, MSSPTenantMetrics, MSSPTenantNote
from app.models.tenant import Tenant, User

router = APIRouter(prefix="/mssp", tags=["mssp"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ChildTenantOut(BaseModel):
    id: uuid.UUID
    name: str
    mssp_role: str
    created_at: str

    class Config:
        from_attributes = True


class TenantNoteCreate(BaseModel):
    child_id: uuid.UUID
    body: str


class TenantNoteOut(TenantNoteCreate):
    id: uuid.UUID
    parent_id: uuid.UUID
    author_id: uuid.UUID | None
    created_at: str

    class Config:
        from_attributes = True


class DelegationCreate(BaseModel):
    child_tenant_id: uuid.UUID
    granted_role: str = "soc_analyst"
    expires_at: datetime | None = None


class DelegationOut(DelegationCreate):
    id: uuid.UUID
    parent_tenant_id: uuid.UUID
    granted_by_user: uuid.UUID | None
    revoked_at: datetime | None
    created_at: str

    class Config:
        from_attributes = True


class MetricsOut(BaseModel):
    tenant_id: uuid.UUID
    snapshot_at: str
    open_alerts: int
    critical_alerts: int
    open_cases: int
    mttr_minutes: float | None
    sla_breaches: int
    connector_count: int
    health_score: float | None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Child-tenant management
# ---------------------------------------------------------------------------


@router.get("/children", response_model=list[ChildTenantOut])
async def list_child_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Tenant]:
    """Return all child tenants of the current parent tenant."""
    result = await db.execute(select(Tenant).where(Tenant.parent_tenant_id == current_user.tenant_id))
    return list(result.scalars().all())


@router.post("/children/{child_id}/onboard", status_code=status.HTTP_200_OK)
async def onboard_child_tenant(
    child_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Link an existing tenant as a child of the current MSSP tenant."""
    child = await db.get(Tenant, child_id)
    if not child:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if child.parent_tenant_id and child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=409, detail="Tenant already has a parent")
    child.parent_tenant_id = current_user.tenant_id  # type: ignore[assignment]
    child.mssp_role = "child"  # type: ignore[assignment]
    parent = await db.get(Tenant, current_user.tenant_id)
    if parent:
        parent.mssp_role = "parent"  # type: ignore[assignment]
    await db.commit()
    return {"status": "ok", "child_id": str(child_id)}


# ---------------------------------------------------------------------------
# Cross-tenant notes
# ---------------------------------------------------------------------------


@router.get("/notes", response_model=list[TenantNoteOut])
async def list_notes(
    child_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPTenantNote]:
    q = select(MSSPTenantNote).where(MSSPTenantNote.parent_id == current_user.tenant_id)
    if child_id:
        q = q.where(MSSPTenantNote.child_id == child_id)
    q = q.order_by(MSSPTenantNote.created_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/notes", response_model=TenantNoteOut, status_code=status.HTTP_201_CREATED)
async def create_note(
    body: TenantNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPTenantNote:
    note = MSSPTenantNote(
        parent_id=current_user.tenant_id,
        child_id=body.child_id,
        body=body.body,
        author_id=current_user.id,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return note


# ---------------------------------------------------------------------------
# Cross-tenant delegations
# ---------------------------------------------------------------------------


@router.get("/delegations", response_model=list[DelegationOut])
async def list_delegations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPDelegation]:
    result = await db.execute(
        select(MSSPDelegation)
        .where(
            MSSPDelegation.parent_tenant_id == current_user.tenant_id,
            MSSPDelegation.revoked_at.is_(None),
        )
        .order_by(MSSPDelegation.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/delegations", response_model=DelegationOut, status_code=status.HTTP_201_CREATED)
async def create_delegation(
    body: DelegationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPDelegation:
    delegation = MSSPDelegation(
        parent_tenant_id=current_user.tenant_id,
        child_tenant_id=body.child_tenant_id,
        granted_role=body.granted_role,
        granted_by_user=current_user.id,
        expires_at=body.expires_at,
    )
    db.add(delegation)
    await db.commit()
    await db.refresh(delegation)
    return delegation


@router.delete("/delegations/{delegation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_delegation(
    delegation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    delegation = await db.get(MSSPDelegation, delegation_id)
    if not delegation or delegation.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Delegation not found")
    delegation.revoked_at = datetime.now(UTC)  # type: ignore[assignment]
    await db.commit()


# ---------------------------------------------------------------------------
# Tenant rollup metrics
# ---------------------------------------------------------------------------


@router.get("/metrics", response_model=list[MetricsOut])
async def list_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPTenantMetrics]:
    """Return the latest metrics snapshot for every child tenant."""
    # Get child tenant ids
    children_result = await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == current_user.tenant_id))
    child_ids = list(children_result.scalars().all())
    if not child_ids:
        return []

    # Subquery: most recent snapshot per tenant
    subq = (
        select(
            MSSPTenantMetrics.tenant_id,
            MSSPTenantMetrics.snapshot_at,
        )
        .where(MSSPTenantMetrics.tenant_id.in_(child_ids))
        .order_by(MSSPTenantMetrics.tenant_id, MSSPTenantMetrics.snapshot_at.desc())
        .distinct(MSSPTenantMetrics.tenant_id)
        .subquery()
    )

    result = await db.execute(
        select(MSSPTenantMetrics).join(
            subq,
            (MSSPTenantMetrics.tenant_id == subq.c.tenant_id) & (MSSPTenantMetrics.snapshot_at == subq.c.snapshot_at),
        )
    )
    return list(result.scalars().all())
