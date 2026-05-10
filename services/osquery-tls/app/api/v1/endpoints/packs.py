"""Pack catalog API endpoints.

GET  /api/v1/osquery/packs                         – list all available packs
GET  /api/v1/osquery/packs/{pack_id}               – pack detail
GET  /api/v1/osquery/packs/{pack_id}/render        – render pack in target format
POST /api/v1/osquery/tenants/{tenant_id}/packs     – assign a pack to a tenant
GET  /api/v1/osquery/tenants/{tenant_id}/packs     – list tenant pack assignments
DELETE /api/v1/osquery/tenants/{tenant_id}/packs/{pack_id} – remove assignment
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.pack_assignment import OsqueryPackAssignment
from app.services.pack_loader import OsqueryPack, get_all_packs, get_pack

router = APIRouter(tags=["packs"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class PackQueryOut(BaseModel):
    name: str
    sql: str
    interval: int
    severity: str
    description: str
    mitre: list[str]

    model_config = {"from_attributes": True}


class PackOut(BaseModel):
    id: str
    name: str
    version: str
    platforms: list[str]
    description: str
    queries: list[PackQueryOut]

    @classmethod
    def from_pack(cls, pack: OsqueryPack) -> PackOut:
        return cls(
            id=pack.id,
            name=pack.name,
            version=pack.version,
            platforms=pack.platforms,
            description=pack.description,
            queries=[
                PackQueryOut(
                    name=q.name,
                    sql=q.sql,
                    interval=q.interval,
                    severity=q.severity,
                    description=q.description,
                    mitre=q.mitre,
                )
                for q in pack.queries
            ],
        )


class PackAssignRequest(BaseModel):
    pack_id: str
    enabled: bool = True


class PackAssignmentOut(BaseModel):
    pack_id: str
    enabled: bool
    assigned_at: str  # ISO-8601 string


# ---------------------------------------------------------------------------
# Pack catalog (read-only, no auth required for listing)
# ---------------------------------------------------------------------------


@router.get("/packs", response_model=list[PackOut])
async def list_packs() -> list[PackOut]:
    """Return all packs loaded from the on-disk YAML catalog."""
    return [PackOut.from_pack(p) for p in get_all_packs()]


@router.get("/packs/{pack_id}", response_model=PackOut)
async def get_pack_detail(pack_id: str) -> PackOut:
    """Return a single pack by id."""
    pack = get_pack(pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail=f"Pack '{pack_id}' not found")
    return PackOut.from_pack(pack)


@router.get("/packs/{pack_id}/render")
async def render_pack(
    pack_id: str,
    format: Annotated[
        Literal["osquery-json", "osctrl", "fleetdm"],
        Query(description="Target render format"),
    ] = "osquery-json",
) -> Any:
    """Render a pack in the requested format.

    - **osquery-json**: canonical osquery pack JSON (queries + optional discovery)
    - **osctrl**: osquery-json wrapped with pack metadata for osctrl
    - **fleetdm**: FleetDM pack dict format
    """
    pack = get_pack(pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail=f"Pack '{pack_id}' not found")

    if format == "osctrl":
        return pack.to_osctrl_format()
    elif format == "fleetdm":
        return pack.to_fleetdm_format()
    else:
        return pack.to_osquery_json()


# ---------------------------------------------------------------------------
# Tenant pack assignments
# ---------------------------------------------------------------------------


@router.post("/tenants/{tenant_id}/packs", status_code=201)
async def assign_pack(
    tenant_id: str,
    body: PackAssignRequest,
    db: AsyncSession = Depends(get_db),
) -> PackAssignmentOut:
    """Assign (or update) an osquery pack for a tenant."""
    if get_pack(body.pack_id) is None:
        raise HTTPException(status_code=404, detail=f"Pack '{body.pack_id}' not found in catalog")

    # Upsert: update enabled flag if assignment already exists
    result = await db.execute(
        select(OsqueryPackAssignment).where(
            OsqueryPackAssignment.tenant_id == tenant_id,
            OsqueryPackAssignment.pack_id == body.pack_id,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.enabled = body.enabled
        await db.commit()
        await db.refresh(existing)
        row = existing
    else:
        row = OsqueryPackAssignment(
            tenant_id=tenant_id,
            pack_id=body.pack_id,
            enabled=body.enabled,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)

    return PackAssignmentOut(
        pack_id=row.pack_id,
        enabled=row.enabled,
        assigned_at=row.assigned_at.isoformat(),
    )


@router.get("/tenants/{tenant_id}/packs", response_model=list[PackAssignmentOut])
async def list_tenant_packs(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
) -> list[PackAssignmentOut]:
    """List all pack assignments for a tenant."""
    result = await db.execute(select(OsqueryPackAssignment).where(OsqueryPackAssignment.tenant_id == tenant_id))
    rows = result.scalars().all()
    return [
        PackAssignmentOut(
            pack_id=r.pack_id,
            enabled=r.enabled,
            assigned_at=r.assigned_at.isoformat(),
        )
        for r in rows
    ]


@router.delete("/tenants/{tenant_id}/packs/{pack_id}", status_code=204)
async def remove_pack_assignment(
    tenant_id: str,
    pack_id: str,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Remove a pack assignment from a tenant."""
    await db.execute(
        delete(OsqueryPackAssignment).where(
            OsqueryPackAssignment.tenant_id == tenant_id,
            OsqueryPackAssignment.pack_id == pack_id,
        )
    )
    await db.commit()
