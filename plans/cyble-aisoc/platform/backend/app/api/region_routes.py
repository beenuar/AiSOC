"""Multi-region admin + residency-aware request fronting (t6-multi-region).

  GET   /regions/mesh                        Live mesh + local region.
  GET   /regions/tenants/{tenant_id}/home    Resolve a tenant's home region.
  PUT   /regions/tenants/{tenant_id}/home    Pin a tenant's home region.
  GET   /regions/tenants/{tenant_id}/events  Audit trail.

  GET   /regions/route                       Decide the residency outcome
                                             for the active tenant. Used by
                                             the gateway to decide whether
                                             to serve, forward, or reject.

The route endpoint is the integration point: every external
caller can hit it before its real request and get back either
``serve_locally``, ``forward_to_peer`` (with the peer URL), or
``reject_residency`` (with the reason). The gateway can use this
to short-circuit at the edge instead of accepting the request body
into a region that shouldn't have it.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.regions import (
    RegionResolution,
    decide_residency,
)
from app.regions.service import (
    get_region_mesh,
    home_region_for,
    list_region_events,
    pin_home_region,
    resolve_for_tenant,
)
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/regions", tags=["regions"])


def _region_to_dict(region) -> dict[str, Any]:  # noqa: ANN001 - dataclass at runtime
    return {
        "region_id": region.region_id,
        "base_url": region.base_url,
        "residency_zone": region.residency_zone,
    }


@router.get("/mesh")
def get_mesh() -> dict[str, Any]:
    mesh = get_region_mesh()
    return {
        "local_region_id": mesh.local_region_id,
        "regions": [_region_to_dict(r) for r in mesh.regions],
        "allowed_residency_zones": sorted(mesh.allowed_residency_zones),
    }


@router.get("/tenants/{tenant_id}/home")
def get_tenant_home(tenant_id: str) -> dict[str, Any]:
    pinned = home_region_for(tenant_id)
    if pinned is None:
        return {
            "tenant_id": tenant_id,
            "configured": False,
            "region_id": None,
            "residency_zone": None,
        }
    return {
        "tenant_id": pinned.tenant_id,
        "configured": True,
        "region_id": pinned.region_id,
        "residency_zone": pinned.residency_zone,
        "pinned_by": pinned.pinned_by,
        "note": pinned.note,
        "updated_at": pinned.updated_at.isoformat(),
    }


class PinHomeRegionRequest(BaseModel):
    region_id: str = Field(min_length=1, max_length=64)
    actor: Optional[str] = Field(default=None, max_length=120)
    note: Optional[str] = Field(default=None, max_length=2000)


@router.put("/tenants/{tenant_id}/home")
def put_tenant_home(
    tenant_id: str,
    body: PinHomeRegionRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Pin a tenant's home region.

    Admin-only — flipping a tenant's residency zone is a regulated
    event. We deliberately do not let the tenant itself modify the
    record.
    """
    if not ctx.is_admin:
        raise HTTPException(
            status_code=403,
            detail="pinning a tenant's home region requires admin privileges",
        )
    try:
        row = pin_home_region(
            tenant_id,
            region_id=body.region_id,
            actor=body.actor or ctx.subject,
            note=body.note or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "tenant_id": row.tenant_id,
        "region_id": row.region_id,
        "residency_zone": row.residency_zone,
        "pinned_by": row.pinned_by,
        "updated_at": row.updated_at.isoformat(),
    }


@router.get("/tenants/{tenant_id}/events")
def get_tenant_region_events(tenant_id: str) -> dict[str, Any]:
    events = list_region_events(tenant_id)
    return {
        "tenant_id": tenant_id,
        "count": len(events),
        "events": [
            {
                "id": e.id,
                "previous_region_id": e.previous_region_id,
                "previous_residency_zone": e.previous_residency_zone,
                "new_region_id": e.new_region_id,
                "new_residency_zone": e.new_residency_zone,
                "actor": e.actor,
                "note": e.note,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.get("/route")
def route_for_active_tenant(
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    """Compute the residency outcome for the active tenant.

    Returns:

    * ``serve_locally``  — the gateway should let the request through.
    * ``forward_to_peer`` — the gateway should proxy to the returned URL.
    * ``reject_residency`` — return 451 to the client.
    """
    decision = resolve_for_tenant(ctx.active_tenant_id)
    payload: dict[str, Any] = {
        "tenant_id": ctx.active_tenant_id,
        "resolution": decision.resolution.value,
        "reason": decision.reason,
    }
    if decision.target_region is not None:
        payload["target_region"] = _region_to_dict(decision.target_region)
    if decision.resolution == RegionResolution.reject_residency:
        # Surface a hint so the gateway can map this to HTTP 451.
        payload["http_status"] = 451
    return payload
