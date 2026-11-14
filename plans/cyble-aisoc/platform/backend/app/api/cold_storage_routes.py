"""Cold-storage REST surface (t6-cold-storage).

  GET   /cold-storage/stats                       Archive write counters.
  GET   /cold-storage/batches                     List per-day batches by tier.
  POST  /cold-storage/query                       Execute a cold-archive query.
  POST  /cold-storage/archive                     Push a single event into the
                                                  archive (admin-only —
                                                  intended for backfill /
                                                  testing, not production
                                                  ingest).

The archive endpoint is admin-only on purpose. Production ingest
goes through the OCSF normaliser path; the archive endpoint exists
so an operator can backfill historical evidence ahead of an
incident drill without standing up a full pipeline.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.cold_storage import (
    StorageTier,
    archive_event,
    cold_archive,
    query_cold_archive,
)
from app.security.tenant import TenantContext, require_tenant


router = APIRouter(prefix="/cold-storage", tags=["cold-storage"])


@router.get("/stats")
def get_stats(_: TenantContext = Depends(require_tenant)) -> dict[str, Any]:
    s = cold_archive.stats
    return {
        "hot_writes": s.hot_writes,
        "warm_writes": s.warm_writes,
        "cold_writes": s.cold_writes,
        "bytes_written": s.bytes_written,
    }


@router.get("/batches")
def list_batches(
    tier: str = StorageTier.WARM,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    if tier not in (StorageTier.WARM, StorageTier.COLD):
        raise HTTPException(
            status_code=400,
            detail=f"tier must be 'warm' or 'cold', got '{tier}'",
        )
    batches = cold_archive.list_batches(ctx.active_tenant_id, tier=tier)
    return {
        "tenant_id": ctx.active_tenant_id,
        "tier": tier,
        "count": len(batches),
        "batches": [
            {
                "day": b.day,
                "rows": b.rows,
                "bytes_on_disk": b.bytes_on_disk,
            }
            for b in batches
        ],
    }


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)


@router.post("/query")
def post_query(
    body: QueryRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    try:
        return query_cold_archive(query=body.query, tenant_id=ctx.active_tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class ArchiveEventRequest(BaseModel):
    event_time: str = Field(min_length=1)
    event_class: str = Field(min_length=1, max_length=64)
    extra: dict[str, Any] = Field(default_factory=dict)


@router.post("/archive")
def post_archive(
    body: ArchiveEventRequest,
    ctx: TenantContext = Depends(require_tenant),
) -> dict[str, Any]:
    if not ctx.is_admin:
        raise HTTPException(
            status_code=403,
            detail="archive ingest is admin-only",
        )
    payload: dict[str, Any] = {
        "tenant_id": ctx.active_tenant_id,
        "event_time": body.event_time,
        "event_class": body.event_class,
    }
    payload.update(body.extra)
    tier = archive_event(payload)
    if tier is None:
        raise HTTPException(
            status_code=400,
            detail="event missing required fields (tenant_id + event_time)",
        )
    return {"tier": tier, "tenant_id": ctx.active_tenant_id}
