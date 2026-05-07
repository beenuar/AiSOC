"""EASM (External Attack Surface Management) endpoints (Tier 3.6)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.database import get_db
from app.models.easm import ExternalAsset, ExternalAssetDrift, ExternalAssetType
from app.models.tenant import Tenant
from app.services.easm_discovery import run_discovery
from app.services.easm_drift import detect_drift

logger = logging.getLogger("aisoc.easm")

router = APIRouter(prefix="/easm", tags=["easm"])


class ScanRequest(BaseModel):
    tenant_id: UUID
    org_query: str | None = None
    ip_targets: list[str] = []
    asset_type: ExternalAssetType | None = None


async def _run_scan_job(
    tenant_id: UUID,
    org_query: str,
    ip_targets: list[str],
) -> None:
    """Background task that runs discovery + drift detection."""
    from app.db.database import AsyncSessionLocal as async_session_factory  # noqa: deferred

    try:
        discovered = await run_discovery(org_query, ip_targets=ip_targets or None)
        async with async_session_factory() as db:
            drift_records = await detect_drift(db, tenant_id, discovered)
            await db.commit()
            logger.info(
                "EASM scan complete: tenant=%s discovered=%d drifts=%d",
                tenant_id, len(discovered), len(drift_records),
            )
    except Exception:
        logger.exception("EASM scan failed for tenant=%s", tenant_id)


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
async def trigger_easm_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Trigger an EASM discovery scan for a tenant (Tier 3.6).

    Runs passive connectors (Shodan / Censys) and, when enabled, an active
    TCP connect probe.  Results are upserted into ``external_assets`` and
    drift events written to ``external_asset_drift``.
    """
    s = get_settings()
    if not s.AISOC_FEATURE_EASM:
        raise HTTPException(status_code=403, detail="EASM feature is disabled")

    tenant = await db.get(Tenant, body.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    org_query = body.org_query or tenant.name

    background_tasks.add_task(
        _run_scan_job,
        body.tenant_id,
        org_query,
        body.ip_targets,
    )

    return {
        "status": "accepted",
        "tenant_id": str(body.tenant_id),
        "org_query": org_query,
        "message": "EASM scan enqueued.",
    }


@router.get("/assets")
async def list_external_assets(
    tenant_id: UUID,
    asset_type: Optional[ExternalAssetType] = Query(None),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """List externally discovered assets for a tenant."""
    stmt = (
        select(ExternalAsset)
        .where(ExternalAsset.tenant_id == tenant_id)
        .order_by(ExternalAsset.last_seen.desc())
        .limit(limit)
    )
    if asset_type:
        stmt = stmt.where(ExternalAsset.asset_type == asset_type)

    result = await db.execute(stmt)
    assets = result.scalars().all()
    return [
        {
            "id": str(a.id),
            "asset_type": a.asset_type.value,
            "value": a.value,
            "first_seen": a.first_seen.isoformat(),
            "last_seen": a.last_seen.isoformat(),
            "metadata": a.metadata_json,
        }
        for a in assets
    ]


@router.get("/drift")
async def list_external_asset_drift(
    tenant_id: UUID,
    external_asset_id: Optional[UUID] = Query(None),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """List drift events (new ports, certs, sub-domains, etc.)."""
    stmt = (
        select(ExternalAssetDrift)
        .where(ExternalAssetDrift.tenant_id == tenant_id)
        .order_by(ExternalAssetDrift.detected_at.desc())
        .limit(limit)
    )
    if external_asset_id:
        stmt = stmt.where(ExternalAssetDrift.external_asset_id == external_asset_id)

    result = await db.execute(stmt)
    drifts = result.scalars().all()
    return [
        {
            "id": str(d.id),
            "external_asset_id": str(d.external_asset_id),
            "drift_type": d.drift_type,
            "details": d.details,
            "detected_at": d.detected_at.isoformat(),
        }
        for d in drifts
    ]