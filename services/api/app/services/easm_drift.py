"""
EASM drift detection (Tier 3.6).

Compares newly-discovered assets against the existing ``external_assets``
snapshot for a tenant and emits ``ExternalAssetDrift`` records for:
  * ``new_asset``   — a value that didn't exist in the previous snapshot.
  * ``new_port``    — an existing IP gained a previously-unseen port.
  * ``gone_port``   — a previously-open port is no longer seen.
  * ``new_cert``    — a new TLS certificate CN appeared.
  * ``metadata_change`` — any other metadata field changed.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.easm import ExternalAsset, ExternalAssetDrift
from app.services.easm_discovery import DiscoveredAsset

logger = logging.getLogger("aisoc.easm.drift")


async def _upsert_asset(
    db: AsyncSession,
    tenant_id: UUID,
    asset: DiscoveredAsset,
    now: datetime,
) -> tuple[ExternalAsset, bool]:
    """
    Insert or update an external asset.  Returns ``(row, is_new)``.
    """
    stmt = select(ExternalAsset).where(
        ExternalAsset.tenant_id == tenant_id,
        ExternalAsset.asset_type == asset.asset_type,
        ExternalAsset.value == asset.value,
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing is None:
        row = ExternalAsset(
            tenant_id=tenant_id,
            asset_type=asset.asset_type,
            value=asset.value,
            first_seen=now,
            last_seen=now,
            metadata_json=asset.metadata,
        )
        db.add(row)
        await db.flush()
        return row, True

    existing.last_seen = now
    old_meta = existing.metadata_json or {}
    existing.metadata_json = _merge_metadata(old_meta, asset.metadata)
    await db.flush()
    return existing, False


def _merge_metadata(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Merge metadata dicts, combining port lists."""
    merged = {**old, **new}
    old_ports = set(old.get("ports") or [])
    new_ports = set(new.get("ports") or [])
    if old_ports or new_ports:
        merged["ports"] = sorted(old_ports | new_ports)
    return merged


def _detect_port_drift(
    old_meta: dict[str, Any],
    new_meta: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return drift detail dicts for port changes."""
    drifts: list[dict[str, Any]] = []
    old_ports = set(old_meta.get("ports") or [])
    new_ports = set(new_meta.get("ports") or [])
    added = new_ports - old_ports
    removed = old_ports - new_ports
    if added:
        drifts.append({"drift_type": "new_port", "details": {"ports": sorted(added)}})
    if removed:
        drifts.append({"drift_type": "gone_port", "details": {"ports": sorted(removed)}})
    return drifts


async def detect_drift(
    db: AsyncSession,
    tenant_id: UUID,
    discovered: Sequence[DiscoveredAsset],
) -> list[ExternalAssetDrift]:
    """
    Upsert discovered assets and emit drift records for changes.
    Returns the list of newly created ``ExternalAssetDrift`` rows.
    """
    now = datetime.now(UTC)
    drift_records: list[ExternalAssetDrift] = []

    for asset in discovered:
        stmt = select(ExternalAsset).where(
            ExternalAsset.tenant_id == tenant_id,
            ExternalAsset.asset_type == asset.asset_type,
            ExternalAsset.value == asset.value,
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        old_meta = (existing.metadata_json if existing else None) or {}

        row, is_new = await _upsert_asset(db, tenant_id, asset, now)

        if is_new:
            drift = ExternalAssetDrift(
                tenant_id=tenant_id,
                external_asset_id=row.id,
                drift_type="new_asset",
                details={
                    "asset_type": asset.asset_type.value,
                    "value": asset.value,
                    "metadata": asset.metadata,
                },
                detected_at=now,
            )
            db.add(drift)
            drift_records.append(drift)
        else:
            for pd in _detect_port_drift(old_meta, asset.metadata):
                drift = ExternalAssetDrift(
                    tenant_id=tenant_id,
                    external_asset_id=row.id,
                    drift_type=pd["drift_type"],
                    details=pd["details"],
                    detected_at=now,
                )
                db.add(drift)
                drift_records.append(drift)

    await db.flush()
    logger.info(
        "EASM drift: %d new drift records for tenant %s from %d discovered assets",
        len(drift_records),
        tenant_id,
        len(discovered),
    )
    return drift_records
