"""Override learning service — Tier 1.5.

When an analyst corrects an AI verdict, this service:

1. Computes a stable signature for the alert (category + connector_type +
   primary MITRE technique) so similar future alerts can find this lesson.
2. Persists the correction in ``aisoc_institutional_memory`` with
   ``analyst_override=True`` and the analyst's reason. The agent's memory
   manager retrieves these on every new alert that matches the signature.
3. Surfaces *retroactive candidates* — past alerts in the same tenant that
   share the signature and that would now be dispositioned differently
   based on this new lesson. Analysts can opt-in to mass-apply the
   correction via :func:`apply_redisposition`.

The signature is intentionally coarse (3 fields) so a single correction
generalises to similar alerts. Tighter signatures are tracked separately
once we get a richer feature set.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import structlog
from sqlalchemy import and_, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.institutional_memory import InstitutionalMemory

logger = structlog.get_logger()


@dataclass(frozen=True)
class AlertSignature:
    """Coarse fingerprint used to match similar alerts across time."""

    category: str
    connector_type: str
    primary_technique: str

    @classmethod
    def from_alert(cls, alert: Alert) -> "AlertSignature":
        techniques = list(alert.mitre_techniques or [])
        primary = str(techniques[0]) if techniques else ""
        return cls(
            category=(alert.category or "").lower().strip(),
            connector_type=(alert.connector_type or "").lower().strip(),
            primary_technique=primary.upper().strip(),
        )

    def is_empty(self) -> bool:
        """Empty signatures shouldn't be used to generalise."""
        return not (self.category or self.connector_type or self.primary_technique)

    def memory_key(self) -> str:
        raw = f"{self.category}|{self.connector_type}|{self.primary_technique}"
        digest = hashlib.sha1(raw.encode("utf-8"), usedforsecurity=False).hexdigest()
        return f"override:{digest}"

    def tags(self) -> list[str]:
        out: list[str] = ["analyst_override"]
        if self.category:
            out.append(f"category:{self.category}")
        if self.connector_type:
            out.append(f"connector:{self.connector_type}")
        if self.primary_technique:
            out.append(self.primary_technique)
        return out


@dataclass(frozen=True)
class RedispositionCandidate:
    alert_id: str
    title: str
    severity: str
    current_disposition: str | None
    proposed_disposition: str
    event_time: str

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity,
            "current_disposition": self.current_disposition,
            "proposed_disposition": self.proposed_disposition,
            "event_time": self.event_time,
        }


async def record_override(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    alert: Alert,
    original_verdict: str,
    corrected_verdict: str,
    analyst_id: UUID | None,
    reason: str | None,
) -> AlertSignature | None:
    """Persist the override into institutional memory.

    Returns the :class:`AlertSignature` that was used (or ``None`` if the
    alert lacked enough metadata to generalise).
    """
    signature = AlertSignature.from_alert(alert)
    if signature.is_empty():
        logger.info(
            "override.signature.empty",
            alert_id=str(alert.id),
            tenant_id=str(tenant_id),
        )
        return None

    payload = {
        "alert_id": str(alert.id),
        "original_verdict": original_verdict,
        "corrected_verdict": corrected_verdict,
        "analyst_id": str(analyst_id) if analyst_id else None,
        "reason": reason,
        "signature": {
            "category": signature.category,
            "connector_type": signature.connector_type,
            "primary_technique": signature.primary_technique,
        },
        "recorded_at": datetime.now(UTC).isoformat(),
    }

    stmt = pg_insert(InstitutionalMemory).values(
        tenant_id=str(tenant_id),
        key=signature.memory_key(),
        value=payload,
        tags=signature.tags(),
        analyst_override=True,
        override_reason=reason,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["tenant_id", "key"],
        set_={
            "value": stmt.excluded.value,
            "tags": stmt.excluded.tags,
            "analyst_override": True,
            "override_reason": stmt.excluded.override_reason,
            "created_at": datetime.now(UTC),
        },
    )
    await db.execute(stmt)
    await db.commit()

    logger.info(
        "override.memory.persisted",
        tenant_id=str(tenant_id),
        alert_id=str(alert.id),
        key=signature.memory_key(),
        corrected_verdict=corrected_verdict,
    )
    return signature


async def find_redisposition_candidates(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    signature: AlertSignature,
    corrected_verdict: str,
    exclude_alert_id: UUID,
    limit: int = 50,
) -> list[RedispositionCandidate]:
    """Find past alerts in the same tenant that match *signature* and
    would now be dispositioned differently based on *corrected_verdict*."""
    if signature.is_empty():
        return []

    conditions = [
        Alert.tenant_id == tenant_id,
        Alert.id != exclude_alert_id,
        or_(Alert.disposition.is_(None), Alert.disposition != corrected_verdict),
    ]
    if signature.category:
        conditions.append(Alert.category == signature.category)
    if signature.connector_type:
        conditions.append(Alert.connector_type == signature.connector_type)

    query = (
        select(Alert)
        .where(and_(*conditions))
        .order_by(Alert.event_time.desc())
        .limit(limit * 4)
    )
    rows = list((await db.scalars(query)).all())

    candidates: list[RedispositionCandidate] = []
    for row in rows:
        if signature.primary_technique:
            techniques = {str(t).upper().strip() for t in (row.mitre_techniques or [])}
            if signature.primary_technique not in techniques:
                continue
        candidates.append(
            RedispositionCandidate(
                alert_id=str(row.id),
                title=row.title,
                severity=row.severity,
                current_disposition=row.disposition,
                proposed_disposition=corrected_verdict,
                event_time=row.event_time.isoformat() if row.event_time else "",
            )
        )
        if len(candidates) >= limit:
            break
    return candidates


async def apply_redisposition(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    alert_ids: list[UUID],
    new_disposition: str,
    analyst_id: UUID | None,
) -> int:
    """Bulk-apply *new_disposition* to *alert_ids*. Returns the number
    of rows updated. Each row already has its tenant verified."""
    if not alert_ids:
        return 0
    now = datetime.now(UTC)
    result = await db.execute(
        update(Alert)
        .where(Alert.tenant_id == tenant_id, Alert.id.in_(alert_ids))
        .values(disposition=new_disposition, updated_at=now)
    )
    await db.commit()
    rowcount = result.rowcount or 0
    logger.info(
        "override.redispositioned",
        tenant_id=str(tenant_id),
        analyst_id=str(analyst_id) if analyst_id else None,
        new_disposition=new_disposition,
        rowcount=rowcount,
    )
    return rowcount


async def list_overrides(
    db: AsyncSession,
    *,
    tenant_id: UUID,
    limit: int = 100,
) -> list[dict]:
    """Return institutional-memory analyst-override entries for a tenant."""
    query = (
        select(InstitutionalMemory)
        .where(
            InstitutionalMemory.tenant_id == str(tenant_id),
            InstitutionalMemory.analyst_override.is_(True),
        )
        .order_by(InstitutionalMemory.created_at.desc())
        .limit(limit)
    )
    rows = list((await db.scalars(query)).all())
    out: list[dict] = []
    for r in rows:
        value = r.value
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = {}
        out.append(
            {
                "key": r.key,
                "tags": r.tags or [],
                "reason": r.override_reason,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "value": value,
            }
        )
    return out
