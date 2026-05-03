"""SLA metrics computation service.

Computes MTTD, MTTR, and MTTC from alert_sla_events,
compares against tenant-configured targets, and returns
per-severity SLA compliance summaries.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sla import AlertSLAEvent, TenantSLAConfig


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_sla_configs(
    db: AsyncSession, tenant_id: uuid.UUID
) -> dict[str, dict[str, int]]:
    """Return {severity: {mttd_target, mttr_target, mttc_target}} for the tenant."""
    rows = await db.execute(
        select(TenantSLAConfig).where(TenantSLAConfig.tenant_id == tenant_id)
    )
    configs = rows.scalars().all()
    return {
        c.severity: {
            "mttd_target": c.mttd_target,
            "mttr_target": c.mttr_target,
            "mttc_target": c.mttc_target,
        }
        for c in configs
    }


async def _fetch_alert_events(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    since: datetime | None = None,
) -> dict[str, list[AlertSLAEvent]]:
    """Return events grouped by alert_id."""
    q = select(AlertSLAEvent).where(AlertSLAEvent.tenant_id == tenant_id)
    if since:
        q = q.where(AlertSLAEvent.occurred_at >= since)
    q = q.order_by(AlertSLAEvent.occurred_at)
    rows = await db.execute(q)
    events = rows.scalars().all()

    grouped: dict[str, list[AlertSLAEvent]] = {}
    for ev in events:
        key = str(ev.alert_id)
        grouped.setdefault(key, []).append(ev)
    return grouped


def _compute_durations(
    events: list[AlertSLAEvent],
) -> dict[str, int | None]:
    """Compute MTTD/MTTR/MTTC in minutes for a single alert lifecycle."""
    by_type: dict[str, datetime] = {e.event_type: e.occurred_at for e in events}

    detected_at = by_type.get("detected")
    acknowledged_at = by_type.get("acknowledged")
    resolved_at = by_type.get("resolved")
    closed_at = by_type.get("closed")

    def minutes_between(a: datetime | None, b: datetime | None) -> int | None:
        if a and b and b >= a:
            return int((b - a).total_seconds() / 60)
        return None

    return {
        "mttd": minutes_between(detected_at, acknowledged_at),
        "mttr": minutes_between(detected_at, resolved_at),
        "mttc": minutes_between(detected_at, closed_at),
        "severity": events[0].severity if events else "unknown",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def compute_sla_metrics(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    days: int = 30,
) -> dict[str, Any]:
    """Compute aggregated SLA metrics for the last N days.

    Returns a dict with:
      - per_severity: {severity: {mttd_avg, mttr_avg, mttc_avg, breach_rate, total, breaches}}
      - overall: aggregated across all severities
      - targets: per-severity configured targets
    """
    since = datetime.utcnow() - timedelta(days=days)
    configs = await _get_sla_configs(db, tenant_id)
    grouped = await _fetch_alert_events(db, tenant_id, since=since)

    # Aggregate per severity
    buckets: dict[str, list[dict[str, Any]]] = {}
    for alert_events in grouped.values():
        d = _compute_durations(alert_events)
        sev = d["severity"]
        buckets.setdefault(sev, []).append(d)

    per_severity: dict[str, dict[str, Any]] = {}
    default_targets = {
        "critical": {"mttd_target": 15, "mttr_target": 60, "mttc_target": 120},
        "high":     {"mttd_target": 30, "mttr_target": 120, "mttc_target": 240},
        "medium":   {"mttd_target": 60, "mttr_target": 240, "mttc_target": 480},
        "low":      {"mttd_target": 120, "mttr_target": 480, "mttc_target": 1440},
    }

    for sev in ["critical", "high", "medium", "low"]:
        items = buckets.get(sev, [])
        targets = configs.get(sev) or default_targets.get(sev, {})

        mttd_vals = [i["mttd"] for i in items if i["mttd"] is not None]
        mttr_vals = [i["mttr"] for i in items if i["mttr"] is not None]
        mttc_vals = [i["mttc"] for i in items if i["mttc"] is not None]

        def avg(vals: list[int]) -> float | None:
            return round(sum(vals) / len(vals), 1) if vals else None

        mttd_avg = avg(mttd_vals)
        mttr_avg = avg(mttr_vals)
        mttc_avg = avg(mttc_vals)

        # Breaches: any metric exceeding its target
        breaches = sum(
            1
            for i in items
            if (
                (i["mttd"] is not None and i["mttd"] > targets.get("mttd_target", 9999))
                or (i["mttr"] is not None and i["mttr"] > targets.get("mttr_target", 9999))
                or (i["mttc"] is not None and i["mttc"] > targets.get("mttc_target", 9999))
            )
        )

        per_severity[sev] = {
            "total": len(items),
            "breaches": breaches,
            "breach_rate": round(breaches / len(items) * 100, 1) if items else 0.0,
            "mttd_avg": mttd_avg,
            "mttr_avg": mttr_avg,
            "mttc_avg": mttc_avg,
            "mttd_target": targets.get("mttd_target"),
            "mttr_target": targets.get("mttr_target"),
            "mttc_target": targets.get("mttc_target"),
        }

    # Overall aggregates
    all_items = [i for items in buckets.values() for i in items]
    all_mttd = [i["mttd"] for i in all_items if i["mttd"] is not None]
    all_mttr = [i["mttr"] for i in all_items if i["mttr"] is not None]
    all_mttc = [i["mttc"] for i in all_items if i["mttc"] is not None]
    total_breaches = sum(s["breaches"] for s in per_severity.values())
    total_alerts = sum(s["total"] for s in per_severity.values())

    overall = {
        "total_alerts": total_alerts,
        "total_breaches": total_breaches,
        "breach_rate": round(total_breaches / total_alerts * 100, 1) if total_alerts else 0.0,
        "mttd_avg": round(sum(all_mttd) / len(all_mttd), 1) if all_mttd else None,
        "mttr_avg": round(sum(all_mttr) / len(all_mttr), 1) if all_mttr else None,
        "mttc_avg": round(sum(all_mttc) / len(all_mttc), 1) if all_mttc else None,
    }

    return {
        "period_days": days,
        "computed_at": datetime.utcnow().isoformat(),
        "overall": overall,
        "per_severity": per_severity,
    }
