"""SLA metrics computation service.

Computes MTTD, MTTR, and MTTC from alert_sla_events,
compares against tenant-configured targets, and returns
per-severity SLA compliance summaries.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Text, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.sla import AlertSLAEvent, TenantSLAConfig
from app.models.tenant import Tenant

# 2026 published KPI bar defaults (tenants can override via ``settings.kpi_bar``).
DEFAULT_KPI_BAR_TARGETS: dict[str, float] = {
    "false_positive_rate_max_pct": 5.0,
    "alert_to_incident_ratio_min": 50.0,
    "mitre_technique_tagging_min_pct": 85.0,
    "mitre_subtechnique_tagging_min_pct": 60.0,
}


def merge_kpi_bar_dict(existing: dict | None, patch: dict[str, float]) -> dict[str, float]:
    """Merge ``patch`` into stored ``kpi_bar`` and coerce to the four known keys + defaults."""
    kb = {**(existing or {}), **patch}
    out = {**DEFAULT_KPI_BAR_TARGETS}
    for k in DEFAULT_KPI_BAR_TARGETS:
        if k in kb:
            try:
                out[k] = float(kb[k])
            except (TypeError, ValueError):
                pass
    return out


def merge_tenant_settings_patch(existing: dict | None, patch: dict) -> dict:
    """Shallow-merge ``patch`` into tenant ``settings``; deep-merge only ``kpi_bar``."""
    out = dict(existing or {})
    for k, v in patch.items():
        if k == "kpi_bar" and isinstance(v, dict):
            prev = out.get("kpi_bar")
            base = prev if isinstance(prev, dict) else {}
            out["kpi_bar"] = merge_kpi_bar_dict(base, v)
        else:
            out[k] = v
    return out


async def load_kpi_bar_targets(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, float]:
    row = await db.execute(select(Tenant.settings).where(Tenant.id == tenant_id))
    raw = row.scalar_one_or_none() or {}
    kb = (raw or {}).get("kpi_bar") if isinstance((raw or {}).get("kpi_bar"), dict) else {}
    return merge_kpi_bar_dict(kb, {})


async def patch_tenant_kpi_bar_targets(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    patch: dict[str, float],
) -> dict[str, float]:
    """Persist merged KPI bar targets on the tenant row."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise ValueError("tenant not found")
    settings = dict(tenant.settings or {})
    prev_bar = settings.get("kpi_bar") if isinstance(settings.get("kpi_bar"), dict) else {}
    merged_bar = merge_kpi_bar_dict(prev_bar, patch)
    settings["kpi_bar"] = merged_bar
    tenant.settings = settings
    tenant.updated_at = datetime.now(UTC)
    flag_modified(tenant, "settings")
    await db.commit()
    return merged_bar


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _get_sla_configs(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, dict[str, int]]:
    """Return {severity: {mttd_target, mttr_target, mttc_target}} for the tenant."""
    rows = await db.execute(select(TenantSLAConfig).where(TenantSLAConfig.tenant_id == tenant_id))
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


async def _compute_kpi_bar(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    since: datetime,
    targets: dict[str, float],
) -> dict[str, Any]:
    """Aggregate 2026 KPI bar metrics from ``alerts`` for the look-back window."""
    base = Alert.tenant_id == tenant_id, Alert.created_at >= since

    total_r = await db.execute(select(func.count()).select_from(Alert).where(*base))
    total = int(total_r.scalar_one() or 0)

    fp_r = await db.execute(
        select(func.count()).select_from(Alert).where(*base, Alert.status == "fp")
    )
    fp = int(fp_r.scalar_one() or 0)

    cases_r = await db.execute(
        select(func.count(func.distinct(Alert.case_id))).select_from(Alert).where(*base, Alert.case_id.is_not(None))
    )
    distinct_cases = int(cases_r.scalar_one() or 0)

    tagged_r = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            *base,
            func.coalesce(func.jsonb_array_length(Alert.mitre_techniques), 0) > 0,
        )
    )
    tagged = int(tagged_r.scalar_one() or 0)

    sub_r = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(
            *base,
            func.coalesce(func.jsonb_array_length(Alert.mitre_techniques), 0) > 0,
            Alert.mitre_techniques.cast(Text).like("%.%"),
        )
    )
    sub_tagged = int(sub_r.scalar_one() or 0)

    fp_rate_pct = round(fp / total * 100, 2) if total else 0.0
    if distinct_cases > 0:
        alert_to_incident = round(total / distinct_cases, 2)
    else:
        alert_to_incident = float(total) if total else 0.0

    mitre_tag_pct = round(tagged / total * 100, 2) if total else 0.0
    mitre_sub_pct = round(sub_tagged / total * 100, 2) if total else 0.0

    # Alert-to-incident: only evaluate when there is at least one incident;
    # alerts with zero linked cases are treated as meeting the ratio bar.
    breaches = {
        "false_positive_rate": fp_rate_pct > targets["false_positive_rate_max_pct"],
        "alert_to_incident_ratio": distinct_cases > 0
        and alert_to_incident < targets["alert_to_incident_ratio_min"],
        "mitre_technique_tagging": mitre_tag_pct < targets["mitre_technique_tagging_min_pct"],
        "mitre_subtechnique_tagging": mitre_sub_pct < targets["mitre_subtechnique_tagging_min_pct"],
    }

    return {
        "targets": targets,
        "observed": {
            "total_alerts": total,
            "false_positives": fp,
            "false_positive_rate_pct": fp_rate_pct,
            "distinct_cases": distinct_cases,
            "alert_to_incident_ratio": alert_to_incident,
            "mitre_technique_tagging_pct": mitre_tag_pct,
            "mitre_subtechnique_tagging_pct": mitre_sub_pct,
        },
        "breaches": breaches,
        "breach_count": sum(1 for v in breaches.values() if v),
    }


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
        "high": {"mttd_target": 30, "mttr_target": 120, "mttc_target": 240},
        "medium": {"mttd_target": 60, "mttr_target": 240, "mttc_target": 480},
        "low": {"mttd_target": 120, "mttr_target": 480, "mttc_target": 1440},
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

    out: dict[str, Any] = {
        "period_days": days,
        "computed_at": datetime.utcnow().isoformat(),
        "overall": overall,
        "per_severity": per_severity,
    }
    if get_settings().AISOC_FEATURE_KPI_BAR:
        kpi_targets = await load_kpi_bar_targets(db, tenant_id)
        out["kpi_bar"] = await _compute_kpi_bar(db, tenant_id, since, kpi_targets)
    else:
        out["kpi_bar"] = None
    return out
