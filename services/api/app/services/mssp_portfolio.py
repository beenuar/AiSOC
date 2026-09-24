"""Cross-tenant aggregates over a managed portfolio.

Every function here reads more than one tenant's data on purpose, which
makes this the most dangerous module in the tenancy surface: it is the one
place where "filter by the caller's tenant" is deliberately not the rule.
Three properties keep it honest, and they are structural rather than
conventional because a convention is what the previous cross-tenant leaks
were relying on.

**The scope is a parameter, not a default.** No function reads the request,
the session, or the current user. Each takes a resolved
:class:`~app.services.org_scope.PortfolioScope` and passes it through
:func:`~app.services.org_scope.require_scope`, which raises on an empty
portfolio. An aggregate therefore cannot run with no filter — the failure
mode is an exception, not a table scan.

**The tenant list is bound, never interpolated.** `tenant_id = ANY(:ids)`
with the ids as a parameter. This mirrors the ClickHouse lesson: the moment
a scoping predicate is built by string formatting, its correctness depends
on whoever edits the string next.

**Nothing is invented.** These endpoints previously returned five
hardcoded companies — "Acme Corp, health 92.4, 12 open alerts" — to any
authenticated caller. Where a figure cannot be measured from real rows it
is absent or zero here, and an empty portfolio returns empty results rather
than a sample.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.entitlements import Headroom, headroom_for_tenant
from app.services.org_scope import PortfolioScope, require_scope

# A connector that has not synced in this long is stale. Chosen against the
# platform's own defaults: the connector scheduler polls every five minutes,
# so an hour is twelve missed cycles — comfortably past a transient blip and
# well short of a working day.
STALE_AFTER = timedelta(hours=1)

# Window for the resolution-time average. Long enough that a tenant closing
# a handful of cases a week still has a number, short enough that it tracks
# how the account is being run now rather than a year ago.
MTTR_WINDOW = timedelta(days=30)


@dataclass(frozen=True)
class TenantRollup:
    """One managed tenant's posture, every field counted from real rows."""

    tenant_id: uuid.UUID
    name: str
    slug: str
    relationship: str
    is_active: bool
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    untriaged_alerts: int
    # Seeded demo rows, counted apart from everything above so a demo
    # install reads "0 real, 15 synthetic" rather than reporting fifteen
    # alerts an operator would go looking for.
    synthetic_alerts: int
    open_cases: int
    sla_breached_cases: int
    # Mean time to resolve, from cases this tenant actually closed in the
    # trailing window. `None` when they closed none — a tenant with no
    # closed cases has no MTTR, and reporting 0.0 would put them top of the
    # league table for having done nothing.
    mttr_minutes: float | None
    connectors_total: int
    connectors_healthy: int
    connectors_stale: int
    connectors_error: int
    last_event_at: datetime | None
    limits: list[Headroom]

    @property
    def limits_exhausted(self) -> int:
        return sum(1 for limit in self.limits if limit.state == "exhausted")

    @property
    def limits_warning(self) -> int:
        return sum(1 for limit in self.limits if limit.state == "warning")

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": str(self.tenant_id),
            "name": self.name,
            "slug": self.slug,
            "relationship": self.relationship,
            "is_active": self.is_active,
            "open_alerts": self.open_alerts,
            "critical_alerts": self.critical_alerts,
            "high_alerts": self.high_alerts,
            "untriaged_alerts": self.untriaged_alerts,
            "synthetic_alerts": self.synthetic_alerts,
            "open_cases": self.open_cases,
            "sla_breached_cases": self.sla_breached_cases,
            "mttr_minutes": self.mttr_minutes,
            "connectors": {
                "total": self.connectors_total,
                "healthy": self.connectors_healthy,
                "stale": self.connectors_stale,
                "error": self.connectors_error,
            },
            "last_event_at": self.last_event_at.isoformat() if self.last_event_at else None,
            "limits": [limit.as_dict() for limit in self.limits],
            "limits_exhausted": self.limits_exhausted,
            "limits_warning": self.limits_warning,
        }


# Statuses that mean "still needs someone". Kept in one place so the
# portfolio backlog and a single tenant's queue cannot drift apart.
_OPEN_ALERT_STATUSES = ("new", "open", "investigating", "triaged", "in_progress")
_OPEN_CASE_STATUSES = ("open", "investigating", "in_progress", "containment", "eradication", "recovery")


async def tenant_rollups(db: AsyncSession, scope: PortfolioScope) -> list[TenantRollup]:
    """Per-tenant posture for every tenant in ``scope``.

    Returns a row for each scoped tenant even when that tenant has no data
    at all — a managed customer with zero alerts is a real state an operator
    needs to see, and dropping the row would read as "not onboarded".
    """
    tenant_ids = require_scope(scope)
    ids = [str(t) for t in tenant_ids]
    stale_before = datetime.now(UTC) - STALE_AFTER

    rows = (
        await db.execute(
            text(
                """
                SELECT
                    t.id,
                    t.name,
                    t.slug,
                    t.is_active,
                    t.limits,
                    COALESCE(ot.relationship, 'managed')                        AS relationship,
                    COALESCE(a.open_alerts, 0)                                  AS open_alerts,
                    COALESCE(a.critical_alerts, 0)                              AS critical_alerts,
                    COALESCE(a.high_alerts, 0)                                  AS high_alerts,
                    COALESCE(a.untriaged_alerts, 0)                             AS untriaged_alerts,
                    COALESCE(a.synthetic_alerts, 0)                             AS synthetic_alerts,
                    a.last_event_at                                             AS last_event_at,
                    COALESCE(c.open_cases, 0)                                   AS open_cases,
                    COALESCE(c.sla_breached_cases, 0)                           AS sla_breached_cases,
                    r.mttr_minutes                                              AS mttr_minutes,
                    COALESCE(k.total, 0)                                        AS connectors_total,
                    COALESCE(k.healthy, 0)                                      AS connectors_healthy,
                    COALESCE(k.stale, 0)                                        AS connectors_stale,
                    COALESCE(k.errored, 0)                                      AS connectors_error
                FROM tenants t
                LEFT JOIN organization_tenants ot ON ot.tenant_id = t.id
                LEFT JOIN (
                    SELECT
                        tenant_id,
                        count(*) FILTER (WHERE status = ANY(:open_statuses)
                                           AND NOT COALESCE(is_synthetic, FALSE))          AS open_alerts,
                        count(*) FILTER (WHERE severity = 'critical'
                                           AND status = ANY(:open_statuses)
                                           AND NOT COALESCE(is_synthetic, FALSE))          AS critical_alerts,
                        count(*) FILTER (WHERE severity = 'high'
                                           AND status = ANY(:open_statuses)
                                           AND NOT COALESCE(is_synthetic, FALSE))          AS high_alerts,
                        count(*) FILTER (WHERE ai_summary IS NULL AND ai_score IS NULL
                                           AND status = ANY(:open_statuses)
                                           AND NOT COALESCE(is_synthetic, FALSE))          AS untriaged_alerts,
                        count(*) FILTER (WHERE COALESCE(is_synthetic, FALSE))              AS synthetic_alerts,
                        max(event_time) FILTER (WHERE NOT COALESCE(is_synthetic, FALSE))   AS last_event_at
                    FROM alerts
                    WHERE tenant_id = ANY(:tenant_ids)
                    GROUP BY tenant_id
                ) a ON a.tenant_id = t.id
                LEFT JOIN (
                    SELECT
                        tenant_id,
                        count(*)                                                           AS open_cases,
                        count(*) FILTER (WHERE COALESCE(sla_breached, FALSE))              AS sla_breached_cases
                    FROM cases
                    WHERE tenant_id = ANY(:tenant_ids) AND status = ANY(:open_case_statuses)
                    GROUP BY tenant_id
                ) c ON c.tenant_id = t.id
                LEFT JOIN (
                    SELECT
                        tenant_id,
                        round(
                            (avg(EXTRACT(EPOCH FROM (closed_at - created_at))) / 60.0)::numeric,
                            1
                        )::float8                                                          AS mttr_minutes
                    FROM cases
                    WHERE tenant_id = ANY(:tenant_ids)
                      AND closed_at IS NOT NULL
                      AND closed_at >= :mttr_since
                      AND closed_at >= created_at
                    GROUP BY tenant_id
                ) r ON r.tenant_id = t.id
                LEFT JOIN (
                    SELECT
                        tenant_id,
                        count(*)                                                           AS total,
                        count(*) FILTER (WHERE health_status = 'healthy'
                                           AND last_sync IS NOT NULL
                                           AND last_sync >= :stale_before)                 AS healthy,
                        count(*) FILTER (WHERE health_status <> 'unhealthy'
                                           AND (last_sync IS NULL
                                                OR last_sync < :stale_before))             AS stale,
                        count(*) FILTER (WHERE health_status = 'unhealthy')                AS errored
                    FROM connectors
                    WHERE tenant_id = ANY(:tenant_ids) AND is_enabled
                    GROUP BY tenant_id
                ) k ON k.tenant_id = t.id
                WHERE t.id = ANY(:tenant_ids)
                ORDER BY t.name
                """
            ),
            {
                "tenant_ids": ids,
                "open_statuses": list(_OPEN_ALERT_STATUSES),
                "open_case_statuses": list(_OPEN_CASE_STATUSES),
                "stale_before": stale_before,
                "mttr_since": datetime.now(UTC) - MTTR_WINDOW,
            },
        )
    ).mappings()

    rollups: list[TenantRollup] = []
    for row in rows:
        tenant_id = uuid.UUID(str(row["id"]))
        rollups.append(
            TenantRollup(
                tenant_id=tenant_id,
                name=str(row["name"]),
                slug=str(row["slug"]),
                relationship=str(row["relationship"]),
                is_active=bool(row["is_active"]),
                open_alerts=int(row["open_alerts"]),
                critical_alerts=int(row["critical_alerts"]),
                high_alerts=int(row["high_alerts"]),
                untriaged_alerts=int(row["untriaged_alerts"]),
                synthetic_alerts=int(row["synthetic_alerts"]),
                open_cases=int(row["open_cases"]),
                sla_breached_cases=int(row["sla_breached_cases"]),
                mttr_minutes=float(row["mttr_minutes"]) if row["mttr_minutes"] is not None else None,
                connectors_total=int(row["connectors_total"]),
                connectors_healthy=int(row["connectors_healthy"]),
                connectors_stale=int(row["connectors_stale"]),
                connectors_error=int(row["connectors_error"]),
                last_event_at=row["last_event_at"],
                limits=await headroom_for_tenant(db, tenant_id, row["limits"]),
            )
        )
    return rollups


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


def summarise(rollups: list[TenantRollup]) -> dict[str, Any]:
    """Portfolio totals derived from the per-tenant rows above.

    Derived rather than separately queried so the summary and the table can
    never disagree — a dashboard whose header contradicts its own rows is
    how people stop trusting both.
    """
    return {
        "tenants": len(rollups),
        "tenants_active": sum(1 for r in rollups if r.is_active),
        "open_alerts": sum(r.open_alerts for r in rollups),
        "critical_alerts": sum(r.critical_alerts for r in rollups),
        "high_alerts": sum(r.high_alerts for r in rollups),
        "untriaged_alerts": sum(r.untriaged_alerts for r in rollups),
        "synthetic_alerts": sum(r.synthetic_alerts for r in rollups),
        "open_cases": sum(r.open_cases for r in rollups),
        "sla_breached_cases": sum(r.sla_breached_cases for r in rollups),
        # Averaged only over tenants that closed something. `None` when the
        # whole portfolio has closed nothing, rather than a confident 0.0.
        "mttr_minutes": _mean([r.mttr_minutes for r in rollups if r.mttr_minutes is not None]),
        "connectors_total": sum(r.connectors_total for r in rollups),
        "connectors_healthy": sum(r.connectors_healthy for r in rollups),
        "connectors_stale": sum(r.connectors_stale for r in rollups),
        "connectors_error": sum(r.connectors_error for r in rollups),
        "tenants_with_exhausted_limits": sum(1 for r in rollups if r.limits_exhausted),
        "tenants_with_limit_warnings": sum(1 for r in rollups if r.limits_warning),
        "tenants_without_connectors": sum(1 for r in rollups if r.connectors_total == 0),
    }


EMPTY_SUMMARY: dict[str, Any] = {
    "tenants": 0,
    "tenants_active": 0,
    "open_alerts": 0,
    "critical_alerts": 0,
    "high_alerts": 0,
    "untriaged_alerts": 0,
    "synthetic_alerts": 0,
    "open_cases": 0,
    "sla_breached_cases": 0,
    "mttr_minutes": None,
    "connectors_total": 0,
    "connectors_healthy": 0,
    "connectors_stale": 0,
    "connectors_error": 0,
    "tenants_with_exhausted_limits": 0,
    "tenants_with_limit_warnings": 0,
    "tenants_without_connectors": 0,
}


async def portfolio_alerts(
    db: AsyncSession,
    scope: PortfolioScope,
    *,
    severity: str | None = None,
    status: str | None = None,
    include_synthetic: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Open alerts across the portfolio, newest first.

    Replaces a list of five invented incidents attributed to invented
    companies. Every row here is an `alerts` row belonging to a tenant in
    ``scope``, carrying the real tenant name so an operator can tell whose
    estate they are looking at.
    """
    tenant_ids = require_scope(scope)
    clauses = ["a.tenant_id = ANY(:tenant_ids)"]
    params: dict[str, Any] = {
        "tenant_ids": [str(t) for t in tenant_ids],
        "limit": max(1, min(int(limit), 500)),
    }

    if severity:
        clauses.append("a.severity = :severity")
        params["severity"] = severity
    if status:
        clauses.append("a.status = :status")
        params["status"] = status
    else:
        clauses.append("a.status = ANY(:open_statuses)")
        params["open_statuses"] = list(_OPEN_ALERT_STATUSES)
    if not include_synthetic:
        clauses.append("NOT COALESCE(a.is_synthetic, FALSE)")

    rows = (
        await db.execute(
            text(
                "SELECT a.id, a.tenant_id, t.name AS tenant_name, a.title, a.severity, a.status, "
                "       a.category, a.created_at, a.event_time, a.case_id, "
                "       COALESCE(a.is_synthetic, FALSE) AS is_synthetic "
                "FROM alerts a JOIN tenants t ON t.id = a.tenant_id "
                f"WHERE {' AND '.join(clauses)} "
                "ORDER BY a.created_at DESC LIMIT :limit"
            ),
            params,
        )
    ).mappings()

    return [
        {
            "alert_id": str(row["id"]),
            "tenant_id": str(row["tenant_id"]),
            "tenant_name": str(row["tenant_name"]),
            "title": str(row["title"]),
            "severity": str(row["severity"]),
            "status": str(row["status"]),
            "category": row["category"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "event_time": row["event_time"].isoformat() if row["event_time"] else None,
            "case_id": str(row["case_id"]) if row["case_id"] else None,
            # Carried through rather than hidden: a caller that opts into
            # seeded rows must be able to tell them apart.
            "is_synthetic": bool(row["is_synthetic"]),
        }
        for row in rows
    ]
