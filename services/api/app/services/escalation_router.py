"""Per-tenant escalation routing — `enqueue_event`'s first real caller.

`services/escalations` watches for unacknowledged critical cases and fires
ONE deployment-wide webhook; its own docstring records that "per-tenant
routing is exactly what the native outbound-webhook [subsystem] is for",
and that subsystem's `enqueue_event` had **no production caller**. This
module is the routing half the bridge invited:

* a tenant writes `escalation_routes` rows — severity floor, unacked
  window, destination webhook, optionally scoped to the responsibility
  matrix's owner for the case's class;
* the sweep finds open cases past their route's unacked window and
  enqueues `case.escalated` to exactly that tenant's destinations, through
  the outbound-webhook queue (signed, retried, dead-lettered — the
  machinery that already existed);
* `escalation_nags` dedups: one escalation per case per route, not one
  per tick.

The deployment-wide bridge keeps running as the operator's own fallback;
this path is the tenant's. "Acknowledged" here is ownership: a case with
an assignee or an owning agent run is being worked, which is the same
criterion the attention feed uses.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import responsibility
from app.services.outbound_webhooks import enqueue_event

logger = logging.getLogger("aisoc.escalation_router")

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_ROUTES_SQL = text(
    """
    SELECT r.id, r.tenant_id, r.responsibility, r.min_severity, r.unacked_minutes, r.webhook_id
    FROM escalation_routes r
    WHERE r.enabled = TRUE
    """
)

#: Open, unowned cases older than the route's window, not yet nagged for
#: this route. Ownership is the attention feed's criterion: an assignee or
#: an owning agent run means somebody is working it.
_OVERDUE_CASES_SQL = text(
    """
    SELECT c.id, c.case_number, c.title, c.severity, c.case_type, c.created_at
    FROM aisoc_cases c
    WHERE c.tenant_id = :tenant_id
      AND c.status IN ('new', 'triaged')
      AND c.assigned_to_id IS NULL
      AND c.owner_agent_run_id IS NULL
      AND c.created_at < now() - make_interval(mins => :unacked_minutes)
      AND NOT EXISTS (
        SELECT 1 FROM escalation_nags n
        WHERE n.tenant_id = c.tenant_id AND n.case_id = c.id AND n.route_id = :route_id
      )
    ORDER BY c.created_at
    LIMIT 25
    """
)

_RECORD_NAG_SQL = text(
    """
    INSERT INTO escalation_nags (tenant_id, case_id, route_id)
    VALUES (:tenant_id, :case_id, :route_id)
    ON CONFLICT DO NOTHING
    """
)


@dataclass
class RoutingSummary:
    routes: int = 0
    escalated: int = 0
    suppressed_by_matrix: int = 0
    errors: list[str] = field(default_factory=list)


def _severity_at_or_above(severity: str, floor: str) -> bool:
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(floor, 0)


async def route_overdue_cases(db: AsyncSession) -> RoutingSummary:
    """One sweep over every enabled route. Per-tenant isolation is the
    route's own tenant_id: a route only ever reads and escalates its own
    tenant's cases, and `enqueue_event` fans out only to that tenant's
    webhooks."""
    summary = RoutingSummary()
    routes = (await db.execute(_ROUTES_SQL)).fetchall()
    summary.routes = len(routes)
    for route_id, tenant_id, resp_filter, min_severity, unacked_minutes, _webhook_id in routes:
        try:
            cases = (
                await db.execute(
                    _OVERDUE_CASES_SQL,
                    {
                        "tenant_id": str(tenant_id),
                        "unacked_minutes": int(unacked_minutes),
                        "route_id": str(route_id),
                    },
                )
            ).fetchall()
            for case_id, case_number, title, severity, case_type, created_at in cases:
                if not _severity_at_or_above(str(severity or "medium"), str(min_severity)):
                    continue
                if resp_filter != "*":
                    decision = await responsibility.check(
                        db,
                        tenant_id=tenant_id,
                        activity="triage",
                        party=str(resp_filter),
                        alert_class=str(case_type or "*"),
                        severity=str(severity or "*"),
                    )
                    # The route carries work owned by `resp_filter`; a matrix
                    # that assigns this case's triage elsewhere means this
                    # route is not the one that should wake anybody.
                    if not decision.allowed:
                        summary.suppressed_by_matrix += 1
                        continue
                payload: dict[str, Any] = {
                    "case_id": str(case_id),
                    "case_number": case_number,
                    "title": title,
                    "severity": severity,
                    "unacknowledged_for_minutes": int(unacked_minutes),
                    "created_at": created_at.isoformat() if created_at else None,
                    "route_responsibility": resp_filter,
                }
                await enqueue_event(db, tenant_id=tenant_id, event_type="case.escalated", payload=payload)
                await db.execute(
                    _RECORD_NAG_SQL,
                    {"tenant_id": str(tenant_id), "case_id": str(case_id), "route_id": str(route_id)},
                )
                summary.escalated += 1
        except Exception as exc:  # noqa: BLE001 — one route's failure must not stop the rest
            summary.errors.append(f"route {route_id}: {type(exc).__name__}")
            logger.warning(
                "escalation_router.route_failed route=%s tenant=%s err=%s",
                route_id,
                tenant_id,
                type(exc).__name__,
            )
    return summary
