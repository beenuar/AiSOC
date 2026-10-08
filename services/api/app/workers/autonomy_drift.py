"""Take autonomy back when the evidence stops holding, without waiting to be read.

Fix pass item 3.7. See ``plans/aisoc_fix_pass_plan.plan.md``.

``reconcile_grants`` re-checks every standing grant against the demotion
floors and writes the transition with its audit row. It shipped with exactly
one production caller: ``GET /api/v1/autonomy-policy/grants``. So a grant
whose agreement had collapsed stayed ``granted`` — and kept auto-executing at
dispatch — until somebody happened to open the autonomy page. On a deployment
nobody opens that page on, which is every deployment running unattended, the
demotion floors were decoration.

This is the caller that does not need a human. It runs in ``services/api``
because that is where the evaluator's write half lives: the tenant session,
the hash-chained audit log, and the one module allowed to move a grant
between states.

Reads only this deployment's database
=====================================

Unlike ``shadow_reconcile``, which is default-off because it polls a
customer's SIEM on a timer, this sweep makes no outbound call at all. It
aggregates rows this platform already wrote and, when the floors are crossed,
demotes. So it is **default on**: a safety control that has to be switched on
is one that is off wherever nobody knew to switch it on, and the condition it
exists to catch is precisely the one nobody is watching for.

Closures first
==============

Each tenant's own closures are reconciled before the grants are judged, in
that order and for the same reason the endpoint does it: an analyst who has
just worked a queue should be judged on those decisions rather than on the
state before them. Running the demotion first would score a window that is
knowably out of date by the length of one tick.

What it does not do
===================

It does not promote. Nothing here can widen a tenant's autonomy, in either
direction of the evidence — a tenant whose numbers recover asks for the
capability again through the gate, with an actor and an audit row, because a
grant that reappeared on its own would have nobody's name on it.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.services.autonomy_grants import reconcile_grants
from app.services.shadow_agreement import reconcile_local_closures
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.autonomy_drift")

__all__ = [
    "SweepRun",
    "run_forever",
    "run_once",
]

#: Tenants holding at least one standing grant. A tenant with none has nothing
#: that could drift, and sweeping every tenant on the deployment to discover
#: that would scale with the customer list rather than with the feature.
_TENANTS_WITH_GRANTS_SQL = """
SELECT DISTINCT tenant_id
FROM aisoc_autonomy_grants
WHERE state = 'granted'
ORDER BY tenant_id
"""


@dataclass
class SweepRun:
    """One pass, in the terms an operator reading the log needs.

    ``tenants`` and ``demoted`` are both reported. Zero tenants means nobody
    on this deployment holds autonomy, which is a different fact from a sweep
    that looked at twenty and found nothing wrong, and the two are otherwise
    indistinguishable from the outside.
    """

    started_at: datetime
    tenants: int = 0
    reconciled_closures: int = 0
    demoted: list[dict[str, Any]] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "tenants": self.tenants,
            "reconciled_closures": self.reconciled_closures,
            "demoted": len(self.demoted),
            "failed": len(self.failed),
        }


def _interval() -> int:
    """Tick cadence, floored so a misconfigured value cannot become a scan storm."""
    return max(int(getattr(settings, "AUTONOMY_DRIFT_INTERVAL_SECONDS", 600)), 60)


def _max_tenants() -> int:
    return max(int(getattr(settings, "AUTONOMY_DRIFT_MAX_TENANTS_PER_TICK", 100)), 1)


def _safe(value: object, cap: int = 300) -> str:
    return str(value).replace("\r", "").replace("\n", " ")[:cap]


async def run_once(*, db: AsyncSession | None = None, now: datetime | None = None) -> SweepRun:
    """Re-check every standing grant on the deployment and demote what no longer holds."""
    started = now or datetime.now(UTC)
    own_session = db is None
    if db is None:
        db = AsyncSessionLocal()
    run = SweepRun(started_at=started)

    try:
        await assert_cross_tenant_session(db, "autonomy drift sweep")
        tenants: list[uuid.UUID] = list((await db.execute(text(_TENANTS_WITH_GRANTS_SQL))).scalars().all())
        run.tenants = len(tenants)

        for tenant_id in tenants[: _max_tenants()]:
            try:
                run.reconciled_closures += await reconcile_local_closures(db, tenant_id)
                transitions = await reconcile_grants(db, tenant_id, now=now)
                await db.commit()
            except Exception as exc:  # noqa: BLE001 - one tenant must not end the pass
                await db.rollback()
                run.failed.append(str(tenant_id))
                logger.warning(
                    "autonomy_drift.tenant_failed tenant=%s err=%s detail=%s",
                    _safe(tenant_id, 64),
                    type(exc).__name__,
                    _safe(exc),
                )
                continue

            for transition in transitions:
                record = transition.as_dict()
                run.demoted.append({"tenant_id": str(tenant_id), **record})
                # Warning, not info. A capability was taken away from a tenant
                # who is not looking at the page that would have told them.
                logger.warning(
                    "autonomy_drift.demoted tenant=%s reasons=%s",
                    _safe(tenant_id, 64),
                    _safe(",".join(transition.refusal_values)),
                )
    finally:
        if own_session:
            await db.close()

    _log_pass(run)
    return run


def _log_pass(run: SweepRun) -> None:
    if run.tenants == 0:
        logger.info("autonomy_drift idle: no tenant holds a standing grant, so nothing can have drifted")
        return
    logger.info(
        "autonomy_drift pass tenants=%d closures_reconciled=%d demoted=%d failed=%d",
        run.tenants,
        run.reconciled_closures,
        len(run.demoted),
        len(run.failed),
    )


async def run_forever() -> None:
    """Tick until cancelled. Owned by the API ``lifespan``, like the other workers."""
    interval = _interval()
    logger.info("autonomy_drift started interval=%ds max-tenants-per-tick=%d", interval, _max_tenants())
    failures = TickFailures("autonomy_drift", logger)
    try:
        while True:
            try:
                await run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                failures.record_failure(exc)
            else:
                failures.record_success()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("autonomy_drift stopped")
        raise
