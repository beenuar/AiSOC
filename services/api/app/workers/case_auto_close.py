"""Auto-close cases that have sat in ``resolved`` past the cooling-off window.

Why this exists
---------------
The case ladder is forward-only and ``resolved`` is explicitly **not** terminal
(see services/api/app/services/case_status.py): it reads finished but is not
counted as closed, does not stamp ``closed_at``, and every closure metric reads
``closed``. Until now the only writers of ``closed`` were a human PATCHing it or
a case merge, so a resolved case with no analyst coming back sat open forever.

The policy this enforces, per Alexandru (16-Nov-2026):
**a human moves a case to ``resolved``; the system closes it after 7 days of
staying resolved.**

The human/system split is what makes the window safe:

* Only a human sets ``resolved`` (the PATCH endpoint), so the clock starts on a
  deliberate act, never on an automated guess.
* A reopen (``POST /reopen``) clears ``resolved_at = NULL``, so a case that comes
  back off resolved is no longer eligible -- the timer only runs on cases that are
  genuinely still sitting resolved.

The sweep is idempotent (re-running finds nothing) and stamps a custody entry per
case so the closure is attributable to the system, not to a person. Fail-soft per
case: one bad row logs and is skipped, the rest of the sweep proceeds.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.services import evidence_custody

logger = logging.getLogger(__name__)

#: Stamped on the custody detail so the case chain shows a system closure.
AUTO_CLOSE_REASON = "auto_closed_after_resolved_window"

_SELECT_DUE = text(
    """
    SELECT id, tenant_id, case_number, resolved_at
      FROM aisoc_cases
     WHERE status = 'resolved'
       AND resolved_at IS NOT NULL
       AND resolved_at <= :cutoff
     ORDER BY resolved_at ASC
     LIMIT :limit
    """
)

_CLOSE_CASE = text(
    """
    UPDATE aisoc_cases
       SET status = 'closed',
           closed_at = :now,
           updated_at = :now
     WHERE id = :id
       AND tenant_id = :tenant_id
       AND status = 'resolved'
    """
)


@dataclass
class AutoCloseSweepResult:
    closed: int = 0
    failed: int = 0
    by_tenant: dict[str, int] = field(default_factory=dict)


def cutoff(now: datetime, days: int) -> datetime:
    """The ``resolved_at`` boundary: close anything resolved at or before this."""
    return now - timedelta(days=days)


async def sweep_auto_close(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    days: int | None = None,
    limit: int | None = None,
) -> AutoCloseSweepResult:
    """Move cases resolved for more than ``days`` to ``closed``.

    Cross-tenant by design (one deployment-wide cooling-off window), so the
    precondition is asserted rather than assumed -- a session that silently bound
    one tenant would close only that tenant's cases and report success.
    """
    now = now or datetime.now(UTC)
    days = int(days if days is not None else settings.CASE_AUTO_CLOSE_AFTER_DAYS)
    limit = int(limit if limit is not None else settings.CASE_AUTO_CLOSE_BATCH_LIMIT)

    await assert_cross_tenant_session(db, "case auto-close sweep")

    result = AutoCloseSweepResult()
    rows = (await db.execute(_SELECT_DUE, {"cutoff": cutoff(now, days), "limit": limit})).mappings().all()

    for row in rows:
        case_id = row["id"]
        tenant_id = row["tenant_id"]
        try:
            upd = await db.execute(_CLOSE_CASE, {"now": now, "id": case_id, "tenant_id": tenant_id})
            if upd.rowcount != 1:
                # A human closed or reopened it between SELECT and UPDATE. Not a
                # failure; nothing to record.
                continue

            resolved_at = row["resolved_at"]
            age_days = (now - resolved_at).days if resolved_at else None

            # Custody entry so the case's own chain shows the system closed it.
            try:
                current = await db.scalar(
                    text("SELECT evidence_chain FROM aisoc_cases WHERE id = :id AND tenant_id = :t").bindparams(
                        id=case_id, t=tenant_id
                    )
                )
                chain = evidence_custody.append_entry(
                    list(current or []),
                    action="case_closed",
                    actor_id=None,
                    actor_email="system",
                    item="closed",
                    detail={"to": "closed", "auto": True, "reason": AUTO_CLOSE_REASON, "age_days": age_days},
                )
                await db.execute(
                    text("UPDATE aisoc_cases SET evidence_chain = CAST(:c AS jsonb) WHERE id = :id AND tenant_id = :t").bindparams(
                        c=json.dumps(chain), id=case_id, t=tenant_id
                    )
                )
            except Exception:  # noqa: BLE001 - custody is best-effort; never fail the close
                logger.warning("case_auto_close.custody_append_failed case_id=%s", str(case_id)[:36], exc_info=True)

            await db.commit()

            result.closed += 1
            result.by_tenant[str(tenant_id)] = result.by_tenant.get(str(tenant_id), 0) + 1
            logger.warning(
                "case_auto_close.closed case_number=%s age_days=%s window_days=%d",
                str(row["case_number"] or "")[:32], age_days, days,
            )
        except Exception:  # noqa: BLE001 - fail-soft per case; the sweep continues
            await db.rollback()
            result.failed += 1
            logger.warning("case_auto_close.case_failed case_id=%s", str(case_id)[:36], exc_info=True)

    return result


async def run_once() -> AutoCloseSweepResult:
    async with AsyncSessionLocal() as db:
        return await sweep_auto_close(db)


async def run_forever() -> None:
    """Periodic worker. Exits immediately when disabled."""
    if not settings.CASE_AUTO_CLOSE_ENABLED:
        logger.info(
            "case_auto_close worker disabled; cases set to 'resolved' will never reach 'closed'. "
            "Set CASE_AUTO_CLOSE_ENABLED=true to sweep them"
        )
        return

    interval = settings.CASE_AUTO_CLOSE_INTERVAL_SECONDS
    days = settings.CASE_AUTO_CLOSE_AFTER_DAYS
    logger.info("case_auto_close worker started interval_s=%d window_days=%d", interval, days)

    while True:
        try:
            result = await run_once()
            if result.closed or result.failed:
                logger.warning(
                    "case_auto_close.sweep closed=%d failed=%d tenants=%d",
                    result.closed, result.failed, len(result.by_tenant),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - worker survives transient failures
            logger.error("case_auto_close.sweep_failed error=%s", type(exc).__name__)
        await asyncio.sleep(interval)


__all__ = [
    "AUTO_CLOSE_REASON",
    "AutoCloseSweepResult",
    "cutoff",
    "run_forever",
    "run_once",
    "sweep_auto_close",
]
