"""Expire approvals nobody answered (deferral 9b).

Phase 9's live-router half landed: a decision on `/approvals/{id}/decide`
carries through to `services/actions` and the row records whether it
executed. The durable timer table landed too, in `062_approval_timers.sql`.

What was left is every approval the bot never sees. The expiry lives in
`services/slack-bot`, a `chatops`-profile service, and is armed per ChatOps
approval. The API's own `agent_approvals` row carries an `expires_at` and its
status vocabulary includes `expired` — and **nothing wrote that status and no
worker swept the column**. An approval raised in the console and never
answered waited forever rather than timing out to its declared safe default.

Forever is the wrong default for a pending containment. It is also the
*invisible* wrong default: the row stays `pending`, the queue keeps showing
it, and nobody can tell a request still being considered from one abandoned
three weeks ago.

The safe default, and where it comes from
-----------------------------------------
`rejected`. Not invented here — it is what `services/slack-bot` has always
used (`SafeDefault = Literal["rejected", "approved"]` defaulting to
`"rejected"`, and `safe_default TEXT NOT NULL DEFAULT 'rejected'` in
migration 062), stated there as "so a forgotten approval can never
accidentally execute". This worker expires to the same default the other half
of the system already declares, because two halves timing out two different
ways would be worse than either.

Expiring is not deciding
------------------------
An expired approval is marked `expired`, and **nothing is dispatched**. The
`/decide` endpoint deliberately still accepts an `expired` row — its guard is
`status not in {"pending", "expired"}` — so a human who returns to a timed-out
request can still act on it. Timing out removes the pretence that the request
is live; it does not spend the decision on the operator's behalf.

Only rows that opted in
-----------------------
`expires_at` is nullable and only `POST /approvals` ever writes it, from a
caller-supplied value. Rows without one are left alone rather than given a
default window here: inventing a deadline for an approval whose creator did
not set one would start expiring containments on a schedule nobody chose.
That gap is reported in the run summary rather than silently closed, so the
number of never-expiring approvals is visible instead of assumed to be zero.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.approval_expiry")

#: The safe default, mirrored from `services/slack-bot` and migration 062.
#: A forgotten approval must never resolve to something that executes.
SAFE_DEFAULT = "rejected"

#: Expiring writes `expired`, which is in the status vocabulary the migration
#: comments and `approvals.py::_VALID_STATUSES` both declare, and which
#: nothing wrote before this worker.
EXPIRED_STATUS = "expired"

_SWEEP_SQL = text(
    """
    UPDATE agent_approvals
       SET status = :expired, decision_comment = COALESCE(decision_comment, :note)
     WHERE status = 'pending'
       AND expires_at IS NOT NULL
       AND expires_at < now()
    RETURNING id, tenant_id, risk_level
    """
)

#: Counted, not swept. An approval with no deadline is one whose creator did
#: not set one, and a worker that invented deadlines would start expiring
#: containments on a schedule nobody chose.
_NO_DEADLINE_SQL = text("SELECT count(*) FROM agent_approvals WHERE status = 'pending' AND expires_at IS NULL")

_NOTE = (
    "Expired automatically: the approval window elapsed with no decision. "
    f"Safe default is '{SAFE_DEFAULT}' — nothing was dispatched, and this request can still be decided."
)


@dataclass
class ExpirySweep:
    """What one sweep found."""

    started_at: datetime
    expired: int = 0
    #: Pending approvals that carry no deadline and therefore cannot expire.
    #: Reported so the gap is visible rather than read as zero.
    pending_without_deadline: int = 0
    by_risk: dict[str, int] = field(default_factory=dict)


async def run_once(*, db: AsyncSession | None = None) -> ExpirySweep:
    """Expire every pending approval whose window has elapsed, across all tenants."""
    own_session = db is None
    if db is None:
        db = AsyncSessionLocal()
    sweep = ExpirySweep(started_at=datetime.now(UTC))

    try:
        # Cross-tenant by nature. The precondition that makes the policy's
        # `OR current_tenant_id() IS NULL` arm apply is asserted rather than
        # assumed — a session bound to one tenant would expire that tenant's
        # approvals and report success for all of them.
        await assert_cross_tenant_session(db, "approval expiry sweep")

        rows = (await db.execute(_SWEEP_SQL, {"expired": EXPIRED_STATUS, "note": _NOTE})).mappings().all()
        sweep.expired = len(rows)
        for row in rows:
            level = str(row["risk_level"] or "unknown")
            sweep.by_risk[level] = sweep.by_risk.get(level, 0) + 1

        sweep.pending_without_deadline = int((await db.execute(_NO_DEADLINE_SQL)).scalar_one())
        await db.commit()
    finally:
        if own_session:
            await db.close()

    if sweep.expired:
        # At warning, not info. An approval timing out means a human was
        # asked and did not answer, which is a fact about the rota.
        logger.warning(
            "approval_expiry expired=%d by_risk=%s safe_default=%s",
            sweep.expired,
            sweep.by_risk,
            SAFE_DEFAULT,
        )
    if sweep.pending_without_deadline:
        logger.info(
            "approval_expiry %d pending approval(s) carry no expires_at and can never time out; "
            "set one at POST /approvals to bring them under this sweep",
            sweep.pending_without_deadline,
        )
    return sweep


async def run_forever() -> None:
    """Tick until cancelled. Owned by the API ``lifespan``, like the other workers."""
    interval = max(int(getattr(settings, "APPROVAL_EXPIRY_INTERVAL_SECONDS", 300)), 30)
    logger.info("approval_expiry started interval=%ds safe_default=%s", interval, SAFE_DEFAULT)
    failures = TickFailures("approval_expiry", logger)
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
        logger.info("approval_expiry stopped")
        raise


__all__ = ["EXPIRED_STATUS", "SAFE_DEFAULT", "ExpirySweep", "run_forever", "run_once"]
