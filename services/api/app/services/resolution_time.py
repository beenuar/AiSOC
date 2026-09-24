"""One definition of "how long did it take to resolve", for every surface.

The dashboard and the MSSP portfolio both answer "what is our MTTR?" and they
answered it differently, from separate queries, against the same rows. The
dashboard printed **0.0 hrs** and **Cases Closed (7d) 0** for a tenant that
had closed two cases at a 90-minute mean, which the portfolio reported
correctly as 1.5h. Two wrong things caused that, and both are the kind that
survive review because each query reads plausibly on its own:

**The dashboard counted the wrong lifecycle state.** It filtered
``status = 'resolved'``, but ``resolved`` is an intermediate state — the
terminal one is ``closed`` (see ``_TRANSITIONS`` in the cases endpoint), and
it is the transition that writes ``closed_at``. A case that completed its
lifecycle was therefore invisible to the count. It also windowed on
``updated_at``, a mutable audit column, so editing a note on an old case
would move it into the window and closing one without touching it again
would eventually move it out.

**The dashboard measured a different table.** It averaged
``alerts.resolved_at - alerts.created_at`` while the portfolio averaged
``cases.closed_at - cases.created_at``. Only three code paths ever write
``alerts.resolved_at``, none of which runs during ordinary case work, so the
average was over zero rows — and ``float(None or 0.0)`` published that as a
confident ``0.0``.

So this module owns the definition rather than the execution. The portfolio
computes MTTR inside one bound cross-tenant statement on purpose (one round
trip for the whole portfolio, see ``mssp_portfolio``), and splitting that
apart to share a function would cost a query per tenant. Sharing the window
and the SQL expression keeps one source of truth without that; the property
that actually prevents the two surfaces drifting apart again is the test that
asserts they report the same number for the same rows.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Window for the resolution-time average. Long enough that a tenant closing a
# handful of cases a week still has a number, short enough that it tracks how
# the account is being run now rather than a year ago.
MTTR_WINDOW = timedelta(days=30)

# What "this case is finished" means. `closed_at` is written by the transition
# into the terminal state, so its presence is the fact; `status` is a label
# that has had several spellings. The `closed_at >= created_at` guard drops
# rows whose timestamps were back-filled out of order rather than letting a
# negative duration pull the mean below zero.
CLOSED_CASE_PREDICATE = "closed_at IS NOT NULL AND closed_at >= created_at"

# Mean resolution time in minutes. Rounded here, once, so no caller has to
# decide — and so the dashboard and the portfolio round identically.
MTTR_MINUTES_EXPR = "round((avg(EXTRACT(EPOCH FROM (closed_at - created_at))) / 60.0)::numeric, 1)::float8"


async def tenant_case_mttr_minutes(db: AsyncSession, tenant_id) -> float | None:
    """Mean minutes from case open to case close for one tenant.

    ``None`` when the tenant closed nothing in the window. That is the whole
    point of the return type: a tenant with no closed cases has no MTTR, and
    reporting ``0.0`` puts them top of the league table for having done
    nothing.
    """
    value = await db.scalar(
        text(
            f"""
            SELECT {MTTR_MINUTES_EXPR} AS mttr_minutes
              FROM cases
             WHERE tenant_id = :tenant_id
               AND {CLOSED_CASE_PREDICATE}
               AND closed_at >= :since
            """
        ),
        {"tenant_id": str(tenant_id), "since": datetime.now(UTC) - MTTR_WINDOW},
    )
    return float(value) if value is not None else None


async def tenant_cases_closed(db: AsyncSession, tenant_id, since: datetime) -> int:
    """Cases this tenant actually finished since ``since``.

    Counted on ``closed_at`` for the same reason the mean is: it is the column
    the close writes, and it does not move when someone edits the case later.
    """
    value = await db.scalar(
        text(
            f"""
            SELECT count(*)
              FROM cases
             WHERE tenant_id = :tenant_id
               AND {CLOSED_CASE_PREDICATE}
               AND closed_at >= :since
            """
        ),
        {"tenant_id": str(tenant_id), "since": since},
    )
    return int(value or 0)
