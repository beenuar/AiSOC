"""Emit the alert lifecycle events SLA reporting is computed from.

Wave 0 of the gap-closure plan.

`alert_sla_events` has one writer in the shipped product: `POST
/api/v1/sla/events`, which nothing calls. The console never posts it and
no service emits it, so :mod:`app.services.sla` — 350 lines computing
MTTD, MTTR and MTTC per severity against five configurable tiers, with a
dashboard rendering the result — aggregates over an empty table on every
deployment. The arithmetic is right and there is nothing to do it on.

Where the events come from now
--------------------------------
``acknowledged`` when an analyst claims an alert, and ``resolved`` when
a disposition is set. Both are the moment the thing actually happened
rather than a background sweep, so the timestamp is the event's own.

``detected`` is **backfilled** rather than emitted at creation time, and
that is the one decision here worth explaining. Alerts are written by
`services/fusion` on a different database session; making fusion emit
into an API-owned table would couple the hot ingest path to SLA
reporting, and a fusion deployment that lagged behind the API schema
would start failing to write alerts. Instead, the first lifecycle event
for an alert checks whether a ``detected`` row exists and, if not,
writes one stamped with ``alerts.created_at`` — the real detection time,
already recorded. The pair is therefore always complete, and MTTD is
measured from when the alert existed rather than from when somebody
happened to install this code.

Never raises
------------
Every function here swallows its failure and logs at ``warning``. An SLA
event is a measurement of work, not the work: losing the analyst's claim
because a reporting insert failed would be the wrong trade. The log line
is how a missing row is explained rather than mysterious.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)

__all__ = ["EVENT_TYPES", "record_event"]

#: Mirrors the `ck_sla_event_type` check constraint. A value outside this
#: set is refused by the database, so it is refused here first with a
#: message naming the column rather than as an IntegrityError.
EVENT_TYPES = ("detected", "acknowledged", "resolved", "closed")


def _clean(value: Any, limit: int = 200) -> str:
    return str(value).replace("\r", "").replace("\n", " ")[:limit]


async def record_event(
    db: Any,
    *,
    alert_id: uuid.UUID | str,
    tenant_id: uuid.UUID | str,
    event_type: str,
    actor_id: uuid.UUID | str | None = None,
    occurred_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> bool:
    """Record one lifecycle event, backfilling ``detected`` if needed.

    Returns whether the event was written. Callers do not check it — the
    return exists so a test can assert the write happened rather than
    inferring it from an absence of exceptions.
    """
    if event_type not in EVENT_TYPES:
        logger.warning("sla_events.unknown_type type=%s", _clean(event_type, 40))
        return False

    try:
        severity = await db.scalar(
            text("SELECT severity FROM alerts WHERE id = CAST(:a AS uuid) AND tenant_id = CAST(:t AS uuid)").bindparams(
                a=str(alert_id), t=str(tenant_id)
            )
        )
        if severity is None:
            # The alert is gone or belongs to another tenant. Recording an
            # event for it would put a row in the reporting table that no
            # alert explains.
            return False

        if event_type != "detected":
            await _ensure_detected(db, alert_id=alert_id, tenant_id=tenant_id, severity=severity)

        existing = await db.scalar(
            text(
                "SELECT 1 FROM alert_sla_events "
                " WHERE alert_id = CAST(:a AS uuid) AND tenant_id = CAST(:t AS uuid) AND event_type = :e "
                " LIMIT 1"
            ).bindparams(a=str(alert_id), t=str(tenant_id), e=event_type)
        )
        if existing:
            # Idempotent. An analyst re-claiming after a release must not
            # move the acknowledgement time, for the same reason
            # `first_seen_at` is written with COALESCE.
            return False

        await db.execute(
            text("""
                INSERT INTO alert_sla_events
                    (id, tenant_id, alert_id, severity, event_type, occurred_at, actor_id, metadata)
                VALUES (gen_random_uuid(), CAST(:t AS uuid), CAST(:a AS uuid), :s, :e, :o,
                        CAST(:actor AS uuid), CAST(:m AS jsonb))
            """).bindparams(
                t=str(tenant_id),
                a=str(alert_id),
                s=str(severity),
                e=event_type,
                o=occurred_at or datetime.now(UTC),
                actor=str(actor_id) if actor_id else None,
                m=json.dumps(metadata or {}),
            )
        )
        return True
    except Exception as exc:  # noqa: BLE001 - reporting must not fail the work
        logger.warning(
            "sla_events.write_failed type=%s alert=%s error=%s",
            _clean(event_type, 40),
            _clean(alert_id, 40),
            _clean(exc),
        )
        return False


async def _ensure_detected(db: Any, *, alert_id: Any, tenant_id: Any, severity: str) -> None:
    """Write the ``detected`` event from the alert's own creation time.

    Done lazily so `services/fusion` does not have to write into a table
    the API owns. `ON CONFLICT DO NOTHING` is not available without a
    unique constraint, so this checks first; a race writes two rows,
    which overstates nothing because `sla.py` takes the earliest.
    """
    already = await db.scalar(
        text(
            "SELECT 1 FROM alert_sla_events "
            " WHERE alert_id = CAST(:a AS uuid) AND tenant_id = CAST(:t AS uuid) AND event_type = 'detected' "
            " LIMIT 1"
        ).bindparams(a=str(alert_id), t=str(tenant_id))
    )
    if already:
        return

    await db.execute(
        text("""
            INSERT INTO alert_sla_events
                (id, tenant_id, alert_id, severity, event_type, occurred_at, metadata)
            SELECT gen_random_uuid(), a.tenant_id, a.id, :s, 'detected', a.created_at,
                   CAST('{"backfilled": true}' AS jsonb)
              FROM alerts a
             WHERE a.id = CAST(:a AS uuid) AND a.tenant_id = CAST(:t AS uuid)
        """).bindparams(a=str(alert_id), t=str(tenant_id), s=str(severity))
    )
