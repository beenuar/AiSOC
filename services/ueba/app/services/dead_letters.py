"""Record events this service refused, where an operator already looks.

The UEBA consumer had no ``except`` around its handler at all, so the first
event that raised ended the ``async for``, ran the ``finally`` that stopped
the consumer, and left the container ``running`` with ``/health`` answering
200. Nothing was logged, because the task holding the exception lived in a
module global and was never garbage-collected, so asyncio's
"exception was never retrieved" warning never fired either.

Guarding the handler is half the fix; the other half is that a guarded
failure has to go somewhere. It goes to ``aisoc_dead_letters`` — the table
``services/fusion`` already writes and ``GET /api/v1/health/dead-letters``
already reads, with a per-reason breakdown that turns fifty identical rows
into one finding. A second dead-letter path would mean an operator had to
know to check two.

Two properties, both inherited deliberately from
``services/fusion/app/services/dlq_sink.py``:

**A failure to record must not become a second failure.** The sink exists to
let the consumer keep going; if writing the record can raise, one bad event
stops the stream anyway. Every error here is logged and swallowed.

**The payload is truncated, never stored whole.** It is the thing that was
refused, so it is untrusted by definition and may be large.
"""

from __future__ import annotations

import json
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

logger = structlog.get_logger(__name__)

#: Characters of payload kept. Matches the fusion sink so the same column
#: holds comparable rows: enough to recognise the shape and find the
#: producer, far short of enough to replay it.
MAX_EXCERPT = 2000

#: This service's schema version marker on the shared table. The column is
#: ``NOT NULL DEFAULT 'unknown'`` and "unknown" would be a worse answer than
#: naming the envelope the consumer was reading.
SCHEMA_VERSION = "ueba.raw_events.v1"

_INSERT_SQL = text(
    """
    INSERT INTO aisoc_dead_letters
        (tenant_id, topic, reason, schema_version, payload_excerpt, source_event_id)
    VALUES (:tenant_id, :topic, :reason, :schema_version, :payload_excerpt, :source_event_id)
    """
)


def _excerpt(payload: Any) -> str:
    try:
        return json.dumps(payload, default=str)[:MAX_EXCERPT]
    except (TypeError, ValueError):
        return str(payload)[:MAX_EXCERPT]


class DeadLetterSink:
    """Persist a refused event to the shared dead-letter table."""

    def __init__(self, session_factory: async_sessionmaker) -> None:
        self._session_factory = session_factory

    async def record(
        self,
        *,
        topic: str,
        reason: str,
        payload: Any,
        tenant_id: str | None = None,
        source_event_id: str | None = None,
    ) -> bool:
        """Write one dead letter. Returns whether it landed.

        The return value is for the caller's counters, not for control flow —
        there is no branch here a consumer should take differently.
        """
        params = {
            "tenant_id": tenant_id,
            "topic": topic,
            "reason": reason[:1000],
            "schema_version": SCHEMA_VERSION,
            "payload_excerpt": _excerpt(payload),
            "source_event_id": source_event_id,
        }

        # Two attempts, and the second is not a retry of the same statement.
        # ``tenant_id`` carries a foreign key to ``tenants``, and UEBA's
        # tenants come from the event envelope rather than from a join — an
        # event naming a tenant this database has never seen would otherwise
        # lose the dead letter to a constraint violation, and that event is
        # precisely the evidence that something upstream is producing them.
        # The reason string already names the tenant, so nothing is lost by
        # detaching the column.
        last_error: Exception | None = None
        for attempt_params in (params, {**params, "tenant_id": None}):
            try:
                async with self._session_factory() as session:
                    async with session.begin():
                        await session.execute(_INSERT_SQL, attempt_params)
                return True
            except Exception as exc:  # noqa: BLE001 — see the module docstring
                last_error = exc
                if attempt_params["tenant_id"] is None:
                    break

        logger.warning(
            "ueba.dead_letter_persist_failed",
            topic=topic,
            reason=reason[:200],
            error=str(last_error)[:300],
            hint=(
                "the refused event is in the log line above this one; "
                "aisoc_dead_letters is created by services/api migration "
                "053_dead_letters.sql"
            ),
        )
        return False
