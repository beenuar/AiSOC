"""Grade a shadow decision against the closure an analyst made in their own SIEM.

Gap-closure Phase 2.1.

Half the closures that matter never happen in AiSOC. A customer evaluating the
agent runs their queue where they always have: an analyst dispositions the
notable in Splunk ES, classifies the incident in Sentinel, closes the offense
in QRadar. If agreement were measured only against closures made in this
console, a tenant whose analysts work in their SIEM would show a scorecard
that never fills in, and the natural reading of that is "the agent is not
being evaluated" rather than "we are looking in the wrong place".

Phase 1.1 already built the readers. ``SplunkClient.list_closed_notables``,
``SentinelClient.list_closed_incidents``, ``ElasticClient.list_closed_signals``,
``QRadarClient.list_closed_offenses`` and ``DefenderClient.list_resolved_alerts``
each return :class:`~app.services.alert_history.ClosedFinding` rows carrying
the analyst's disposition already mapped onto the canonical taxonomy, with a
vendor label outside it landing on ``unlabeled`` rather than being guessed at.
This module is the sink those rows flow into: it is the one piece Phase 2
needed that Phase 1 did not build, and it deliberately reuses the readers
rather than adding a sixth way to ask a SIEM what its analysts decided.

The join key
============

``ClosedFinding.finding_id`` is the vendor's own id for the finding, and it
reaches the shadow decision row as ``external_id`` by way of
``alerts.external_id``, which ``services/ingest`` already carries through from
the vendor payload. Matching on anything else, a title or a timestamp, would
silently grade one alert against another's closure, and the symptom would be
an agreement rate that is merely wrong rather than obviously broken.

What it refuses to do
=====================

It never invents a label. A finding whose disposition is ``unlabeled`` is
still recorded as resolved, because "an analyst looked at this and declined to
classify it" is a fact the scorecard must show; it is excluded from every rate
by the aggregate, not by being dropped here. Dropping it would make a tenant
whose history is mostly unlabeled look like a tenant with a small clean
sample.

It never overwrites a decision that already carries a closure. A tenant whose
analysts work in both places would otherwise have whichever reconciliation ran
last win, and a promotion would rest on evidence that changes depending on
scheduling.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog

from app.services.alert_history import UNLABELED, ClosedFinding
from app.services.disposition_writeback import CANONICAL_DISPOSITIONS

logger = structlog.get_logger(__name__)

__all__ = ["ReconcileResult", "database_configured", "reconcile_findings"]


@dataclass(frozen=True)
class ReconcileResult:
    """What one reconciliation pass did, in numbers an operator can act on.

    ``unmatched`` is the interesting one. A large unmatched count against a
    healthy ``matched`` means the tenant's analysts are closing findings the
    agent never triaged, which is ordinary. A total of zero matched with a
    large unmatched means the join key is not arriving, which is a wiring
    fault, and the two must not be reported as one number.
    """

    considered: int = 0
    matched: int = 0
    unmatched: int = 0
    already_resolved: int = 0
    skipped_no_key: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "considered": self.considered,
            "matched": self.matched,
            "unmatched": self.unmatched,
            "already_resolved": self.already_resolved,
            "skipped_no_key": self.skipped_no_key,
        }


def _dsn() -> str | None:
    """An asyncpg-compatible DSN, or None when no database is configured.

    Same resolution as ``tenant_policy._dsn`` and ``action_store._dsn``:
    both the SQLAlchemy spelling the API uses and the plain pgx spelling
    ``services/ingest`` uses are already present in deployed environments.
    """
    raw = (os.environ.get("DATABASE_DSN") or os.environ.get("DATABASE_URL") or "").strip()
    if not raw:
        return None
    return raw.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


def database_configured() -> bool:
    """Whether this service can reach the database the decisions live in.

    Asked by the route before it reads a vendor window, because the no-database
    path below returns a result rather than raising: it reports ``considered``
    findings and ``matched`` zero, which is indistinguishable from a window
    whose join key never arrives. One of those is a wiring fault in ingest and
    the other is a missing ``DATABASE_URL`` on this container, and a sweep that
    reported them the same way would send an operator to debug the wrong one.
    """
    return _dsn() is not None


async def _connect(dsn: str) -> Any:
    import asyncpg  # noqa: PLC0415 - optional at import time; only needed with a DSN

    return await asyncpg.connect(dsn, timeout=10.0)


def _disposition_of(finding: ClosedFinding) -> str:
    """The label to record: canonical, or the literal ``unlabeled``.

    ``ClosedFinding.__post_init__`` already refuses anything else, so this is
    belt and braces rather than a second mapping. It exists so that a future
    reader who changes the reader layer finds the invariant restated at the
    point it is written to the database.
    """
    return finding.disposition if finding.disposition in CANONICAL_DISPOSITIONS else UNLABELED


async def reconcile_findings(
    tenant_id: str | UUID,
    findings: Iterable[ClosedFinding],
    *,
    connection: Any = None,
) -> ReconcileResult:
    """Attach each closure to the shadow decision it grades, if there is one.

    ``connection`` is injectable so a test drives the real SQL against a real
    connection, and so a caller reconciling several vendors in one pass does
    not open five. Production passes nothing and gets one connection for the
    call.
    """
    rows: Sequence[ClosedFinding] = list(findings)
    if not rows:
        return ReconcileResult()

    owned = connection is None
    if owned:
        dsn = _dsn()
        if dsn is None:
            logger.debug("shadow_reconcile.no_database")
            return ReconcileResult(considered=len(rows), skipped_no_key=0)
        connection = await _connect(dsn)

    result = ReconcileResult(considered=len(rows))
    try:
        await connection.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(tenant_id))
        for finding in rows:
            key = (finding.finding_id or "").strip()
            if not key:
                result = _bump(result, skipped_no_key=1)
                continue
            updated = await connection.fetchval(
                """
                UPDATE aisoc_shadow_decisions
                   SET analyst_disposition = $3,
                       vendor_disposition = $4,
                       resolution_source = $5,
                       resolved_at = $6,
                       resolved_by = $7
                 WHERE tenant_id = $1
                   AND external_id = $2
                   AND resolved_at IS NULL
                RETURNING id
                """,
                UUID(str(tenant_id)),
                key,
                _disposition_of(finding),
                finding.vendor_disposition or None,
                finding.vendor,
                finding.closed_at,
                finding.closed_by,
            )
            if updated is not None:
                result = _bump(result, matched=1)
                continue
            # No row updated means either no decision carries this id, or the
            # one that does was already graded. The two are told apart
            # explicitly rather than folded together, because one is ordinary
            # and one means the join key never arrives.
            existing = await connection.fetchval(
                """
                SELECT 1 FROM aisoc_shadow_decisions
                 WHERE tenant_id = $1 AND external_id = $2 AND resolved_at IS NOT NULL
                 LIMIT 1
                """,
                UUID(str(tenant_id)),
                key,
            )
            result = _bump(result, already_resolved=1) if existing else _bump(result, unmatched=1)
    finally:
        if owned:
            await connection.close()

    logger.info("shadow_reconcile.pass_complete", tenant_id=str(tenant_id), **result.as_dict())
    return result


def _bump(result: ReconcileResult, **deltas: int) -> ReconcileResult:
    """Return ``result`` with the named counters advanced.

    The dataclass is frozen because it is reported and logged, and a counter
    somebody can mutate after the log line is written is a counter that
    eventually disagrees with it.
    """
    return ReconcileResult(
        considered=result.considered + deltas.get("considered", 0),
        matched=result.matched + deltas.get("matched", 0),
        unmatched=result.unmatched + deltas.get("unmatched", 0),
        already_resolved=result.already_resolved + deltas.get("already_resolved", 0),
        skipped_no_key=result.skipped_no_key + deltas.get("skipped_no_key", 0),
    )
