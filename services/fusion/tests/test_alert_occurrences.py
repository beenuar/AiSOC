"""A repeated vendor finding is one alert that says how many times.

Wave 2, Phase 3.3. Same-fingerprint repeats are already collapsed — a 300 s
Redis check in ``Deduplicator``, a ``WHERE NOT EXISTS`` in the insert, and
``uq_alerts_tenant_dedup`` from migration 120 behind both. All three work.
What none of them does is *keep* the repeat.

What the tree does with a repeat today
--------------------------------------
Exactly one thing: it appends the folded event's id to the surviving alert's
``source_event_ids`` array, best-effort, capped at 200, and only when the id
is not already there. That column answers "did more than one event produce
this?" and nothing else. It cannot answer the question an analyst actually
asks of a noisy vendor — *how many times, between when and when* — because:

* it conflates true repeats with multi-event correlation (both append), so a
  length of 79 does not mean 79 repeats;
* it saturates at 200 and then silently stops, so a vendor repeating a
  finding 5,000 times and one repeating it 200 times read identically;
* ``alerts.first_seen`` and ``alerts.last_seen`` have existed since
  ``001_init.sql`` and **fusion has never written either**, so the window the
  repeats span is not recorded anywhere at all.

So "a vendor repeating a finding 79 times is one alert that says 79" is not
expressible. The first test below is the reproduction: it asks for the count
and the window, and on the pre-change tree there is no statement that carries
either.

Why a count and not a row per repeat
------------------------------------
A row per occurrence is unbounded by construction and the one shape this
pipeline must never take — "one IOC, a thousand alerts" is the failure the
retro-hunt sweep is deliberately built to avoid, and the same reasoning
applies here. ``alert_occurrences`` is therefore a rollup keyed
``(tenant_id, alert_id)``: an exact count, the real window, and a bounded
*recent* window of the original payload ids.

The recent window, rather than the first N, is the deliberate half. A Kafka
consumer-group rebalance redelivers recent messages, and the redelivery guard
is a containment test against the ids the row still holds. Keeping the
*oldest* 200 would put the guard's coverage exactly where redelivery never
happens; keeping the most recent 200 puts it exactly where it does.
``payload_ids_complete`` goes false the moment the window evicts anything, so
a reader is never told a partial list is the whole set.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import AlertSink, PersistOutcome

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
CONNECTOR = uuid.UUID("00000000-0000-0000-0000-0000000000c1")


def _fused(
    decision: FusionDecision = FusionDecision.NEW_ALERT,
    *,
    source_event_ids: list[str] | None = None,
    event_time: datetime | None = None,
) -> FusedAlert:
    """A GuardDuty-shaped finding, the canonical repeating vendor alert."""
    raw = RawAlert(
        tenant_id=TENANT,
        source="AWS GuardDuty",
        title="UnauthorizedAccess:EC2/SSHBruteForce",
        severity=AlertSeverity.HIGH,
        src_ip="203.0.113.17",
        hostname="i-0abc123def456",
        mitre_techniques=["T1110"],
        connector_id=CONNECTOR,
        connector_type="aws_guardduty",
        source_event_ids=["evt-1"] if source_event_ids is None else list(source_event_ids),
        ocsf_class_uid=2004,
        event_time=event_time or datetime(2026, 11, 1, 9, 0, tzinfo=UTC),
    )
    raw.id = raw.deterministic_id()
    return FusedAlert(id=raw.id, tenant_id=TENANT, fusion_decision=decision, alert=raw)


_UNSET = object()


class _StubConn:
    """Records every statement, and answers fetchrow with a scripted row."""

    def __init__(self, row, surviving=_UNSET):
        self._row = row
        self._surviving = row if surviving is _UNSET else surviving
        self.calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        lowered = sql.lower().lstrip()
        if lowered.startswith("select") and "from alerts" in lowered and "dedup_hash" in lowered:
            return self._surviving
        return self._row

    async def execute(self, sql, *args):
        self.calls.append((sql, args))
        return "INSERT 0 1"


class _StubPool:
    def __init__(self, row, surviving=_UNSET):
        self.conn = _StubConn(row, surviving=surviving)

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


def _occurrence_statements(pool: _StubPool) -> list[tuple[str, tuple]]:
    return [(sql, args) for sql, args in pool.conn.calls if "alert_occurrences" in sql]


# ── the reproduction ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_repeated_finding_is_counted_on_the_alert_it_folded_onto() -> None:
    """The gap: a repeat is collapsed and the fact that it happened is lost.

    On the pre-change tree the only statement a duplicate produces is the
    ``source_event_ids`` append, which carries no count and no window. This
    test fails there with "no statement touched alert_occurrences".
    """
    pool = _StubPool(row=None, surviving={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    result = await sink.persist(_fused(source_event_ids=["evt-2"]))
    assert result.outcome is PersistOutcome.DUPLICATE

    statements = _occurrence_statements(pool)
    assert statements, (
        "a repeated vendor finding folded onto its surviving alert and left no "
        "occurrence record, so the alert cannot say how many times the vendor "
        "reported it. source_event_ids is not that number: it also grows on "
        "multi-event correlation and stops at 200."
    )


@pytest.mark.asyncio
async def test_the_occurrence_record_carries_the_folded_payload_id() -> None:
    """The original payload id is kept, so the repeat resolves to its source."""
    pool = _StubPool(row=None, surviving={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist(_fused(source_event_ids=["gd-finding-0042"]))

    statements = _occurrence_statements(pool)
    assert statements, "no occurrence statement issued"
    assert "gd-finding-0042" in json.dumps(statements[0][1], default=str)


@pytest.mark.asyncio
async def test_the_occurrence_record_is_tenant_scoped_in_the_statement() -> None:
    """RLS is defence in depth; the predicate is the control.

    ``scripts/check_tenant_query_predicates.py`` reads this statement and
    requires the tenant in the SQL rather than only in the session GUC.
    """
    pool = _StubPool(row=None, surviving={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist(_fused(source_event_ids=["evt-9"]))

    sql, args = _occurrence_statements(pool)[0]
    assert "tenant_id" in sql
    assert TENANT in args


@pytest.mark.asyncio
async def test_a_redelivered_event_cannot_inflate_the_count() -> None:
    """The guard a Kafka rebalance makes necessary, visible in the SQL.

    A consumer-group rebalance redelivers the same message. If the count
    incremented unconditionally, "79" would be "how many times this message
    was delivered", not "how many times the vendor reported it" — the exact
    shape of fabricated measurement this project refuses.
    """
    pool = _StubPool(row=None, surviving={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist(_fused(source_event_ids=["evt-redelivered"]))

    sql, _ = _occurrence_statements(pool)[0]
    normalised = " ".join(sql.split()).lower()
    assert "@>" in normalised, (
        "the occurrence statement has no containment guard, so a redelivered message increments the count a second time"
    )


@pytest.mark.asyncio
async def test_an_inserted_alert_writes_no_occurrence_row() -> None:
    """The first sighting is the alert itself; the extra write is only for repeats."""
    fused = _fused()
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist(fused)

    assert _occurrence_statements(pool) == []


@pytest.mark.asyncio
async def test_a_repeat_with_no_payload_id_still_counts() -> None:
    """A vendor that sends no event id still repeated, and the count says so.

    ``_record_deduplicated_event`` returns early when there is no id, because
    it has nothing to append. The count does not depend on an id, and
    returning early here would under-report every connector whose normaliser
    does not populate ``source_event_ids`` — which is most of them.
    """
    pool = _StubPool(row=None, surviving={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    result = await sink.persist(_fused(source_event_ids=[]))
    assert result.outcome is PersistOutcome.DUPLICATE

    assert _occurrence_statements(pool), (
        "a repeat from a connector that emits no source event id was not "
        "counted, so the occurrence count under-reports exactly the "
        "connectors whose normaliser leaves source_event_ids empty"
    )


@pytest.mark.asyncio
async def test_a_failing_occurrence_write_does_not_change_the_verdict() -> None:
    """Provenance is best-effort; it must never cost a durable alert."""

    class _BoomConn(_StubConn):
        async def execute(self, sql, *args):
            self.calls.append((sql, args))
            raise RuntimeError("connection reset")

    pool = _StubPool(row=None, surviving={"id": uuid.uuid4()})
    pool.conn = _BoomConn(row=None, surviving={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    result = await sink.persist(_fused(source_event_ids=["evt-boom"]))
    assert result.outcome is PersistOutcome.DUPLICATE
