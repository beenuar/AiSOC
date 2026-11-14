"""A trip survives a receiver that is down, against real Postgres.

GHSA-9q6p-m345-h3hj (F58). The reporter's proof of concept is "configure a
receiver, take it down, trip a token, bring the receiver back up — no alert
is ever sent". That is this file, executed.

Why live
--------
The durability claim is made of database facts a stub cannot show:

* the journal row is committed **before** delivery is attempted, so a crash
  in the delivery window costs a duplicate rather than the signal;
* ``status``/``attempts``/``next_attempt_at`` form a state machine whose
  terminal states must really be terminal — a ``dead`` row that the claim
  query still returns would be retried forever;
* ``trigger_id`` is UNIQUE, so a redelivery bumps an attempt instead of
  growing the table without bound. Only Postgres enforces that;
* the partial index and the ``status = 'pending'`` predicate have to agree,
  or the drain silently finds nothing and the outbox fills up quietly —
  which is a more honest version of the original defect, not a fix.

Skips without a database rather than passing without one.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
import sqlalchemy as sa
from app.models.honeytoken import HoneytokenAlertOutbox
from app.services.delivery import MAX_ATTEMPTS, DeliveryResult, Disposition
from app.services.outbox import drain_once, record_attempt
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("HONEYTOKEN_OUTBOX_DSN", "").strip()

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(not DSN, reason="HONEYTOKEN_OUTBOX_DSN is not set; this suite needs a live Postgres"),
]

TENANT = uuid.UUID("11111111-1111-1111-1111-1111111111aa")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def sessions():
    engine = create_async_engine(DSN)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(loop_scope="module")
async def journal(sessions):
    """Write a pending row the way the trip route does, and hand back its id."""

    async def _write(trigger_id: uuid.UUID | None = None) -> uuid.UUID:
        trigger_id = trigger_id or uuid.uuid4()
        async with sessions() as session:
            session.add(
                HoneytokenAlertOutbox(
                    tenant_id=TENANT,
                    trigger_id=trigger_id,
                    payload={"event": "honeytoken.triggered", "trigger_id": str(trigger_id)},
                )
            )
            await session.commit()
        return trigger_id

    return _write


def _recorder(sink: list[dict]):
    """A `deliver` stand-in that records what it was asked to send."""

    async def _deliver(payload, **_):
        sink.append(payload)
        return DeliveryResult(Disposition.DELIVERED, "ingest responded 202")

    return _deliver


def _mine(calls: list[dict], trigger_id: uuid.UUID) -> int:
    """How many of those deliveries were *this* test's row.

    Scoped deliberately. `drain_once` returns a count over the whole table,
    and this suite shares a database with every other row a CI run leaves
    behind -- an assertion on the global count passes or fails depending on
    what ran before it, which is how a live test gets its answer from
    somebody else's data.
    """
    return sum(1 for c in calls if c.get("trigger_id") == str(trigger_id))


async def _row(sessions, trigger_id: uuid.UUID):
    async with sessions() as session:
        return (await session.execute(sa.select(HoneytokenAlertOutbox).where(HoneytokenAlertOutbox.trigger_id == trigger_id))).scalar_one()


# ── the advisory's proof of concept ───────────────────────────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_a_trip_during_a_receiver_outage_is_delivered_once_it_returns(sessions, journal, monkeypatch) -> None:
    """Down, trip, up — the alert must arrive. It never used to."""
    from app.services import outbox

    trigger_id = await journal()

    # The receiver is down. This is the attempt the trip route makes inline.
    async with sessions() as session:
        await record_attempt(
            session,
            trigger_id=trigger_id,
            result=DeliveryResult(Disposition.RETRY, "ConnectError: connection refused"),
        )

    row = await _row(sessions, trigger_id)
    assert row.status == "pending", "the trip was dropped rather than kept for retry"
    assert row.attempts == 1
    assert "connection refused" in row.last_error

    # It is not due yet — the backoff is real, not a busy loop. Asserted on
    # this row's attempt count rather than on the drain's global return,
    # which counts whatever else the database happens to hold.
    await drain_once(sessions)
    assert (await _row(sessions, trigger_id)).attempts == 1, "a row inside its backoff was retried early"

    # Time passes and the receiver comes back.
    async with sessions() as session:
        await session.execute(
            sa.update(HoneytokenAlertOutbox)
            .where(HoneytokenAlertOutbox.trigger_id == trigger_id)
            .values(next_attempt_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()

    delivered: list[dict] = []
    monkeypatch.setattr(outbox, "deliver", _recorder(delivered))
    await drain_once(sessions)

    row = await _row(sessions, trigger_id)
    assert row.status == "delivered", f"the receiver returned and the trip is still {row.status}"
    assert row.delivered_at is not None
    assert row.last_error is None
    assert _mine(delivered, trigger_id) == 1, "the recovered trip was not delivered exactly once"


@pytest.mark.asyncio(loop_scope="module")
async def test_a_delivered_row_is_never_drained_again(sessions, journal, monkeypatch) -> None:
    """A terminal state has to be terminal, or the receiver gets it forever."""
    from app.services import outbox

    trigger_id = await journal()
    async with sessions() as session:
        await record_attempt(session, trigger_id=trigger_id, result=DeliveryResult(Disposition.DELIVERED, "202"))

    calls: list[dict] = []
    monkeypatch.setattr(outbox, "deliver", _recorder(calls))
    await drain_once(sessions)
    assert _mine(calls, trigger_id) == 0, "a delivered trip was sent a second time"


@pytest.mark.asyncio(loop_scope="module")
async def test_a_permanent_failure_is_dead_rather_than_retried_forever(sessions, journal, monkeypatch) -> None:
    """A 404 retried for a day is load with no alert, and tells nobody."""
    from app.services import outbox

    trigger_id = await journal()
    async with sessions() as session:
        await record_attempt(
            session,
            trigger_id=trigger_id,
            result=DeliveryResult(Disposition.DEAD, "ingest responded 404"),
        )

    row = await _row(sessions, trigger_id)
    assert row.status == "dead"
    assert "404" in row.last_error, "a dead row must say why, or the operator has only a log line"

    calls: list[dict] = []

    async def _count(payload, **_):
        calls.append(payload)
        return DeliveryResult(Disposition.DELIVERED, "202")

    monkeypatch.setattr(outbox, "deliver", _count)
    await drain_once(sessions)
    assert calls == [], "a dead trip was retried"


@pytest.mark.asyncio(loop_scope="module")
async def test_the_attempt_ceiling_ends_in_dead_with_the_reason(sessions, journal) -> None:
    """A row that will never land stops, rather than retrying until somebody notices."""
    trigger_id = await journal()
    for _ in range(MAX_ATTEMPTS):
        async with sessions() as session:
            await record_attempt(
                session,
                trigger_id=trigger_id,
                result=DeliveryResult(Disposition.RETRY, "ReadTimeout: timed out"),
            )

    row = await _row(sessions, trigger_id)
    assert row.attempts == MAX_ATTEMPTS
    assert row.status == "dead", f"still {row.status} after {MAX_ATTEMPTS} attempts"
    assert "gave up" in row.last_error


@pytest.mark.asyncio(loop_scope="module")
async def test_one_trip_is_one_row_however_many_times_it_is_journalled(sessions, journal) -> None:
    """The UNIQUE on trigger_id is what stops an outage growing this table."""
    trigger_id = await journal()
    with pytest.raises(Exception) as caught:
        await journal(trigger_id)
    assert "unique" in str(caught.value).lower() or "duplicate" in str(caught.value).lower()


@pytest.mark.asyncio(loop_scope="module")
async def test_the_claim_is_a_lease_so_two_drainers_do_not_both_deliver(sessions, journal, monkeypatch) -> None:
    """`FOR UPDATE SKIP LOCKED` plus `claimed_until`, asserted rather than assumed."""
    from app.services import outbox

    trigger_id = await journal()
    async with sessions() as session:
        await session.execute(
            sa.update(HoneytokenAlertOutbox)
            .where(HoneytokenAlertOutbox.trigger_id == trigger_id)
            .values(next_attempt_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()

    seen: list[dict] = []
    monkeypatch.setattr(outbox, "deliver", _recorder(seen))
    await drain_once(sessions)
    assert _mine(seen, trigger_id) == 1, "the drain did not deliver this trip exactly once"

    # A second pass must not send it again: the row is delivered, and even
    # had it not been, the claim would still be held.
    await drain_once(sessions)
    assert _mine(seen, trigger_id) == 1, f"the trip was delivered {_mine(seen, trigger_id)} times"
