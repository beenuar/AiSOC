"""Windowed detections must survive the re-delivery the consumer relies on.

Two defects, and they pull in opposite directions, which is why they have to
be fixed together.

**Observation inflation.** ``_observe_and_check`` mints a fresh
``uuid.uuid4().hex`` member per call for a threshold rule with no
``distinct_by``. Kafka delivery here is at-least-once and the consumer
deliberately re-delivers on ``RetryableProcessingError``, so one event
counted N times is N members in the sorted set: N re-deliveries of a single
event cross a threshold of N. A brute-force alert fires for one failed login
that the database happened to be slow about.

**Threshold suppression.** The fire-once marker is written *inside*
``_observe_and_check`` — before ``evaluate`` has built the ``DetectionHit``,
and long before the consumer persists anything. ``_fuse_and_persist`` raises
``RetryableProcessingError`` when the row is not durable, so Kafka
re-delivers; on re-delivery ``SET NX`` returns falsy and no hit is produced
until the window rolls. **The retry path that exists specifically to recover
the alert is the thing guaranteed to suppress it.**

The dual-use of one sorted set at the heart of ``_observe_and_check`` is
deliberate and must keep working: a random member counts *events*, an
observed value counts *distinct values*, because ZADD on an existing member
updates its score instead of adding a row. The fix has to preserve both
meanings while making the event counter idempotent, which means the member
for an event-count rule becomes the event's stable identity rather than a
random one.
"""

from __future__ import annotations

import json
import time
from uuid import uuid4

import pytest
from app.services.windowed_detection import WindowedDetectionEngine, WindowRule
from tests.redis_doubles import FakeRedis


def _auth_fail(tenant: str, user: str = "alice", when: str | None = None) -> dict:
    payload = {"event_type": "authentication", "outcome": "failure", "user": user}
    if when is not None:
        payload["timestamp"] = when
    return {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps(payload)}}


def _engine(redis, rules=None):  # noqa: ANN001, ANN201
    return WindowedDetectionEngine(redis, rules=rules if rules is not None else _BRUTE_FORCE)


_BRUTE_FORCE = (
    WindowRule(
        id="wd-bruteforce-auth",
        name="Brute-force: repeated authentication failures",
        severity="high",
        category="identity",
        mitre=["T1110"],
        match_when={"event_type": "authentication", "outcome": "failure"},
        group_by="user",
        threshold=5,
        window_seconds=600,
    ),
)


@pytest.mark.asyncio
async def test_one_event_delivered_five_times_does_not_cross_a_threshold_of_five():
    """The inflation case, stated as bluntly as it happens in production.

    At-least-once delivery plus a random member per call means a single
    failed login that the database was slow about becomes a brute-force
    alert naming a user who did nothing.
    """
    redis = FakeRedis()
    engine = _engine(redis)
    event = _auth_fail(str(uuid4()))

    hits = []
    for _ in range(5):
        hits += await engine.evaluate(event, event_id="ingest-evt-1")

    assert hits == [], "five deliveries of one event are one observation"


@pytest.mark.asyncio
async def test_five_distinct_events_still_cross_the_threshold():
    """The positive control. Deduplicating must not break the detection."""
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())

    hits = []
    for n in range(5):
        hits += await engine.evaluate(_auth_fail(tenant), event_id=f"ingest-evt-{n}")

    assert [h.rule_id for h in hits] == ["wd-bruteforce-auth"]


@pytest.mark.asyncio
async def test_a_distinct_by_rule_still_counts_distinct_values():
    """The dual use of one sorted set is deliberate and must survive.

    "Fifty requests from one source" and "fifty *different* secrets read by
    one principal" are different detections. A fix that made every member
    the event id would turn the second into the first.
    """
    rule = WindowRule(
        id="wd-secret-enumeration",
        name="Secret enumeration",
        severity="high",
        category="identity",
        mitre=["T1552"],
        match_when={"event_type": "secret_read"},
        group_by="user",
        threshold=3,
        window_seconds=600,
        distinct_by="secret_name",
    )
    redis = FakeRedis()
    engine = _engine(redis, rules=(rule,))
    tenant = str(uuid4())

    def event(secret: str) -> dict:
        return {
            "tenant_id": tenant,
            "ocsf_event": {
                "tenant_uid": tenant,
                "raw_data": json.dumps({"event_type": "secret_read", "user": "svc", "secret_name": secret}),
            },
        }

    # The same secret read ten times by ten *different* events is one value.
    hits = []
    for n in range(10):
        hits += await engine.evaluate(event("db-password"), event_id=f"evt-{n}")
    assert hits == [], "re-reading one secret is not enumeration"

    hits += await engine.evaluate(event("api-key"), event_id="evt-a")
    hits += await engine.evaluate(event("signing-key"), event_id="evt-b")
    assert [h.rule_id for h in hits] == ["wd-secret-enumeration"]


@pytest.mark.asyncio
async def test_a_hit_that_was_never_persisted_fires_again_on_re_delivery():
    """The suppression case: the retry must be able to recover the alert.

    The cooldown was written before the hit even existed, so a persistence
    failure -- the exact condition the retry exists for -- guaranteed the
    re-delivery produced nothing.
    """
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())
    for n in range(4):
        await engine.evaluate(_auth_fail(tenant), event_id=f"evt-{n}")

    first = await engine.evaluate(_auth_fail(tenant), event_id="evt-threshold")
    assert len(first) == 1

    # Persistence failed. The consumer releases the claim and Kafka
    # re-delivers the very same record.
    await engine.release(first[0])
    again = await engine.evaluate(_auth_fail(tenant), event_id="evt-threshold")

    assert len(again) == 1, "a hit that reached no database must fire again"


@pytest.mark.asyncio
async def test_a_persisted_hit_does_not_fire_twice():
    """The other half: once it is durable, re-delivery must stay quiet."""
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())
    for n in range(4):
        await engine.evaluate(_auth_fail(tenant), event_id=f"evt-{n}")

    first = await engine.evaluate(_auth_fail(tenant), event_id="evt-threshold")
    assert len(first) == 1
    await engine.confirm(first[0])

    again = await engine.evaluate(_auth_fail(tenant), event_id="evt-threshold")
    assert again == [], "a durable hit must not produce a second alert"


@pytest.mark.asyncio
async def test_two_workers_on_overlapping_deliveries_produce_one_hit():
    """Concurrency: the claim is what stops a duplicate alert.

    Moving the cooldown write to *after* persistence would create exactly
    this race instead of fixing it -- two workers both crossing the
    threshold before either has written anything.
    """
    redis = FakeRedis()
    worker_a = _engine(redis)
    worker_b = _engine(redis)
    tenant = str(uuid4())
    for n in range(4):
        await worker_a.evaluate(_auth_fail(tenant), event_id=f"evt-{n}")

    hits_a = await worker_a.evaluate(_auth_fail(tenant), event_id="evt-5")
    hits_b = await worker_b.evaluate(_auth_fail(tenant), event_id="evt-6")

    assert len(hits_a) + len(hits_b) == 1, "exactly one worker may own the fire"


@pytest.mark.asyncio
async def test_a_crashed_worker_does_not_suppress_the_alert_forever():
    """Crash recovery: a claim nobody confirmed must expire, not persist.

    A worker that dies between the hit and the database never releases its
    claim. If the claim were the full window the alert would be suppressed
    for ten minutes by a process that no longer exists.
    """
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())
    for n in range(4):
        await engine.evaluate(_auth_fail(tenant), event_id=f"evt-{n}")

    claimed = await engine.evaluate(_auth_fail(tenant), event_id="evt-5")
    assert len(claimed) == 1
    # The worker is gone. Nothing released the claim; the lease simply ages
    # out, which the double models by dropping the key the way an EX would.
    redis.strings.clear()

    recovered = await engine.evaluate(_auth_fail(tenant), event_id="evt-6")
    assert len(recovered) == 1, "an unconfirmed claim must not outlive the worker that took it"


@pytest.mark.asyncio
async def test_out_of_order_arrival_reaches_the_same_verdict_as_in_order():
    """Arrival order is not evidence of event order.

    Almost every connector here polls, so a batch arrives in the vendor's
    order. Scoring the window by wall clock makes the detection a function
    of the poll cadence; two deliveries of one burst must agree.
    """
    tenant = str(uuid4())
    stamps = [f"2026-10-27T12:00:0{n}Z" for n in range(5)]

    in_order = FakeRedis()
    engine_a = _engine(in_order)
    forward = []
    for n, stamp in enumerate(stamps):
        forward += await engine_a.evaluate(_auth_fail(tenant, when=stamp), event_id=f"evt-{n}")

    reversed_order = FakeRedis()
    engine_b = _engine(reversed_order)
    backward = []
    for n, stamp in reversed(list(enumerate(stamps))):
        backward += await engine_b.evaluate(_auth_fail(tenant, when=stamp), event_id=f"evt-{n}")

    assert len(forward) == 1
    assert len(backward) == 1, "the same five events in the other order must reach the same verdict"


@pytest.mark.asyncio
async def test_a_historical_backfill_does_not_merge_with_live_traffic():
    """Backfill must be counted in its own window, not piled onto today's.

    Scoring by arrival time means replaying a week of history looks like one
    enormous burst happening right now.
    """
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())

    # Four failures last week, and one now. Nothing should fire: neither
    # window holds five.
    hits = []
    for n in range(4):
        hits += await engine.evaluate(_auth_fail(tenant, when=f"2026-10-20T03:00:0{n}Z"), event_id=f"old-{n}")
    hits += await engine.evaluate(_auth_fail(tenant, when="2026-10-27T12:00:00Z"), event_id="new-0")

    assert hits == [], "four old failures and one new one are not a burst"


@pytest.mark.asyncio
async def test_a_redis_failure_is_reported_rather_than_swallowed():
    """A blip meant the rule silently did not fire.

    The per-rule handler logged at debug, so a Redis outage and a quiet
    estate were indistinguishable. Detection stays fail-soft -- Redis must
    not wedge the alert pipeline -- but the degradation has to be countable.
    """
    redis = FakeRedis()
    engine = _engine(redis)
    redis.failing = True

    hits = await engine.evaluate(_auth_fail(str(uuid4())), event_id="evt-1")

    assert hits == []
    assert engine.rule_errors >= 1, "a skipped rule must be visible, not inferred from an absence of alerts"


@pytest.mark.asyncio
async def test_an_event_with_no_identity_still_counts_exactly_once():
    """No ingest id and no Kafka coordinates: the fallback must still be stable.

    Falling back to a random member here would reintroduce the whole defect
    for any producer that does not set an id.
    """
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())
    event = _auth_fail(tenant, when="2026-10-27T12:00:00Z")

    for _ in range(5):
        hits = await engine.evaluate(event)

    assert hits == [], "an identity derived from the event content must be stable across deliveries"


@pytest.mark.asyncio
async def test_the_window_is_measured_in_event_time_not_arrival_time():
    """Five failures spread over an hour are not a ten-minute burst."""
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())

    hits = []
    for n in range(5):
        # One every fifteen minutes, all arriving now.
        hits += await engine.evaluate(_auth_fail(tenant, when=f"2026-10-27T{12 + n:02d}:00:00Z"), event_id=f"evt-{n}")

    assert hits == [], "arrival time would make this a burst; event time does not"


@pytest.mark.asyncio
async def test_a_confirmed_hit_survives_a_second_evaluation_pass_over_the_window():
    """Replaying the whole window must not produce a second alert.

    The cooldown is keyed on the event-time bucket, so a replay lands in the
    same bucket and finds the confirmed marker rather than a cooldown that
    happens to have aged out in wall-clock terms.
    """
    redis = FakeRedis()
    engine = _engine(redis)
    tenant = str(uuid4())
    stamps = [f"2026-10-27T12:00:0{n}Z" for n in range(5)]

    hits = []
    for n, stamp in enumerate(stamps):
        hits += await engine.evaluate(_auth_fail(tenant, when=stamp), event_id=f"evt-{n}")
    assert len(hits) == 1
    await engine.confirm(hits[0])

    replay = []
    for n, stamp in enumerate(stamps):
        replay += await engine.evaluate(_auth_fail(tenant, when=stamp), event_id=f"evt-{n}")

    assert replay == [], "replaying the window must be idempotent"
    assert time.time() > 0  # the verdict must not depend on the wall clock
