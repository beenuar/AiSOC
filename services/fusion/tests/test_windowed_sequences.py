"""Ordered sequences: A then B, by the same entity, inside a window.

A threshold rule cannot express an ordering. "Fifty failed logons" and "a
failed logon followed by a successful one from a new address" are different
detections, and only the second says *compromise* rather than *attempt*. The
counting engine sees each event in isolation and remembers only how many
there were, so every sequence detection in the corpus had nowhere to go.

What ordering means here, precisely, because the loose version is useless:

* stages advance **one event at a time**, so a single event matching two
  stages cannot complete a sequence by itself;
* a stage advances only from an earlier event **by event time**, not by
  arrival order, because a connector polling a vendor delivers a batch whose
  internal order is the vendor's and not the clock's;
* the whole sequence must fit inside one window, measured from the first
  stage, not from the previous one, so a slow drip cannot walk a sequence
  forward indefinitely;
* an out-of-order arrival is tolerated up to a stated bound and is not
  silently treated as in-order.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
from app.services.windowed_detection import SequenceRule, WindowedDetectionEngine
from tests.redis_doubles import FakeRedis


SPRAY_THEN_SUCCESS = SequenceRule(
    id="wd-seq-test-spray-then-success",
    name="Failed logons then a success for the same account",
    severity="high",
    category="identity",
    mitre=["T1110"],
    sequence=(
        {"event_type": "authentication", "outcome": "failure"},
        {"event_type": "authentication", "outcome": "success"},
    ),
    group_by="user",
    window_seconds=600,
)


def _event(tenant: str, outcome: str, when: float, user: str = "alice") -> dict[str, Any]:
    return {
        "tenant_id": tenant,
        "ocsf_event": {
            "tenant_uid": tenant,
            "raw_data": json.dumps({"event_type": "authentication", "outcome": outcome, "user": user, "event_time": when}),
        },
    }


def _engine() -> WindowedDetectionEngine:
    return WindowedDetectionEngine(FakeRedis(), rules=(), sequences=(SPRAY_THEN_SUCCESS,))


@pytest.mark.asyncio
async def test_the_sequence_fires_in_order() -> None:
    engine = _engine()
    tenant = str(uuid4())
    assert not await engine.evaluate(_event(tenant, "failure", 1000.0))
    hits = await engine.evaluate(_event(tenant, "success", 1060.0))
    assert [h.rule_id for h in hits] == [SPRAY_THEN_SUCCESS.id]


@pytest.mark.asyncio
async def test_the_last_stage_alone_does_not_fire() -> None:
    """Otherwise the sequence is just its final stage with extra machinery."""
    engine = _engine()
    tenant = str(uuid4())
    for offset in range(5):
        assert not await engine.evaluate(_event(tenant, "success", 1000.0 + offset))


@pytest.mark.asyncio
async def test_out_of_order_by_event_time_does_not_fire() -> None:
    """The success happened *before* the failure, so nothing was compromised."""
    engine = _engine()
    tenant = str(uuid4())
    assert not await engine.evaluate(_event(tenant, "failure", 2000.0))
    assert not await engine.evaluate(_event(tenant, "success", 1000.0))


@pytest.mark.asyncio
async def test_a_batch_delivered_out_of_arrival_order_still_fires() -> None:
    """A connector polling a vendor delivers the vendor's order, not the clock's.

    The success arrives first and is held; the failure that precedes it by
    event time arrives second. Replaying the later event is what makes this
    work, and without it every vendor that batches would be undetectable.
    """
    engine = _engine()
    tenant = str(uuid4())
    assert not await engine.evaluate(_event(tenant, "success", 1060.0))
    hits = await engine.evaluate(_event(tenant, "failure", 1000.0))
    assert [h.rule_id for h in hits] == [SPRAY_THEN_SUCCESS.id]


@pytest.mark.asyncio
async def test_the_stages_must_fit_inside_one_window() -> None:
    engine = _engine()
    tenant = str(uuid4())
    assert not await engine.evaluate(_event(tenant, "failure", 1000.0))
    assert not await engine.evaluate(_event(tenant, "success", 1000.0 + SPRAY_THEN_SUCCESS.window_seconds + 1))


@pytest.mark.asyncio
async def test_the_entity_must_be_the_same() -> None:
    engine = _engine()
    tenant = str(uuid4())
    assert not await engine.evaluate(_event(tenant, "failure", 1000.0, user="alice"))
    assert not await engine.evaluate(_event(tenant, "success", 1060.0, user="bob"))


@pytest.mark.asyncio
async def test_one_event_cannot_advance_two_stages() -> None:
    """A rule whose stages overlap must still need two events."""
    overlapping = SequenceRule(
        id="wd-seq-test-overlap",
        name="overlap",
        severity="low",
        category="identity",
        mitre=[],
        sequence=({"event_type": "authentication"}, {"event_type": "authentication"}),
        group_by="user",
        window_seconds=600,
    )
    engine = WindowedDetectionEngine(FakeRedis(), rules=(), sequences=(overlapping,))
    tenant = str(uuid4())
    assert not await engine.evaluate(_event(tenant, "failure", 1000.0))
    hits = await engine.evaluate(_event(tenant, "failure", 1001.0))
    assert [h.rule_id for h in hits] == [overlapping.id]


@pytest.mark.asyncio
async def test_it_fires_once_per_window() -> None:
    engine = _engine()
    tenant = str(uuid4())
    await engine.evaluate(_event(tenant, "failure", 1000.0))
    assert await engine.evaluate(_event(tenant, "success", 1060.0))
    assert not await engine.evaluate(_event(tenant, "success", 1120.0))


@pytest.mark.asyncio
async def test_a_three_stage_sequence_needs_all_three_in_order() -> None:
    three = SequenceRule(
        id="wd-seq-test-three",
        name="three",
        severity="high",
        category="identity",
        mitre=[],
        sequence=(
            {"event_type": "authentication", "outcome": "failure"},
            {"event_type": "authentication", "outcome": "success"},
            {"event_type": "authentication", "outcome": "mfa_reset"},
        ),
        group_by="user",
        window_seconds=600,
    )
    engine = WindowedDetectionEngine(FakeRedis(), rules=(), sequences=(three,))
    tenant = str(uuid4())
    assert not await engine.evaluate(_event(tenant, "failure", 1000.0))
    assert not await engine.evaluate(_event(tenant, "mfa_reset", 1010.0))
    assert not await engine.evaluate(_event(tenant, "success", 1020.0))
    hits = await engine.evaluate(_event(tenant, "mfa_reset", 1030.0))
    assert [h.rule_id for h in hits] == [three.id]


@pytest.mark.asyncio
async def test_tenants_do_not_share_sequence_progress() -> None:
    engine = _engine()
    one, two = str(uuid4()), str(uuid4())
    assert not await engine.evaluate(_event(one, "failure", 1000.0))
    assert not await engine.evaluate(_event(two, "success", 1060.0))


@pytest.mark.asyncio
async def test_an_event_with_no_time_falls_back_to_arrival() -> None:
    """A source that stamps nothing must still be able to fire a sequence."""
    engine = _engine()
    tenant = str(uuid4())

    def untimed(outcome: str) -> dict[str, Any]:
        return {
            "tenant_id": tenant,
            "ocsf_event": {
                "tenant_uid": tenant,
                "raw_data": json.dumps({"event_type": "authentication", "outcome": outcome, "user": "alice"}),
            },
        }

    assert not await engine.evaluate(untimed("failure"))
    assert [h.rule_id for h in await engine.evaluate(untimed("success"))] == [SPRAY_THEN_SUCCESS.id]
