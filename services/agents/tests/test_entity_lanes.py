"""Triage runs concurrently across entities and in order within one.

Parity 6.9. The property that matters is not "it is faster" — it is that
making it faster did not reorder the alerts whose order is load-bearing.
Two alerts about one host are the ones most likely to be one incident,
and triage reads institutional memory earlier triages of the same entity
wrote, so racing them turns a deterministic verdict into a coin toss.
"""

from __future__ import annotations

import asyncio

import pytest
from app.workers.entity_lane import (
    DEFAULT_MAX_CONCURRENCY,
    MAX_CONCURRENCY_CEILING,
    EntityLanes,
    configured_concurrency,
    entity_of,
)

pytestmark = pytest.mark.asyncio


async def test_alerts_about_one_entity_run_in_arrival_order():
    lanes = EntityLanes(max_concurrency=8)
    order: list[int] = []

    def work(index: int, delay: float):
        async def _run() -> None:
            await asyncio.sleep(delay)
            order.append(index)

        return _run

    # The first is the slowest. Without the lane it would finish last.
    await lanes.submit("WS-014", work(1, 0.05))
    await lanes.submit("WS-014", work(2, 0.01))
    await lanes.submit("WS-014", work(3, 0.0))
    await lanes.drain()

    assert order == [1, 2, 3], f"one entity's alerts were reordered: {order}"


async def test_alerts_about_different_entities_overlap():
    lanes = EntityLanes(max_concurrency=8)
    started: list[str] = []
    release = asyncio.Event()

    def work(name: str):
        async def _run() -> None:
            started.append(name)
            await release.wait()

        return _run

    await lanes.submit("host-a", work("a"))
    await lanes.submit("host-b", work("b"))
    # Let both tasks reach their first await.
    await asyncio.sleep(0.02)
    both_running = sorted(started)
    release.set()
    await lanes.drain()

    assert both_running == ["a", "b"], f"only {started} started; different entities are being serialised"


async def test_concurrency_is_bounded():
    lanes = EntityLanes(max_concurrency=2)
    peak = 0
    current = 0
    release = asyncio.Event()

    def work():
        async def _run() -> None:
            nonlocal peak, current
            current += 1
            peak = max(peak, current)
            await release.wait()
            current -= 1

        return _run

    for i in range(6):
        await lanes.submit(f"host-{i}", work())
    await asyncio.sleep(0.02)
    observed = peak
    release.set()
    await lanes.drain()

    assert observed == 2, f"peak concurrency {observed}; an unbounded fan-out rate-limits the provider"


async def test_a_failing_alert_does_not_take_the_lane_or_the_loop_down():
    lanes = EntityLanes(max_concurrency=4)
    done: list[str] = []

    async def boom() -> None:
        raise RuntimeError("triage blew up")

    async def fine() -> None:
        done.append("second")

    await lanes.submit("WS-014", boom)
    await lanes.submit("WS-014", fine)
    await lanes.drain()

    assert done == ["second"], "a failing alert stopped the entity's lane"


async def test_lanes_do_not_accumulate_for_every_host_ever_seen():
    """A long-running deployment must not hold one lock per host it has
    ever processed."""
    lanes = EntityLanes(max_concurrency=4)

    async def nothing() -> None:
        return None

    for i in range(50):
        await lanes.submit(f"host-{i}", nothing)
    await lanes.drain()

    assert lanes.tracked_entities == 0, f"{lanes.tracked_entities} lanes retained after draining"


async def test_drain_waits_for_everything():
    lanes = EntityLanes(max_concurrency=4)
    finished: list[int] = []

    def work(i: int):
        async def _run() -> None:
            await asyncio.sleep(0.01)
            finished.append(i)

        return _run

    for i in range(10):
        await lanes.submit(f"host-{i % 3}", work(i))
    await lanes.drain()

    assert len(finished) == 10
    assert lanes.in_flight == 0


# ---------------------------------------------------------------------------
# Entity resolution. It has to be the same field fusion correlates on.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("alert", "expected"),
    [
        ({"src_ip": "198.51.100.4", "hostname": "WS-014"}, "198.51.100.4"),
        ({"hostname": "WS-014", "username": "alice"}, "WS-014"),
        ({"username": "alice"}, "alice"),
        ({"entities": [{"value": "evil.example.com"}]}, "evil.example.com"),
    ],
)
async def test_entity_precedence_matches_the_correlation_key(alert, expected):
    assert entity_of(alert) == expected


async def test_an_alert_naming_nobody_gets_its_own_lane():
    # It shares an incident with nothing, so there is no order to
    # preserve — and keying them all together would serialise the lot.
    a = entity_of({"id": "alert-1"})
    b = entity_of({"id": "alert-2"})
    assert a != b
    assert a == "alert:alert-1"


async def test_a_blank_entity_is_not_used():
    assert entity_of({"hostname": "   ", "username": "alice"}) == "alice"


# ---------------------------------------------------------------------------
# Configuration.
# ---------------------------------------------------------------------------


async def test_the_default_applies_when_unset(monkeypatch):
    monkeypatch.delenv("AISOC_TRIAGE_CONCURRENCY", raising=False)
    assert configured_concurrency() == DEFAULT_MAX_CONCURRENCY


@pytest.mark.parametrize("bad", ["lots", "0", "-3", str(MAX_CONCURRENCY_CEILING + 1)])
async def test_an_unusable_override_falls_back_rather_than_clamping_silently(monkeypatch, bad):
    # Silently clamping a typo would leave an operator who asked for 200
    # believing they got it.
    monkeypatch.setenv("AISOC_TRIAGE_CONCURRENCY", bad)
    assert configured_concurrency() == DEFAULT_MAX_CONCURRENCY


async def test_a_valid_override_is_honoured(monkeypatch):
    monkeypatch.setenv("AISOC_TRIAGE_CONCURRENCY", "3")
    assert configured_concurrency() == 3
    assert EntityLanes().limit == 3
