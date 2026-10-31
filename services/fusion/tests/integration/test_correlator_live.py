"""The real Correlator against a real Redis: windows, tenants, restarts, races.

Every other correlation test drives the grouping *decision* —
`correlation_key()` plus a window — or a FakeRedis double. None of them can
answer the questions this file exists for, because each one is a property of
the server and the storage layer the doubles replace: does the window
actually expire, does a replacement worker keep correlating into the open
incident, can two concurrent creators split one logical incident in half.

The concurrency test is the reason this file exists. The pre-fix creation
path was GET (miss) → SET for every worker: the last SET owned the index and
every other worker's incident became an unreachable orphan carrying a real
alert — an alert that vanished from incident lineage while both callers were
told everything worked. A single-threaded double passes that sequence by
construction, which is exactly the more-capable-than-reality shape this
repository keeps finding.

Skips cleanly when no server is reachable, and says so rather than passing
quietly.

    docker run -d --name feedback-redis -p 63790:6379 redis:7-alpine
    AISOC_TEST_REDIS=redis://127.0.0.1:63790/0 pytest tests/integration/test_correlator_live.py
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio

from app.models.alert import AlertSeverity, RawAlert
from app.services.correlator import _CORRELATION_PREFIX, Correlator

URL = os.getenv("AISOC_TEST_REDIS", "").strip()
pytestmark = pytest.mark.skipif(not URL, reason="set AISOC_TEST_REDIS=redis://host:port/db to run the live correlator proof")

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")


@pytest_asyncio.fixture
async def redis():  # noqa: ANN201
    aioredis = pytest.importorskip("redis.asyncio")
    client = aioredis.from_url(URL)
    await client.flushdb()
    yield client
    await client.aclose()


def _alert(
    *,
    tenant: uuid.UUID = TENANT_A,
    host: str | None = None,
    tactic: str | None = None,
    rule: str | None = None,
    title: str = "live test alert",
) -> RawAlert:
    return RawAlert(
        tenant_id=tenant,
        source="live-test",
        title=title,
        hostname=host,
        severity=AlertSeverity.MEDIUM,
        mitre_tactics=[tactic] if tactic else [],
        rule_id=rule,
    )


def _correlator(redis, *, window: int = 3600) -> Correlator:  # noqa: ANN001
    correlator = Correlator(redis)
    # The window is read from settings at construction; the live suite needs
    # a short one for the expiry proof and sets it on the instance it built
    # rather than mutating process settings under every other test.
    correlator._window = window
    return correlator


@pytest.mark.asyncio
async def test_same_key_within_window_joins_one_incident(redis) -> None:  # noqa: ANN001
    correlator = _correlator(redis)
    host = f"ws-{uuid.uuid4().hex[:8]}"

    first_correlated, first = await correlator.correlate(_alert(host=host, tactic="execution"))
    second_correlated, second = await correlator.correlate(_alert(host=host, tactic="execution"))

    assert not first_correlated
    assert second_correlated
    assert second.id == first.id
    assert second.alert_count == 2


@pytest.mark.asyncio
async def test_tenant_boundary_separates_identical_entities(redis) -> None:  # noqa: ANN001
    """Two tenants, same entity and tactic: never one incident."""
    correlator = _correlator(redis)
    host = f"ws-{uuid.uuid4().hex[:8]}"

    _, incident_a = await correlator.correlate(_alert(tenant=TENANT_A, host=host, tactic="execution"))
    correlated_b, incident_b = await correlator.correlate(_alert(tenant=TENANT_B, host=host, tactic="execution"))

    assert not correlated_b, "a second tenant's identical alert must open its own incident"
    assert incident_b.id != incident_a.id
    assert incident_b.tenant_id == TENANT_B


@pytest.mark.asyncio
async def test_window_expiry_opens_a_new_incident(redis) -> None:  # noqa: ANN001
    """A late event lands in a new incident once the window has expired."""
    correlator = _correlator(redis, window=1)
    host = f"ws-{uuid.uuid4().hex[:8]}"

    _, first = await correlator.correlate(_alert(host=host, tactic="execution"))
    await asyncio.sleep(1.2)
    correlated, second = await correlator.correlate(_alert(host=host, tactic="execution"))

    assert not correlated, "the window expired; a new incident opens rather than a stale one growing forever"
    assert second.id != first.id


@pytest.mark.asyncio
async def test_restart_keeps_correlating_into_the_open_incident(redis) -> None:  # noqa: ANN001
    """Correlation state lives in Redis, not the process: a replacement worker joins the same incident."""
    host = f"ws-{uuid.uuid4().hex[:8]}"

    _, first = await _correlator(redis).correlate(_alert(host=host, tactic="execution"))
    # A fresh Correlator stands in for the restarted replica.
    correlated, second = await _correlator(redis).correlate(_alert(host=host, tactic="execution"))

    assert correlated
    assert second.id == first.id


@pytest.mark.asyncio
async def test_detection_shaped_alerts_group_per_rule_in_the_real_store(redis) -> None:  # noqa: ANN001
    """The conservative fallback holds through the production path, not only the key.

    Three tactic-less detection alerts on one entity: two of one rule join
    one incident, the third rule opens its own. Before the fallback all
    three shared `{tenant}:{entity}:unknown`.
    """
    correlator = _correlator(redis)
    host = f"ws-{uuid.uuid4().hex[:8]}"

    _, storm = await correlator.correlate(_alert(host=host, rule="r-1", title="storm 1"))
    joined, storm_2 = await correlator.correlate(_alert(host=host, rule="r-1", title="storm 2"))
    other_correlated, other = await correlator.correlate(_alert(host=host, rule="r-2", title="different rule"))

    assert joined and storm_2.id == storm.id
    assert not other_correlated, "a different rule on the same entity is not known to be one incident"
    assert other.id != storm.id


@pytest.mark.asyncio
async def test_concurrent_creators_converge_on_one_incident(redis) -> None:  # noqa: ANN001
    """N concurrent first-arrivals for one key cannot split the incident.

    With `SET NX` exactly one creator wins the index and the losers merge
    into the winner, so every caller is told the same incident id and no
    alert lands in an unreachable orphan.

    What this deliberately does NOT assert: `alert_count == N`. Concurrent
    *merges* into one incident are still read-modify-write and can lose
    increments to each other; that narrower window is a known limit, named
    here and in the correlator, and closing it takes an owner-checked
    script like the windowed engine's. The property that must hold — the
    one the fix is for — is that no caller is handed a divergent incident.
    """
    correlator = _correlator(redis)
    host = f"ws-{uuid.uuid4().hex[:8]}"
    alerts = [_alert(host=host, tactic="execution", title=f"racer {i}") for i in range(10)]

    results = await asyncio.gather(*(correlator.correlate(a) for a in alerts))

    incident_ids = {str(incident.id) for _, incident in results}
    assert len(incident_ids) == 1, f"concurrent creators split one logical incident into {len(incident_ids)}"

    index_keys = [key async for key in redis.scan_iter(match=f"{_CORRELATION_PREFIX}*{host}*")]
    assert len(index_keys) == 1
    indexed = await redis.get(index_keys[0])
    assert (indexed.decode() if isinstance(indexed, bytes) else str(indexed)) in incident_ids

    # At least one merge landed beside the winner's own alert; the exact
    # count under racing merges is the documented limit above.
    winner_id = next(iter(incident_ids))
    reloaded = await correlator._load_incident(winner_id)
    assert reloaded is not None and reloaded.alert_count >= 2
