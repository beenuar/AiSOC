"""Redis is a cache, not the alert store. An outage must degrade, not raise.

The failure being pinned: ``Deduplicator.is_duplicate`` and
``Correlator.correlate`` let ``RedisError`` escape into the fusion engine.
Depending on the caller that either wedged the partition or was swallowed and
its offset committed — with Postgres, the actual source of truth, never
consulted. Both now fail open, and the degradation is counted so it is visible
rather than inferred.
"""

from __future__ import annotations

import pytest
from app.models.alert import AlertSeverity, FusionDecision, RawAlert
from app.services.correlator import Correlator
from app.services.deduplicator import Deduplicator
from app.services.fusion_engine import FusionEngine
from redis.exceptions import ConnectionError as RedisConnectionError


class _DownRedis:
    async def get(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise RedisConnectionError("redis is down")

    async def set(self, *_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise RedisConnectionError("redis is down")


class _HealingRedis:
    def __init__(self) -> None:
        self.down = True
        self.values: dict[str, bytes] = {}

    async def get(self, key):  # noqa: ANN001, ANN202
        if self.down:
            raise RedisConnectionError("redis is down")
        return self.values.get(key)

    async def set(self, key, value, **_k):  # noqa: ANN001, ANN003, ANN202
        if self.down:
            raise RedisConnectionError("redis is down")
        self.values[key] = str(value).encode()
        return True


def _alert() -> RawAlert:
    return RawAlert(
        tenant_id="00000000-0000-0000-0000-000000000001",
        source="CrowdStrike Falcon",
        title="Suspicious PowerShell",
        severity=AlertSeverity.HIGH,
        src_ip="10.20.30.40",
        hostname="WIN-DC01",
        mitre_tactics=["Execution"],
    )


@pytest.mark.asyncio
async def test_dedup_fails_open_when_redis_is_down():
    dedup = Deduplicator(_DownRedis())
    is_dup, original = await dedup.is_duplicate(_alert())
    assert (is_dup, original) == (False, None)
    # The write path must not raise either; the DB guard still suppresses the row.
    await dedup.register(_alert())
    metrics = dedup.metrics()
    assert metrics["degraded"] is True
    assert metrics["read_fallbacks"] == 1
    assert metrics["write_fallbacks"] == 1


@pytest.mark.asyncio
async def test_dedup_reports_recovery_after_redis_returns():
    redis = _HealingRedis()
    dedup = Deduplicator(redis)
    assert await dedup.is_duplicate(_alert()) == (False, None)
    assert dedup.metrics()["degraded"] is True

    redis.down = False
    await dedup.register(_alert())
    assert dedup.metrics()["degraded"] is False
    is_dup, original = await dedup.is_duplicate(_alert())
    assert is_dup is True
    assert original is not None


@pytest.mark.asyncio
async def test_correlation_returns_a_single_alert_incident_when_redis_is_down():
    correlator = Correlator(_DownRedis())
    alert = _alert()
    alert.id = alert.deterministic_id()

    correlated, incident = await correlator.correlate(alert)
    assert correlated is False
    assert incident.alert_count == 1
    assert incident.alert_ids == [str(alert.id)]
    assert incident.tenant_id == alert.tenant_id
    assert correlator.metrics()["degraded"] is True
    assert correlator.metrics()["fallbacks"] == 1


class _CorruptRedis:
    """Redis answers, but with bytes no incident can be parsed from."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def get(self, _key):  # noqa: ANN001, ANN202
        return self.payload

    async def set(self, _key, _value, **_k):  # noqa: ANN001, ANN003, ANN202
        return True


@pytest.mark.asyncio
async def test_dedup_treats_a_corrupt_value_as_a_cache_miss():
    """An undecodable dedup value must not raise into the engine.

    Failing open is safe: Postgres still owns uniqueness, so the worst case is
    a downstream duplicate decision rather than a lost alert.
    """
    dedup = Deduplicator(_CorruptRedis(b"\xff\xfe"))
    is_dup, original = await dedup.is_duplicate(_alert())
    assert (is_dup, original) == (False, None)


@pytest.mark.asyncio
async def test_a_non_uuid_duplicate_reference_does_not_fail_the_alert():
    """A decodable but non-UUID dedup value is still cache data.

    The duplicate verdict stands; only the back-reference is dropped, rather
    than raising ``ValueError`` from the engine and dead-lettering a good alert.
    """

    class _DupDedup:
        async def is_duplicate(self, _alert):  # noqa: ANN001, ANN202
            return True, "not-a-uuid"

        async def register(self, _alert):  # noqa: ANN001, ANN202
            return None

    class _UnusedCorrelator:
        async def correlate(self, _alert):  # noqa: ANN001, ANN202
            raise AssertionError("a duplicate must not reach correlation")

    engine = FusionEngine(_DupDedup(), _UnusedCorrelator())
    fused = await engine.process(_alert())

    assert fused.fusion_decision is FusionDecision.DUPLICATE
    assert fused.duplicate_of is None


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [b"not-json{", b"\xff\xfe"])
async def test_correlation_treats_a_corrupt_payload_as_a_cache_miss(payload):
    """Redis is a cache. A truncated or undecodable entry must not dead-letter
    an otherwise valid alert: it reads as "no existing incident"."""
    correlator = Correlator(_CorruptRedis(payload))
    alert = _alert()
    alert.id = alert.deterministic_id()

    correlated, incident = await correlator.correlate(alert)
    assert correlated is False
    assert incident.alert_count == 1
    assert incident.alert_ids == [str(alert.id)]
    assert correlator.metrics()["degraded"] is False


@pytest.mark.asyncio
async def test_correlation_reports_recovery_after_redis_returns():
    redis = _HealingRedis()
    correlator = Correlator(redis)
    await correlator.correlate(_alert())
    assert correlator.metrics()["degraded"] is True

    redis.down = False
    correlated, incident = await correlator.correlate(_alert())
    assert correlated is False
    assert incident.alert_count == 1
    assert correlator.metrics()["degraded"] is False
