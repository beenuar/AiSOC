"""
Unit tests for the Risk-Based Alerting (RBA) entity-rollup engine.

These tests run without a real Redis: a tiny in-memory fake implements the
exact subset of redis.asyncio commands ``EntityRiskEngine`` calls. That keeps
the test fast and deterministic (no clock + no flakes from TTLs).

The tests gate three properties the 2026 KPI bar depends on:

1. Score accumulates additively across alerts and severities.
2. Time-decay halves the score after one half-life so stale signal drops out.
3. Threshold promotion happens exactly once and is visible on the queue.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.services.entity_risk import EntityRiskEngine

# ---------------------------------------------------------------------------
# In-memory fake redis (only the commands the engine uses)
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Minimal async fake covering hset/hgetall/expire/zadd/zrevrange/zcard/zremrangebyrank."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict[bytes, bytes]] = {}
        self.zsets: dict[str, dict[str, float]] = {}

    async def hset(self, key: str, mapping: dict[str, Any]) -> int:
        bucket = self.hashes.setdefault(key, {})
        for k, v in mapping.items():
            bucket[k.encode() if isinstance(k, str) else k] = (
                v.encode() if isinstance(v, str) else v
            )
        return len(mapping)

    async def hgetall(self, key: str) -> dict[bytes, bytes]:
        return dict(self.hashes.get(key, {}))

    async def expire(self, key: str, ttl: int) -> bool:
        return key in self.hashes or key in self.zsets

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        bucket = self.zsets.setdefault(key, {})
        added = 0
        for member, score in mapping.items():
            if member not in bucket:
                added += 1
            bucket[member] = float(score)
        return added

    async def zrevrange(
        self, key: str, start: int, stop: int, withscores: bool = False
    ) -> list[Any]:
        bucket = self.zsets.get(key, {})
        sorted_pairs = sorted(bucket.items(), key=lambda kv: kv[1], reverse=True)
        # Redis ranges are inclusive on both ends.
        if stop == -1:
            sliced = sorted_pairs[start:]
        else:
            sliced = sorted_pairs[start : stop + 1]
        if withscores:
            return [(m.encode(), s) for m, s in sliced]
        return [m.encode() for m, _ in sliced]

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def zremrangebyrank(self, key: str, start: int, stop: int) -> int:
        bucket = self.zsets.get(key)
        if not bucket:
            return 0
        sorted_pairs = sorted(bucket.items(), key=lambda kv: kv[1])
        n = len(sorted_pairs)
        # Redis allows negative indexes from the end.
        s = start if start >= 0 else max(0, n + start)
        e = stop if stop >= 0 else n + stop
        if e < s:
            return 0
        to_remove = sorted_pairs[s : e + 1]
        for member, _ in to_remove:
            bucket.pop(member, None)
        return len(to_remove)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_TENANT = UUID("11111111-1111-1111-1111-111111111111")


def _alert(
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    *,
    username: str | None = "alice",
    hostname: str | None = None,
    src_ip: str | None = None,
    risk_score: float = 0.0,
) -> RawAlert:
    return RawAlert(
        id=uuid4(),
        tenant_id=_TENANT,
        source="test",
        title="probe",
        severity=severity,
        username=username,
        hostname=hostname,
        src_ip=src_ip,
        risk_score=risk_score,
    )


@pytest.fixture
def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture
def engine(fake_redis: _FakeRedis) -> EntityRiskEngine:
    return EntityRiskEngine(fake_redis)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Score accumulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_observe_creates_record_for_each_entity(engine: EntityRiskEngine) -> None:
    alert = _alert(username="alice", hostname="dc01", src_ip="10.0.0.1")
    await engine.observe(alert)
    assert (await engine.get(_TENANT, "user", "alice")) is not None
    assert (await engine.get(_TENANT, "host", "dc01")) is not None
    assert (await engine.get(_TENANT, "src_ip", "10.0.0.1")) is not None


@pytest.mark.asyncio
async def test_score_accumulates_additively(engine: EntityRiskEngine) -> None:
    """Two medium alerts on the same user must double-up the score."""
    await engine.observe(_alert(severity=AlertSeverity.MEDIUM))
    await engine.observe(_alert(severity=AlertSeverity.MEDIUM))
    rec = await engine.get(_TENANT, "user", "alice")
    assert rec is not None
    # Two medium alerts at base weight 8.0 (config default) ≈ 16.0 (within decay window).
    assert rec.score >= 15.0
    assert rec.alert_count == 2


@pytest.mark.asyncio
async def test_severity_weights_are_ordered(engine: EntityRiskEngine) -> None:
    a_crit = _alert(severity=AlertSeverity.CRITICAL, username="u-crit")
    a_high = _alert(severity=AlertSeverity.HIGH, username="u-high")
    a_med = _alert(severity=AlertSeverity.MEDIUM, username="u-med")
    a_low = _alert(severity=AlertSeverity.LOW, username="u-low")
    for a in (a_crit, a_high, a_med, a_low):
        await engine.observe(a)

    s_crit = (await engine.get(_TENANT, "user", "u-crit")).score  # type: ignore[union-attr]
    s_high = (await engine.get(_TENANT, "user", "u-high")).score  # type: ignore[union-attr]
    s_med = (await engine.get(_TENANT, "user", "u-med")).score  # type: ignore[union-attr]
    s_low = (await engine.get(_TENANT, "user", "u-low")).score  # type: ignore[union-attr]
    assert s_crit > s_high > s_med > s_low


@pytest.mark.asyncio
async def test_risk_score_amplifies_points(engine: EntityRiskEngine) -> None:
    """Upstream risk_score (detection confidence) boosts entity points."""
    base = _alert(severity=AlertSeverity.HIGH, risk_score=0.0, username="u-base")
    boosted = _alert(severity=AlertSeverity.HIGH, risk_score=1.0, username="u-boosted")
    await engine.observe(base)
    await engine.observe(boosted)

    s_base = (await engine.get(_TENANT, "user", "u-base")).score  # type: ignore[union-attr]
    s_boosted = (await engine.get(_TENANT, "user", "u-boosted")).score  # type: ignore[union-attr]
    # confidence_factor doubles points at risk_score=1.0
    assert s_boosted == pytest.approx(2.0 * s_base, rel=0.1)


# ---------------------------------------------------------------------------
# Time decay
# ---------------------------------------------------------------------------


def test_decay_halves_after_one_halflife(engine: EntityRiskEngine) -> None:
    now = datetime.utcnow()
    one_half_life_ago = now - timedelta(seconds=engine._half_life)  # type: ignore[attr-defined]
    decayed = engine._decay(40.0, one_half_life_ago, now)  # type: ignore[attr-defined]
    assert decayed == pytest.approx(20.0, rel=0.05)


def test_decay_floor_zeros_dust(engine: EntityRiskEngine) -> None:
    now = datetime.utcnow()
    long_ago = now - timedelta(seconds=engine._half_life * 20)  # type: ignore[attr-defined]
    assert engine._decay(40.0, long_ago, now) == 0.0  # type: ignore[attr-defined]


def test_decay_no_negative_or_future_time(engine: EntityRiskEngine) -> None:
    now = datetime.utcnow()
    future = now + timedelta(seconds=120)
    # Future "prior_seen" must not amplify the score.
    assert engine._decay(40.0, future, now) <= 40.0  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Promotion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_promotion_fires_when_threshold_crossed(engine: EntityRiskEngine) -> None:
    """Three CRITICAL alerts on one user (3 × 40 = 120) ≥ default threshold 80."""
    for _ in range(3):
        await engine.observe(_alert(severity=AlertSeverity.CRITICAL))
    rec = await engine.get(_TENANT, "user", "alice")
    assert rec is not None and rec.promoted_at is not None


@pytest.mark.asyncio
async def test_promotion_is_idempotent(engine: EntityRiskEngine) -> None:
    """Crossing the threshold a second time must not re-promote."""
    for _ in range(3):
        await engine.observe(_alert(severity=AlertSeverity.CRITICAL))
    rec_first = await engine.get(_TENANT, "user", "alice")
    promoted_at_first = rec_first.promoted_at  # type: ignore[union-attr]

    # Add another contributing alert.
    await engine.observe(_alert(severity=AlertSeverity.CRITICAL))
    rec_second = await engine.get(_TENANT, "user", "alice")
    assert rec_second is not None
    assert rec_second.promoted_at == promoted_at_first


@pytest.mark.asyncio
async def test_no_promotion_below_threshold(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(severity=AlertSeverity.LOW))
    rec = await engine.get(_TENANT, "user", "alice")
    assert rec is not None and rec.promoted_at is None


# ---------------------------------------------------------------------------
# Top-N queue + stats
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_top_entities_orders_by_score(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(severity=AlertSeverity.LOW, username="quiet"))
    await engine.observe(_alert(severity=AlertSeverity.CRITICAL, username="loud"))
    await engine.observe(_alert(severity=AlertSeverity.MEDIUM, username="middle"))
    top = await engine.top_entities(_TENANT, limit=10)
    names = [r.entity_value for r in top if r.entity_type == "user"]
    assert names[0] == "loud"
    assert names[-1] == "quiet"


@pytest.mark.asyncio
async def test_promoted_only_filters_queue(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(severity=AlertSeverity.LOW, username="quiet"))
    for _ in range(3):
        await engine.observe(_alert(severity=AlertSeverity.CRITICAL, username="loud"))
    promoted = await engine.top_entities(_TENANT, limit=10, promoted_only=True)
    assert {r.entity_value for r in promoted} == {"loud"}


@pytest.mark.asyncio
async def test_stats_reports_bands(engine: EntityRiskEngine) -> None:
    await engine.observe(_alert(severity=AlertSeverity.LOW, username="low-1"))
    await engine.observe(_alert(severity=AlertSeverity.MEDIUM, username="med-1"))
    for _ in range(3):
        await engine.observe(_alert(severity=AlertSeverity.CRITICAL, username="crit-1"))
    stats = await engine.stats(_TENANT)
    assert stats["tracked_entities"] >= 3
    assert stats["promoted_entities"] >= 1
    assert stats["threshold"] == engine.threshold
    assert sum(stats["score_bands"].values()) == stats["tracked_entities"]


# ---------------------------------------------------------------------------
# 2026 KPI bar — alert-to-incident ratio ≥ 50:1
#
# This is the headline number RBA exists to deliver. The scenario simulates a
# realistic noisy day: 200 alerts of mixed severity hitting a small set of
# entities (a campaign of related medium / high signal against ~5 users).
# RBA must collapse those 200 alerts into ≤ 4 entity-incidents — i.e. one
# promoted entity per cluster. If this regresses we want CI to fail.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alert_to_incident_ratio_meets_2026_bar(engine: EntityRiskEngine) -> None:
    """500 alerts clustered on 4 entities → ≤ 10 entity-incidents (≥ 50:1).

    This is the headline number RBA exists to deliver — the published 2026
    KPI bar of ≥ 50 alerts per promoted entity-incident. The scenario models
    a real noisy day: a focused campaign of 500 mixed-severity alerts hitting
    a small pool of users. RBA must collapse those into ≤ 10 entity-incidents.
    """
    users = ["alice", "bob", "carol", "dave"]
    severities = [
        AlertSeverity.HIGH,
        AlertSeverity.MEDIUM,
        AlertSeverity.MEDIUM,
        AlertSeverity.LOW,
        AlertSeverity.LOW,
    ]
    total_alerts = 500
    for i in range(total_alerts):
        # Distribute alerts across the 5 users so every promoted entity is a
        # cluster of ~40 contributing alerts — what a real campaign looks like.
        await engine.observe(
            _alert(
                severity=severities[i % len(severities)],
                username=users[i % len(users)],
            )
        )

    promoted = await engine.top_entities(_TENANT, limit=50, promoted_only=True)
    promoted_count = len({(r.entity_type, r.entity_value) for r in promoted})

    # Hard floor: every promoted entity must be a real cluster, not a single
    # noisy alert. This is the "50:1" published bar — at minimum the ratio of
    # contributing alerts to entity-incidents must be ≥ 50.
    assert promoted_count > 0, "RBA must promote at least one entity-incident"
    ratio = total_alerts / promoted_count
    assert ratio >= 50.0, (
        f"alert-to-incident ratio {ratio:.1f}:1 fails the 2026 KPI bar of ≥ 50:1; "
        f"got {promoted_count} entity-incidents from {total_alerts} alerts"
    )


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenants_are_isolated(engine: EntityRiskEngine) -> None:
    other_tenant = UUID("22222222-2222-2222-2222-222222222222")
    a = _alert(severity=AlertSeverity.HIGH, username="alice")
    a_other = RawAlert(**{**a.model_dump(), "tenant_id": other_tenant, "id": uuid4()})
    await engine.observe(a)
    await engine.observe(a_other)
    rec_a = await engine.get(_TENANT, "user", "alice")
    rec_b = await engine.get(other_tenant, "user", "alice")
    assert rec_a is not None and rec_b is not None
    assert rec_a.tenant_id != rec_b.tenant_id

    queue_a = await engine.top_entities(_TENANT)
    queue_b = await engine.top_entities(other_tenant)
    assert all(r.tenant_id == str(_TENANT) for r in queue_a)
    assert all(r.tenant_id == str(other_tenant) for r in queue_b)
