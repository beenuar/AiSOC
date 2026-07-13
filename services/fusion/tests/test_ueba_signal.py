"""Phase A4 — UEBA behavioral-model fusion tests.

Proves the per-entity anomaly cache round-trips, the alert-entity mapping,
that a cached behavioral anomaly boosts an alert's confidence + anomaly score
(with the label recomputed), and that everything is fail-soft (no signal / bad
message / Redis error => no boost, no raise).
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from app.models.alert import (
    ConfidenceLabel,
    FusedAlert,
    FusionDecision,
    RawAlert,
)
from app.services.ueba_signal import (
    UebaSignal,
    UebaSignalCache,
    alert_entities,
    apply_ueba_boost,
)

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}
        self.fail = False

    async def set(self, key, value, ex=None):  # noqa: ANN001, ARG002
        if self.fail:
            raise RuntimeError("redis down")
        self.store[key] = value

    async def get(self, key):  # noqa: ANN001
        if self.fail:
            raise RuntimeError("redis down")
        return self.store.get(key)


def _alert(**kw) -> RawAlert:
    base = {
        "tenant_id": TENANT,
        "source": "test",
        "title": "t",
        "username": "alice",
        "hostname": "HOST-1",
        "src_ip": "10.0.0.9",
    }
    base.update(kw)
    return RawAlert(**base)


def _fused(alert: RawAlert, *, score: float = 0.5) -> FusedAlert:
    return FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        incident_id=uuid4(),
        fusion_decision=FusionDecision.NEW_INCIDENT,
        alert=alert,
        confidence_score=score,
        confidence_label=ConfidenceLabel.MEDIUM,
        anomaly_score=0.1,
    )


def _ueba_msg(entity_type="user", entity_id="alice", score=4.7, risk="high") -> dict:
    return {
        "anomaly_id": str(uuid4()),
        "tenant_id": TENANT,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "anomaly_score": score,
        "risk_level": risk,
    }


# ── entity mapping ───────────────────────────────────────────────────────────


async def test_alert_entities_maps_user_device_ip():
    ents = alert_entities(_alert())
    assert ("user", "alice") in ents
    assert ("device", "HOST-1") in ents
    assert ("ip", "10.0.0.9") in ents


# ── cache round-trip ─────────────────────────────────────────────────────────


async def test_record_then_lookup_returns_signal():
    cache = UebaSignalCache(_FakeRedis())
    assert await cache.record(_ueba_msg()) is True
    sig = await cache.lookup(TENANT, [("user", "alice")])
    assert sig is not None
    assert sig.risk_level == "high"
    assert sig.anomaly_score == 4.7


async def test_lookup_returns_highest_risk_across_entities():
    r = _FakeRedis()
    cache = UebaSignalCache(r)
    await cache.record(_ueba_msg(entity_type="user", entity_id="alice", risk="low"))
    await cache.record(_ueba_msg(entity_type="device", entity_id="HOST-1", risk="critical"))
    sig = await cache.lookup(TENANT, [("user", "alice"), ("device", "HOST-1")])
    assert sig.risk_level == "critical"


async def test_record_rejects_incomplete_message():
    cache = UebaSignalCache(_FakeRedis())
    assert await cache.record({"tenant_id": TENANT}) is False


async def test_cache_is_failsoft_on_redis_error():
    r = _FakeRedis()
    r.fail = True
    cache = UebaSignalCache(r)
    assert await cache.record(_ueba_msg()) is False
    assert await cache.lookup(TENANT, [("user", "alice")]) is None


async def test_lookup_miss_returns_none():
    cache = UebaSignalCache(_FakeRedis())
    assert await cache.lookup(TENANT, [("user", "nobody")]) is None


# ── boost ────────────────────────────────────────────────────────────────────


async def test_boost_raises_confidence_and_recomputes_label():
    alert = _alert()
    fused = _fused(alert, score=0.62)  # MEDIUM
    sig = UebaSignal(entity_type="user", entity_id="alice", anomaly_score=8.0, risk_level="high")
    apply_ueba_boost(fused, sig)
    assert fused.confidence_score > 0.62
    assert fused.confidence_label == ConfidenceLabel.HIGH  # 0.62 + 0.14 = 0.76
    assert any(f.factor == "ueba_anomaly" for f in fused.confidence_rationale)
    assert fused.anomaly_score >= 0.75  # high -> normalized 0.75


async def test_boost_raises_anomaly_score_even_at_low_risk():
    alert = _alert()
    fused = _fused(alert, score=0.5)
    sig = UebaSignal(entity_type="ip", entity_id="10.0.0.9", anomaly_score=2.0, risk_level="medium")
    apply_ueba_boost(fused, sig)
    assert fused.anomaly_score >= 0.45


async def test_no_signal_is_noop():
    alert = _alert()
    fused = _fused(alert, score=0.5)
    apply_ueba_boost(fused, None)
    assert fused.confidence_score == 0.5
    assert not any(f.factor == "ueba_anomaly" for f in fused.confidence_rationale)


async def test_message_shape_round_trips_via_json():
    # The consumer deserialises the ueba.anomalies value as JSON; make sure a
    # realistic serialized message records cleanly.
    cache = UebaSignalCache(_FakeRedis())
    msg = json.loads(json.dumps(_ueba_msg(risk="critical")))
    assert await cache.record(msg) is True
    sig = await cache.lookup(TENANT, [("user", "alice")])
    assert sig.risk_level == "critical"
