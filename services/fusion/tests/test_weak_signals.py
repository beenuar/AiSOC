"""Item 2.3: several weak signals become one finding; one never does.

The invariant the plan states — *one geography or ASN change alone never
is* a finding — is held here rather than left to whoever edits the weight
table next.
"""

from __future__ import annotations

import time

import pytest

from app.services.weak_signals import (
    MIN_DISTINCT_KINDS,
    SIGNAL_WEIGHTS,
    STRENGTH_THRESHOLD,
    WeakSignal,
    WeakSignalAggregator,
    extract_signals,
)


class FakeRedis:
    """A sorted set with scores, which is the surface the aggregator uses."""

    def __init__(self) -> None:
        self.z: dict[str, dict[str, float]] = {}
        self.unreachable = False

    def _guard(self) -> None:
        if self.unreachable:
            raise ConnectionError("redis down")

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        self._guard()
        self.z.setdefault(key, {}).update(mapping)
        return len(mapping)

    async def zremrangebyscore(self, key: str, low: float, high: float) -> int:
        self._guard()
        members = self.z.get(key, {})
        stale = [m for m, score in members.items() if low <= score <= high]
        for member in stale:
            del members[member]
        return len(stale)

    async def zrange(self, key: str, start: int, stop: int) -> list[str]:
        self._guard()
        ordered = sorted(self.z.get(key, {}).items(), key=lambda kv: kv[1])
        return [m for m, _ in ordered]

    async def expire(self, key: str, ttl: int) -> bool:
        self._guard()
        return True

    async def delete(self, key: str) -> int:
        self._guard()
        return int(bool(self.z.pop(key, None)))


def test_no_single_signal_can_fire() -> None:
    """The plan's invariant, as a property of the weight table.

    Asserted against every weight rather than the two the plan names, so a
    future signal added above the threshold fails here instead of shipping
    a one-event alert under a name that promises aggregation.
    """
    for kind, weight in SIGNAL_WEIGHTS.items():
        assert weight < STRENGTH_THRESHOLD, f"{kind} alone would clear the threshold"


@pytest.mark.asyncio
async def test_one_signal_returns_nothing() -> None:
    aggregator = WeakSignalAggregator(FakeRedis())
    finding = await aggregator.accumulate("t1", "session", "s1", [WeakSignal("new_asn", "64496", time.time())])
    assert finding is None


@pytest.mark.asyncio
async def test_several_kinds_on_one_session_become_one_finding() -> None:
    aggregator = WeakSignalAggregator(FakeRedis())
    now = time.time()
    assert await aggregator.accumulate("t1", "session", "s1", [WeakSignal("new_asn", "64496", now)], now=now) is None
    assert await aggregator.accumulate("t1", "session", "s1", [WeakSignal("new_country", "RU", now + 1)], now=now + 1) is None
    finding = await aggregator.accumulate("t1", "session", "s1", [WeakSignal("idp_risk_event", "high", now + 2)], now=now + 2)

    assert finding is not None
    assert finding.strength >= STRENGTH_THRESHOLD
    assert [s.kind for s in finding.signals] == ["new_asn", "new_country", "idp_risk_event"]
    # Severity from the strongest contributor; confidence is its own number.
    assert finding.severity == "high"
    assert 0 <= finding.confidence <= 100


@pytest.mark.asyncio
async def test_one_kind_repeated_cannot_fire() -> None:
    """A noisy integration must not outscore a genuine sequence."""
    aggregator = WeakSignalAggregator(FakeRedis())
    now = time.time()
    finding = None
    for index in range(40):
        finding = await aggregator.accumulate(
            "t1", "session", "s1", [WeakSignal("idp_risk_event", f"evt-{index}", now + index)], now=now + index
        )
    assert finding is None, "repeats of one kind cleared the threshold"
    assert MIN_DISTINCT_KINDS >= 2


@pytest.mark.asyncio
async def test_the_refused_ordered_pair_lands_here() -> None:
    """Item 2.1 refused 'recovery changed then password' as a single rule.

    The windowed engine counts and does not order. This is where the case
    goes instead, and the finding lists both halves in the order they
    arrived so an analyst sees the sequence the rule could not express.
    """
    aggregator = WeakSignalAggregator(FakeRedis())
    now = time.time()
    recovery = {"event_type": "workspace.login.recovery_email_edit", "actor_email": "victim@example.com", "session_id": "s9"}
    password = {"event_type": "workspace.login.password_edit", "actor_email": "victim@example.com", "session_id": "s9", "ip_class": "tor_exit"}

    assert await aggregator.observe("t1", recovery, now=now) == []
    findings = await aggregator.observe("t1", password, now=now + 60)

    assert findings, "the pair did not accumulate into a finding"
    kinds = [s.kind for s in findings[0].signals]
    assert "credential_change" in kinds
    assert "anonymizer_egress" in kinds
    assert findings[0].signals[0].at <= findings[0].signals[-1].at


@pytest.mark.asyncio
async def test_unreachable_store_returns_no_finding() -> None:
    redis = FakeRedis()
    aggregator = WeakSignalAggregator(redis)
    redis.unreachable = True
    assert await aggregator.accumulate("t1", "session", "s1", [WeakSignal("new_asn", "x", time.time())]) is None


def test_extractor_reads_only_fields_something_publishes() -> None:
    """A weight that can never be added is worse than an absent signal.

    The threshold was calibrated as though every kind could contribute, so
    a kind with no publisher would make the calibration describe a
    different mechanism than the one that runs.
    """
    event = {
        "first_seen_asn_for_principal": True,
        "src_asn": 64496,
        "ip_class": "vpn",
        "baseline_principal_volume_z": 4.2,
        "risk_state": "atRisk",
        "event_type": "workspace.login.2sv_disable",
    }
    kinds = {s.kind for s in extract_signals(event, now=0.0)}
    assert kinds == {"new_asn", "anonymizer_egress", "sub_principal_deviation", "idp_risk_event", "mfa_weakened"}
    assert kinds <= set(SIGNAL_WEIGHTS)


def test_confidence_is_independent_of_severity() -> None:
    """Two findings of equal severity must be able to differ in confidence."""
    from app.services.weak_signals import _confidence_of

    assert _confidence_of(STRENGTH_THRESHOLD, 2) < _confidence_of(STRENGTH_THRESHOLD * 2, 4)
