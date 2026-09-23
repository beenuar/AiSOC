"""Wave 2 — stateful/windowed detection fires when a threshold is crossed in a
sliding window, and only once per window."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from app.services.windowed_detection import WindowedDetectionEngine, WindowRule


class _FakeRedis:
    """Minimal in-memory Redis for the sorted-set window + fired marker."""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.strings: dict[str, str] = {}

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, min_s: float, max_s: float) -> None:
        z = self.zsets.get(key, {})
        for m in [m for m, s in list(z.items()) if min_s <= s <= max_s]:
            del z[m]

    async def expire(self, key: str, ttl: int) -> None:
        return None

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None):
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True


def _auth_fail_event(tenant: str, user: str = "alice", src: str = "1.2.3.4") -> dict:
    return {
        "tenant_id": tenant,
        "ocsf_event": {
            "tenant_uid": tenant,
            "raw_data": json.dumps({"event_type": "authentication", "outcome": "failure", "user": user, "src_ip": src}),
        },
    }


@pytest.mark.asyncio
async def test_bruteforce_fires_at_threshold_once():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())

    # First 4 failures: below the threshold of 5 -> no brute-force hit.
    for i in range(4):
        hits = await eng.evaluate(_auth_fail_event(tenant))
        assert not any(h.rule_id == "wd-bruteforce-auth" for h in hits), f"fired early on attempt {i + 1}"

    # 5th crosses the threshold.
    hits = await eng.evaluate(_auth_fail_event(tenant))
    assert any(h.rule_id == "wd-bruteforce-auth" for h in hits)

    # 6th within the same window must NOT re-fire (fired-marker suppresses).
    hits6 = await eng.evaluate(_auth_fail_event(tenant))
    assert not any(h.rule_id == "wd-bruteforce-auth" for h in hits6)


@pytest.mark.asyncio
async def test_group_by_isolates_entities():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    # 4 failures for alice + 4 for bob: neither user reaches the per-user threshold.
    for _ in range(4):
        await eng.evaluate(_auth_fail_event(tenant, user="alice"))
    for _ in range(4):
        hits = await eng.evaluate(_auth_fail_event(tenant, user="bob"))
    assert not any(h.rule_id == "wd-bruteforce-auth" for h in hits)


@pytest.mark.asyncio
async def test_non_matching_event_never_fires():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    benign = {"tenant_id": tenant, "ocsf_event": {"raw_data": json.dumps({"event_type": "process", "user": "alice"})}}
    for _ in range(20):
        hits = await eng.evaluate(benign)
    assert hits == []


@pytest.mark.asyncio
async def test_build_alert_from_hit():
    eng = WindowedDetectionEngine(_FakeRedis())
    tenant = str(uuid4())
    hit = None
    for _ in range(5):
        for h in await eng.evaluate(_auth_fail_event(tenant)):
            hit = h
    assert hit is not None
    alert = eng.build_alert(_auth_fail_event(tenant), hit)
    assert alert is not None
    assert alert.source == "detection:wd-bruteforce-auth"
    assert alert.username == "alice"


# ── distinct counting ────────────────────────────────────────────────────────
#
# "Fifty reads by one principal" is a script retrying. "Fifty *different*
# secrets read by one principal" is a vault being walked. Counting events
# cannot tell those apart, and 21 of the rules the reachability gate lists as
# needing a windowed evaluator name a `distinct_*` field — so without this
# they had nowhere to go even after the engine existed.


_TENANT = str(uuid4())


def _secret_event(user: str, secret: str) -> dict:
    return {
        "tenant_id": _TENANT,
        "ocsf_event": {
            "raw_event": {"event_type": "secret_access", "user": user, "secret_name": secret},
        },
    }


DISTINCT_RULE = WindowRule(
    id="wd-test-distinct",
    name="Many distinct secrets by one principal",
    severity="high",
    category="identity",
    mitre=["T1552.007"],
    match_when={"event_type": "secret_access"},
    group_by="user",
    distinct_by="secret_name",
    threshold=3,
    window_seconds=300,
)


@pytest.mark.asyncio
async def test_repeating_one_value_never_crosses_a_distinct_threshold():
    """The regression this exists for: a script reading the same secret in a
    loop is not enumeration, and must not be reported as it."""
    engine = WindowedDetectionEngine(_FakeRedis(), rules=(DISTINCT_RULE,))
    for _ in range(20):
        assert await engine.evaluate(_secret_event("alice", "db-password")) == []


@pytest.mark.asyncio
async def test_distinct_values_cross_the_threshold():
    engine = WindowedDetectionEngine(_FakeRedis(), rules=(DISTINCT_RULE,))
    assert await engine.evaluate(_secret_event("alice", "s1")) == []
    assert await engine.evaluate(_secret_event("alice", "s2")) == []
    hits = await engine.evaluate(_secret_event("alice", "s3"))
    assert [h.rule_id for h in hits] == ["wd-test-distinct"]


@pytest.mark.asyncio
async def test_distinct_counts_are_per_entity():
    engine = WindowedDetectionEngine(_FakeRedis(), rules=(DISTINCT_RULE,))
    for secret in ("s1", "s2"):
        await engine.evaluate(_secret_event("alice", secret))
    # Bob's two are his own; neither principal has reached three.
    for secret in ("s1", "s2"):
        assert await engine.evaluate(_secret_event("bob", secret)) == []


@pytest.mark.asyncio
async def test_an_event_missing_the_distinct_field_is_skipped_not_counted():
    """Falling back to counting events would be a different, louder detection
    wearing this one's id."""
    engine = WindowedDetectionEngine(_FakeRedis(), rules=(DISTINCT_RULE,))
    bare = {"tenant_id": _TENANT, "ocsf_event": {"raw_event": {"event_type": "secret_access", "user": "alice"}}}
    for _ in range(10):
        assert await engine.evaluate(bare) == []


def test_the_loader_carries_distinct_by():
    from app.services.windowed_detection import load_window_rules

    rules = load_window_rules()
    distinct = [r for r in rules if r.distinct_by]
    assert distinct, "no exported rule uses distinct_by; the capability has no corpus"
    assert all(
        r.group_by and r.distinct_by != r.group_by for r in distinct
    ), "a rule counting distinct values of its own grouping key counts 1 forever"
