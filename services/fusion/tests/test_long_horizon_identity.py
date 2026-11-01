"""Item 2.2: breadth accumulates over weeks, and absence stays absent.

The two cases that matter are the ones the plan names as the pair the
measurement must separate — a slow distributed attack against one admin
account fires, and a travelling user with successful authentication does
not — so both are driven through the same code path with the same store
rather than asserted about different halves of it.
"""

from __future__ import annotations

import time

import pytest
from app.services.long_horizon_identity import (
    DERIVED_FIELDS,
    LongHorizonIdentityStore,
    classify_outcome,
    resolve_account,
)

_DAY = 86400


class FakeRedis:
    """Sets with expiry, which is the whole surface this store uses.

    A dict rather than a mock: a mock that answers every call would let a
    typo in a key name pass, and the key layout is the thing most likely to
    be wrong.
    """

    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}
        self.unreachable = False

    def _guard(self) -> None:
        if self.unreachable:
            raise ConnectionError("redis down")

    async def sadd(self, key: str, value: str) -> int:
        self._guard()
        self.sets.setdefault(key, set()).add(value)
        return 1

    async def scard(self, key: str) -> int:
        self._guard()
        return len(self.sets.get(key, ()))

    async def sunion(self, *keys: str) -> set[str]:
        self._guard()
        out: set[str] = set()
        for key in keys:
            out |= self.sets.get(key, set())
        return out

    async def expire(self, key: str, ttl: int) -> bool:
        self._guard()
        return True


def _auth(account: str, asn: int, outcome: str, country: str = "US") -> dict:
    return {"actor_email": account, "src_asn": asn, "src_country": country, "src_ip": f"203.0.113.{asn % 250}", "outcome": outcome}


@pytest.mark.asyncio
async def test_slow_distributed_attack_accumulates_across_days() -> None:
    """One failure per day from a different network crosses no daily count."""
    store = LongHorizonIdentityStore(FakeRedis(), min_active_days=3)
    now = time.time()
    fields: dict = {}
    for day in range(10):
        at = now - (9 - day) * _DAY
        fields = await store.derived_fields("t1", _auth("admin@example.com", 64496 + day, "failure"), now=at)

    assert fields["lh_distinct_failed_asn"] == 10
    assert fields["lh_horizon_days"] == 30
    # No success side was ever observed, so the ratio is undefined rather
    # than enormous. A dormant account must not fire the ratio rule.
    assert "lh_failed_to_success_asn_ratio" not in fields


@pytest.mark.asyncio
async def test_traveller_with_successes_does_not_widen_the_failing_side() -> None:
    """The negative control the plan names, through the same store."""
    store = LongHorizonIdentityStore(FakeRedis(), min_active_days=3)
    now = time.time()
    fields: dict = {}
    for day, (asn, country) in enumerate([(64496, "US"), (64497, "GB"), (64498, "DE"), (64499, "FR"), (64500, "JP")]):
        at = now - (4 - day) * _DAY
        fields = await store.derived_fields("t1", _auth("traveller@example.com", asn, "success", country), now=at)

    assert fields["lh_distinct_success_asn"] == 5
    assert "lh_distinct_failed_asn" not in fields
    assert "lh_failed_to_success_asn_ratio" not in fields


@pytest.mark.asyncio
async def test_ratio_separates_attack_from_travel() -> None:
    store = LongHorizonIdentityStore(FakeRedis(), min_active_days=3)
    now = time.time()
    for day in range(8):
        await store.derived_fields("t1", _auth("admin@example.com", 64496 + day, "failure"), now=now - (7 - day) * _DAY)
    fields: dict = {}
    for day in range(3):
        fields = await store.derived_fields("t1", _auth("admin@example.com", 65000 + day, "success"), now=now - (2 - day) * _DAY)

    assert fields["lh_distinct_failed_asn"] == 8
    assert fields["lh_distinct_success_asn"] == 3
    assert fields["lh_failed_to_success_asn_ratio"] == pytest.approx(8 / 3, rel=1e-3)


@pytest.mark.asyncio
async def test_short_history_publishes_nothing_rather_than_zero() -> None:
    """An account with one active day has no breadth to report.

    Zero would be a confident claim that nothing has failed against an
    account nobody has observed, which silences exactly the rules that
    exist to catch a new account being attacked.
    """
    store = LongHorizonIdentityStore(FakeRedis(), min_active_days=3)
    fields = await store.derived_fields("t1", _auth("new@example.com", 64496, "failure"))
    assert fields == {}


@pytest.mark.asyncio
async def test_unreachable_store_contributes_no_key() -> None:
    redis = FakeRedis()
    store = LongHorizonIdentityStore(redis, min_active_days=1)
    redis.unreachable = True
    assert await store.derived_fields("t1", _auth("a@example.com", 64496, "failure")) == {}


@pytest.mark.asyncio
async def test_saturated_day_is_reported_not_dropped() -> None:
    from app.services import long_horizon_identity as module

    original = module.MAX_DISTINCT_PER_DAY
    module.MAX_DISTINCT_PER_DAY = 3
    try:
        store = LongHorizonIdentityStore(FakeRedis(), min_active_days=1)
        now = time.time()
        fields: dict = {}
        for asn in range(6):
            fields = await store.derived_fields("t1", _auth("admin@example.com", 64496 + asn, "failure"), now=now)
        assert fields["lh_failed_asn_saturated"] is True
    finally:
        module.MAX_DISTINCT_PER_DAY = original


def test_outcome_is_none_when_the_event_states_neither() -> None:
    """Guessing would put ordinary activity into the failure set."""
    assert classify_outcome({"actor_email": "a@example.com"}) is None
    assert classify_outcome({"outcome": "FAILURE"}) == "failure"
    assert classify_outcome({"is_success": False}) == "failure"
    assert classify_outcome({"is_success": True}) == "success"


def test_target_account_wins_over_the_actor() -> None:
    """A reset names the admin as actor and the victim as target."""
    assert resolve_account({"actor_email": "admin@example.com", "target_user": "victim@example.com"}) == "victim@example.com"


def test_derived_field_set_matches_the_gate() -> None:
    """Both directions, because a one-directional comparison drifts.

    The matcher's operator list and the reachability gate's copy of it
    disagreed once and three shipped rules were dead while the gate called
    them reachable.
    """
    import ast
    import pathlib

    gate = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "check_detection_fields.py"
    tree = ast.parse(gate.read_text(encoding="utf-8"))
    pinned: set[str] | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "_LONG_HORIZON_DERIVED_FIELDS" for t in node.targets):
            pinned = set(ast.literal_eval(node.value.args[0]))  # type: ignore[attr-defined]
    assert pinned is not None, "the gate no longer pins _LONG_HORIZON_DERIVED_FIELDS"
    assert pinned == set(DERIVED_FIELDS)
