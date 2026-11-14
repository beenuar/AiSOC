"""Per-principal behavioural baselines, and the three ways they refuse.

Depth plan 3.4. The assertions below are about behaviour under the
conditions that actually occur — a principal with no history, one with
enough, a service account whose variance has collapsed, a tenant boundary,
and Redis being unavailable — rather than about a helper returning a float.

Three of them are the ones worth having, because each pins a refusal that a
plausible-looking implementation would get wrong in the unsafe direction:

* **A short history contributes no key.** The first event a principal ever
  produces is 100% of their history, so every value looks rare. Reporting
  that would make every new account fire every novelty rule.
* **A degenerate distribution scores `None`, not `0.0`.** Service accounts
  converge on a constant and their standard deviation collapses, so a
  z-score of zero would make the most automated account in the estate the
  least suspicious one it is possible to be.
* **An unreadable store contributes no key.** Same reason as the first-seen
  store: absent means the clause does not match, which is quiet.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from app.services.baselines import (
    DERIVED_FIELDS,
    MIN_PEER_MEMBERS,
    MIN_VOLUME_SAMPLES,
    OAUTH_APP_FIELDS,
    PEER_GROUP_FIELDS,
    PRINCIPAL_FIELDS,
    RARITY_FIELDS,
    BaselineStore,
    resolve_principal,
    welford_add,
    z_score,
)

_REPO = Path(__file__).resolve().parents[3]


class _FakeRedis:
    """The hash and set operations the store actually calls."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self.sets: dict[str, set[str]] = {}

    async def hincrby(self, key: str, field: str, amount: int = 1) -> int:
        bucket = self.hashes.setdefault(key, {})
        value = int(bucket.get(field, "0")) + amount
        bucket[field] = str(value)
        return value

    async def hget(self, key: str, field: str) -> Any:
        return self.hashes.get(key, {}).get(field)

    async def hset(self, key: str, field: str, value: str) -> int:
        self.hashes.setdefault(key, {})[field] = value
        return 1

    async def hgetall(self, key: str) -> dict[str, str]:
        return dict(self.hashes.get(key, {}))

    async def hlen(self, key: str) -> int:
        return len(self.hashes.get(key, {}))

    async def sadd(self, key: str, member: str) -> int:
        self.sets.setdefault(key, set()).add(member)
        return 1

    async def scard(self, key: str) -> int:
        return len(self.sets.get(key, set()))

    async def expire(self, key: str, ttl: int) -> bool:
        return True


class _NoRedis:
    def __getattr__(self, _name: str) -> Any:
        async def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise ConnectionError("redis is down")

        return _boom


async def _warm(store: BaselineStore, tenant: str, event: dict[str, Any], times: int) -> None:
    """Give a principal enough history that rarity is reportable."""
    for _ in range(times):
        await store.derived_fields(tenant, event, now=1000.0)


# -- rarity -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_principal_with_too_little_history_gets_no_rarity() -> None:
    """Every value is novel on day one; saying so would fire on everything."""
    store = BaselineStore(_FakeRedis())
    fields = await store.derived_fields("t-1", {"user": "alice", "event_name": "GetObject"}, now=1000.0)
    assert "baseline_action_rarity" not in fields


@pytest.mark.asyncio
async def test_a_routine_action_scores_near_zero_and_a_novel_one_near_one() -> None:
    store = BaselineStore(_FakeRedis(), min_observations=20)
    routine = {"user": "alice", "event_name": "GetObject"}
    await _warm(store, "t-1", routine, 40)

    common = await store.derived_fields("t-1", routine, now=1000.0)
    assert common["baseline_action_rarity"] < 0.05

    novel = await store.derived_fields("t-1", {"user": "alice", "event_name": "CreateAccessKey"}, now=1000.0)
    # 1 sighting out of 42 observations: rare, but bounded by how much
    # history exists rather than asserted as a flat 1.0.
    assert 0.9 < novel["baseline_action_rarity"] < 1.0


@pytest.mark.asyncio
async def test_rarity_is_per_principal_not_per_tenant() -> None:
    """Alice's routine is not Bob's, which is the whole point of a baseline."""
    store = BaselineStore(_FakeRedis(), min_observations=20)
    await _warm(store, "t-1", {"user": "alice", "event_name": "CreateAccessKey"}, 40)
    await _warm(store, "t-1", {"user": "bob", "event_name": "GetObject"}, 40)

    for_bob = await store.derived_fields("t-1", {"user": "bob", "event_name": "CreateAccessKey"}, now=1000.0)
    assert for_bob["baseline_action_rarity"] > 0.9


@pytest.mark.asyncio
async def test_tenants_do_not_share_baselines() -> None:
    store = BaselineStore(_FakeRedis(), min_observations=20)
    await _warm(store, "t-1", {"user": "alice", "event_name": "GetObject"}, 40)
    other = await store.derived_fields("t-2", {"user": "alice", "event_name": "GetObject"}, now=1000.0)
    assert "baseline_action_rarity" not in other


@pytest.mark.asyncio
async def test_the_value_set_per_principal_is_bounded() -> None:
    """An attacker-chosen resource name must not be a memory primitive."""
    store = BaselineStore(_FakeRedis(), min_observations=1)
    for index in range(700):
        await store.derived_fields("t-1", {"user": "alice", "resource": f"obj-{index}"}, now=1000.0)
    key = "aisoc:bl:t-1:alice:baseline_resource_rarity"
    assert len(store._redis.hashes[key]) <= 514  # cap, plus the total field


# -- volume -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_hour_in_progress_is_not_scored() -> None:
    """A partial count against complete ones calls every event at :01 odd."""
    store = BaselineStore(_FakeRedis())
    first = await store.derived_fields("t-1", {"user": "alice"}, now=3600.0)
    assert "baseline_principal_volume_z" not in first


@pytest.mark.asyncio
async def test_a_volume_spike_scores_once_the_hour_completes() -> None:
    store = BaselineStore(_FakeRedis())
    hour = 3600.0
    # Quiet hours of 8-12 events. The counts must *vary*: a principal who
    # does exactly ten things an hour has zero variance, and the degenerate
    # guard then refuses to score them at all — correctly, and it is what
    # the first draft of this fixture accidentally measured.
    for index in range(MIN_VOLUME_SAMPLES + 2):
        for _ in range(8 + (index % 5)):
            await store.derived_fields("t-1", {"user": "alice"}, now=hour * (index + 1))
    # A loud hour, then the next hour's first event scores the loud one.
    for _ in range(400):
        await store.derived_fields("t-1", {"user": "alice"}, now=hour * 40)
    scored = await store.derived_fields("t-1", {"user": "alice"}, now=hour * 41)
    assert scored["baseline_principal_volume_z"] > 3.0


@pytest.mark.asyncio
async def test_an_oauth_app_is_baselined_separately_from_the_user() -> None:
    """A rogue grant acts as a user, so the user's own volume looks normal."""
    store = BaselineStore(_FakeRedis())
    event = {"user": "alice", "oauth_app": "backup-tool"}
    hour = 3600.0
    for index in range(MIN_VOLUME_SAMPLES + 2):
        await store.derived_fields("t-1", event, now=hour * (index + 1))
    key = "aisoc:bl:t-1:backup-tool:vol:oauth_app"
    assert key in store._redis.hashes


# -- peer groups ------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_group_smaller_than_the_floor_yields_no_peer_signal() -> None:
    """A group of one is that principal's own baseline wearing a group name."""
    store = BaselineStore(_FakeRedis())
    fields = await store.derived_fields("t-1", {"user": "alice", "department": "finance"}, now=1000.0)
    assert "baseline_peer_deviation" not in fields


@pytest.mark.asyncio
async def test_the_peer_floor_counts_members_not_observations() -> None:
    """One noisy principal must not satisfy the minimum on its own."""
    store = BaselineStore(_FakeRedis())
    for _ in range(MIN_PEER_MEMBERS * 10):
        await store.derived_fields("t-1", {"user": "alice", "department": "finance"}, now=1000.0)
    fields = await store.derived_fields("t-1", {"user": "alice", "department": "finance"}, now=1000.0)
    assert "baseline_peer_deviation" not in fields


# -- the refusals -----------------------------------------------------------


def test_a_degenerate_distribution_is_unknown_and_not_normal() -> None:
    """A service account's variance collapses; 0.0 would read as all-clear."""
    stats: dict[str, float] = {}
    for _ in range(50):
        stats = welford_add(stats, 10.0)
    assert z_score(stats, 9999.0, min_samples=5) is None


def test_a_short_history_is_unknown() -> None:
    stats: dict[str, float] = {}
    for value in (1.0, 2.0, 3.0):
        stats = welford_add(stats, value)
    assert z_score(stats, 100.0, min_samples=12) is None


def test_welford_mutates_nothing() -> None:
    """The ueba copy edited in place, so no baseline there ever advanced."""
    stats = {"count": 1.0, "mean": 5.0, "m2": 0.0}
    before = dict(stats)
    welford_add(stats, 9.0)
    assert stats == before


@pytest.mark.asyncio
async def test_an_unreadable_store_contributes_no_key() -> None:
    store = BaselineStore(_NoRedis())
    assert await store.derived_fields("t-1", {"user": "alice", "event_name": "x"}, now=1000.0) == {}


@pytest.mark.asyncio
async def test_an_event_naming_no_principal_contributes_no_key() -> None:
    """A baseline with no subject is not a baseline."""
    store = BaselineStore(_FakeRedis())
    assert await store.derived_fields("t-1", {"event_name": "GetObject"}, now=1000.0) == {}


@pytest.mark.asyncio
async def test_a_tenantless_event_is_not_recorded() -> None:
    """Without a tenant the key is shared, which is a cross-tenant read."""
    redis = _FakeRedis()
    store = BaselineStore(redis)
    assert await store.derived_fields("", {"user": "alice", "event_name": "x"}, now=1000.0) == {}
    assert redis.hashes == {}


def test_a_principal_is_resolved_case_insensitively() -> None:
    assert resolve_principal({"user": "  Alice  "}) == "alice"
    assert resolve_principal({"actor_email": "A@B.COM"}) == "a@b.com"
    assert resolve_principal({"event_name": "GetObject"}) is None


# -- typed signals ----------------------------------------------------------


@pytest.mark.asyncio
async def test_each_observation_is_a_typed_signal() -> None:
    """3.4 requires a typed signal, not an alert — so the kind must survive."""
    store = BaselineStore(_FakeRedis(), min_observations=20)
    routine = {"user": "alice", "event_name": "GetObject"}
    await _warm(store, "t-1", routine, 40)
    signals = await store.signals("t-1", routine, now=1000.0)
    assert signals
    assert {s.kind for s in signals} <= {"rarity", "volume", "peer"}
    assert all(s.subject == "alice" for s in signals)


# -- drift ------------------------------------------------------------------


def test_the_reachability_gate_mirrors_this_module() -> None:
    """A new baseline field must be added in both places or it is invisible.

    The direction that bites is the one the matcher's operator list got
    wrong (deviation D9): the gate kept its own copy, the module grew a
    field, and the gate went on reporting rules unreachable that were not.
    Asserting equality rather than containment catches both directions.
    """
    spec = importlib.util.spec_from_file_location("cdf_baselines", _REPO / "scripts" / "check_detection_fields.py")
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    assert gate._BASELINE_DERIVED_FIELDS == DERIVED_FIELDS


def test_every_rarity_field_is_declared_as_derived() -> None:
    assert set(RARITY_FIELDS) <= DERIVED_FIELDS


def test_every_subject_chain_names_a_field_some_connector_emits() -> None:
    """A baseline over a field nothing emits is a signal that cannot fire.

    This is the test that earns its place. The first draft of
    `RARITY_FIELDS` gave `baseline_client_family_rarity` the chain
    `client_family` / `user_agent_family` / `client_app`, and **no connector
    emits any of the three** — so that rarity would have been published,
    counted, and structurally incapable of being computed on any
    deployment. Worse than a missing feature, because the field name reads
    as working.

    The namespace comes from the same static analysis
    `scripts/check_detection_fields.py` performs, so the two cannot
    disagree about what a connector emits.
    """
    spec = importlib.util.spec_from_file_location("cdf_emit", _REPO / "scripts" / "check_detection_fields.py")
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    emitted = gate._connector_namespace()

    chains: dict[str, tuple[str, ...]] = {
        **RARITY_FIELDS,
        "__principal__": PRINCIPAL_FIELDS,
        "__oauth_app__": OAUTH_APP_FIELDS,
        "__peer_group__": PEER_GROUP_FIELDS,
    }
    unreachable = {name: chain for name, chain in chains.items() if not (set(chain) & emitted)}
    assert not unreachable, f"no connector emits any candidate for: {sorted(unreachable)}"


def test_the_narrowed_family_no_longer_claims_unrelated_fields() -> None:
    """`^active_` swept in a systemd unit state and an ITSM lookup.

    Both were reported as blocked on a baseline that would never have
    helped either, so the family read "2 rules need 3.4" when the answer
    was zero. Pinned so the convenient-looking broad pattern cannot return.
    """
    spec = importlib.util.spec_from_file_location("cdf_family", _REPO / "scripts" / "check_detection_fields.py")
    assert spec and spec.loader
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    assert gate._family("active_state") != "behavioural baseline"
    assert gate._family("active_p0_or_p1_incident") == "external system context"
    for field in DERIVED_FIELDS:
        assert gate._family(field) == "behavioural baseline"
