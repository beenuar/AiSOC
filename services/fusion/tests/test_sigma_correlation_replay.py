"""Every compiled Sigma correlation, replayed through the real engine.

`scripts/check_sigma_correlations.py` proves a correlation document compiles
and that the fields it names are ones something emits. Both are statements
about text. This drives the committed artefact through the real
`WindowedDetectionEngine` and asserts the behaviour each correlation type is
supposed to have:

* ``event_count`` fires at its threshold and not one short;
* ``value_count`` needs distinct values and is not satisfied by one repeated;
* ``temporal_ordered`` needs its stages in event-time order;
* ``temporal`` needs all its stages but accepts either order.

The fourth is the one worth having a test for: unordered and ordered differ
by a single flag, and a flag that is read nowhere looks identical to a flag
that works.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from app.services.windowed_detection import WindowedDetectionEngine, load_sequence_rules, load_window_rules

RULESET = Path(__file__).resolve().parents[1] / "app" / "data" / "windowed_ruleset.json"


class _FakeRedis:
    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.strings: dict[str, str] = {}

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, min_s: float, max_s: float) -> None:
        members = self.zsets.get(key, {})
        for member in [m for m, score in list(members.items()) if min_s <= score <= max_s]:
            del members[member]

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def zrangebyscore(self, key: str, min_s: float, max_s: float, withscores: bool = False) -> list[Any]:
        items = sorted(((m, s) for m, s in self.zsets.get(key, {}).items() if min_s <= s <= max_s), key=lambda kv: (kv[1], kv[0]))
        return items if withscores else [m for m, _ in items]

    async def expire(self, key: str, ttl: int) -> None:
        return None

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> Any:
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True


def _correlations() -> list[dict[str, Any]]:
    rules = [r for r in json.loads(RULESET.read_text(encoding="utf-8"))["rules"] if r.get("correlation_type")]
    assert rules, "no compiled Sigma correlations in the committed ruleset — the replay corpus is empty"
    return rules


CORRELATIONS = _correlations()
BY_TYPE = {r["correlation_type"]: r for r in CORRELATIONS}


def _satisfying(key: str, value: Any) -> tuple[str, Any]:
    """A field and a value that satisfies one compiled clause.

    The Sigma compiler emits anchored patterns rather than equalities, even
    for a plain string, so a literal recovered from `^iam\\.amazonaws\\.com$`
    is what an event has to carry. Recovering it here rather than hand-writing
    the value keeps the replay honest: the event is built from the clause the
    engine will evaluate, not from the YAML a human wrote.
    """
    if key.endswith("_pattern_match_any"):
        pattern = value[0] if isinstance(value, list) else value
        return key[: -len("_pattern_match_any")], re.sub(r"\\(.)", r"\1", str(pattern).strip("^$"))
    if key.endswith("_in"):
        return key[: -len("_in")], value[0] if isinstance(value, list) and value else value
    return key, value


def _event(rule: dict[str, Any], tenant: str, clause: dict[str, Any], entity: str, when: float, distinct: str = "") -> dict[str, Any]:
    raw = dict(_satisfying(key, value) for key, value in clause.items())
    raw[rule["group_by"]] = entity
    raw["event_time"] = when
    if rule.get("distinct_by"):
        raw[rule["distinct_by"]] = distinct
    return {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps(raw)}}


def _engine_for(rule: dict[str, Any]) -> WindowedDetectionEngine:
    counting = tuple(r for r in load_window_rules() if r.id == rule["id"])
    staged = tuple(r for r in load_sequence_rules() if r.id == rule["id"])
    assert counting or staged, f"{rule['id']} is in the committed JSON but neither loader accepted it"
    return WindowedDetectionEngine(_FakeRedis(), rules=counting, sequences=staged)


def test_all_four_correlation_types_are_covered() -> None:
    """A replay suite that silently covers three of four proves three of four."""
    assert set(BY_TYPE) == {"event_count", "value_count", "temporal", "temporal_ordered"}, f"covered: {sorted(BY_TYPE)}"


@pytest.mark.asyncio
async def test_event_count_fires_at_its_threshold_and_not_one_short() -> None:
    rule = BY_TYPE["event_count"]
    engine = _engine_for(rule)
    tenant = str(uuid4())
    for index in range(rule["threshold"] - 1):
        assert not await engine.evaluate(_event(rule, tenant, rule["match_when"], "arn:aws:iam::1:user/a", 1000.0 + index))
    hits = await engine.evaluate(_event(rule, tenant, rule["match_when"], "arn:aws:iam::1:user/a", 2000.0))
    assert [h.rule_id for h in hits] == [rule["id"]]


@pytest.mark.asyncio
async def test_value_count_needs_distinct_values() -> None:
    rule = BY_TYPE["value_count"]
    tenant = str(uuid4())

    repeated = _engine_for(rule)
    for index in range(rule["threshold"] * 2):
        assert not await repeated.evaluate(
            _event(rule, tenant, rule["match_when"], "arn:aws:iam::1:user/a", 1000.0 + index, distinct="one-value")
        )

    distinct = _engine_for(rule)
    hits: list[Any] = []
    for index in range(rule["threshold"]):
        hits = await distinct.evaluate(
            _event(rule, tenant, rule["match_when"], "arn:aws:iam::1:user/a", 1000.0 + index, distinct=f"value-{index}")
        )
    assert [h.rule_id for h in hits] == [rule["id"]]


@pytest.mark.asyncio
async def test_temporal_ordered_requires_the_order() -> None:
    rule = BY_TYPE["temporal_ordered"]
    first, second = rule["sequence"][0], rule["sequence"][1]
    tenant = str(uuid4())

    forwards = _engine_for(rule)
    assert not await forwards.evaluate(_event(rule, tenant, first, "a@example.com", 1000.0))
    assert [h.rule_id for h in await forwards.evaluate(_event(rule, tenant, second, "a@example.com", 1100.0))] == [rule["id"]]

    backwards = _engine_for(rule)
    assert not await backwards.evaluate(_event(rule, tenant, second, "a@example.com", 1000.0))
    assert not await backwards.evaluate(_event(rule, tenant, first, "a@example.com", 1100.0))


@pytest.mark.asyncio
async def test_temporal_accepts_either_order_but_needs_both_stages() -> None:
    rule = BY_TYPE["temporal"]
    first, second = rule["sequence"][0], rule["sequence"][1]
    tenant = str(uuid4())

    backwards = _engine_for(rule)
    assert not await backwards.evaluate(_event(rule, tenant, second, "admin@example.com", 1000.0))
    assert [h.rule_id for h in await backwards.evaluate(_event(rule, tenant, first, "admin@example.com", 1100.0))] == [rule["id"]]

    one_stage_only = _engine_for(rule)
    for index in range(6):
        assert not await one_stage_only.evaluate(_event(rule, tenant, first, "admin@example.com", 1000.0 + index))


@pytest.mark.asyncio
async def test_a_correlation_does_not_cross_entities() -> None:
    for rule in CORRELATIONS:
        engine = _engine_for(rule)
        tenant = str(uuid4())
        clauses = list(rule.get("sequence") or [rule["match_when"]])
        needed = rule.get("threshold", len(clauses))
        for index in range(needed * 2):
            clause = clauses[index % len(clauses)]
            entity = f"entity-{index % 7}"
            hits = await engine.evaluate(_event(rule, tenant, clause, entity, 1000.0 + index, distinct=f"value-{index}"))
            assert not hits, f"{rule['id']} fired across {7} different entities"
