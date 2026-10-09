"""Every translated windowed rule, replayed through the real engine.

Why this file and not a comparison against the exporter
-------------------------------------------------------
``scripts/check_windowed_translation.py`` proves a translation matches the
``det-*`` rule it came from. That is a statement about two pieces of JSON. It
cannot tell you the rule fires, and the corpus already contains the lesson:
the 74 rules this work translated passed fixture replay for years while being
unable to fire, because their fixtures were synthesised from the rule and
replayed against the same clauses.

So this drives the real :class:`WindowedDetectionEngine`, with the committed
ruleset, over events built from each rule's own selector, and asserts the
threshold boundary:

* ``threshold`` matching events fire the rule;
* ``threshold - 1`` do not — the one assertion a synthesised fixture can never
  make, because a stateless fixture has no notion of "one short";
* an event that fails the selector never counts, so a rule cannot be fired by
  traffic it does not select;
* two entities accumulate separately, so the grouping is real rather than a
  global counter wearing an entity's name.

"Fires" here means what it means everywhere else in this tree: replayed
through the real engine on a well-formed event of its log source and observed
to cross its threshold. It is not a claim that the rule detects an attack.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from app.services.windowed_detection import WindowedDetectionEngine, WindowRule, load_window_rules

RULESET = Path(__file__).resolve().parents[1] / "app" / "data" / "windowed_ruleset.json"


class _FakeRedis:
    """In-memory stand-in for the sorted-set window and the fired marker.

    Deliberately a faithful implementation of the five calls the engine makes
    rather than a mock that answers whatever is asked: a double that returns
    a crossing count for any key would make every assertion below vacuous.
    """

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.strings: dict[str, str] = {}

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, min_s: float, max_s: float) -> None:
        members = self.zsets.get(key, {})
        for member in [m for m, score in list(members.items()) if min_s <= score <= max_s]:
            del members[member]

    async def expire(self, key: str, ttl: int) -> None:
        return None

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> Any:
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True


def _translated() -> list[dict[str, Any]]:
    payload = json.loads(RULESET.read_text(encoding="utf-8"))
    rules = [r for r in payload["rules"] if r.get("translated_from")]
    assert rules, "no translated windowed rules in the committed ruleset — the replay corpus is empty"
    return rules


TRANSLATED = _translated()
IDS = [r["id"] for r in TRANSLATED]

#: Clause operators whose satisfying value cannot be read straight off the
#: clause. Everything else is plain equality or a list membership.
_PREFIX_OPS = ("startswith_any", "startswith")
_SUFFIX_OPS = ("endswith_any", "endswith")


def _satisfying_value(key: str, value: Any) -> tuple[str, Any] | None:
    """A field name and a value that satisfies one clause, or None if unknown."""
    for operator in ("in", "match_any", "has_any", *_PREFIX_OPS, *_SUFFIX_OPS, "gt", "gte", "contains_any", "contains"):
        suffix = "_" + operator
        if key.endswith(suffix):
            field = key[: -len(suffix)]
            if operator in {"in", "match_any", "has_any"}:
                return field, value[0] if isinstance(value, list) and value else None
            if operator in {"contains_any"}:
                return field, f"x{value[0]}x" if isinstance(value, list) and value else None
            if operator == "contains":
                return field, f"x{value}x"
            if operator in _PREFIX_OPS:
                head = value[0] if isinstance(value, list) else value
                return field, f"{head}-tail"
            if operator in _SUFFIX_OPS:
                tail = value[0] if isinstance(value, list) else value
                return field, f"head{tail}"
            if operator in {"gt", "gte"}:
                return field, float(value) + 1
            return None
    return key, value


def _event_for(rule: dict[str, Any], tenant: str, entity: str, distinct: str) -> dict[str, Any]:
    """A flat connector-shaped event that this rule's selector accepts."""
    raw: dict[str, Any] = {}
    for key, value in (rule.get("match_when") or {}).items():
        resolved = _satisfying_value(key, value)
        assert resolved is not None, f"{rule['id']}: cannot build an event satisfying clause {key!r}"
        field, satisfying = resolved
        raw[field] = satisfying
    raw[rule["group_by"]] = entity
    if rule.get("distinct_by"):
        raw[rule["distinct_by"]] = distinct
    return {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps(raw)}}


def _engine(rule: dict[str, Any]) -> tuple[WindowedDetectionEngine, _FakeRedis]:
    """An engine holding exactly one rule, so a hit can only be that rule's."""
    loaded = {r.id: r for r in load_window_rules()}
    assert rule["id"] in loaded, f"{rule['id']} is in the committed JSON but the engine did not load it"
    redis = _FakeRedis()
    return WindowedDetectionEngine(redis, rules=(loaded[rule["id"]],)), redis


@pytest.mark.parametrize("rule", TRANSLATED, ids=IDS)
@pytest.mark.asyncio
async def test_fires_on_the_event_that_crosses_its_threshold(rule: dict[str, Any]) -> None:
    engine, _ = _engine(rule)
    tenant = str(uuid4())
    distinct_values = [f"value-{i}" for i in range(rule["threshold"])]

    for index in range(rule["threshold"] - 1):
        hits = await engine.evaluate(_event_for(rule, tenant, "entity-a", distinct_values[index]))
        assert not hits, f"{rule['id']} fired on event {index + 1} of a threshold of {rule['threshold']}"

    hits = await engine.evaluate(_event_for(rule, tenant, "entity-a", distinct_values[-1]))
    assert [h.rule_id for h in hits] == [rule["id"]]


@pytest.mark.parametrize("rule", TRANSLATED, ids=IDS)
@pytest.mark.asyncio
async def test_an_event_its_selector_rejects_never_counts(rule: dict[str, Any]) -> None:
    """A rule must not be fireable by traffic it does not select.

    Skipped where the selector is empty: two of the translated rules inherited
    a `det-*` whose only clauses were the counter and the window, so there is
    no selector to violate. Recorded as a skip rather than passed silently,
    because "nothing to reject" and "rejects correctly" are different results.
    """
    if not rule.get("match_when"):
        pytest.skip(f"{rule['id']} has an empty selector; nothing to reject")
    engine, _ = _engine(rule)
    tenant = str(uuid4())
    for index in range(rule["threshold"] + 5):
        wrong = {
            "tenant_id": tenant,
            "ocsf_event": {
                "tenant_uid": tenant,
                "raw_data": json.dumps({rule["group_by"]: "entity-a", "event_type": "aisoc-test-unrelated", "unrelated": index}),
            },
        }
        assert not await engine.evaluate(wrong), f"{rule['id']} fired on an event its selector rejects"


@pytest.mark.parametrize("rule", TRANSLATED, ids=IDS)
@pytest.mark.asyncio
async def test_the_count_is_per_entity(rule: dict[str, Any]) -> None:
    """Splitting the same traffic across two entities must fire neither."""
    if rule["threshold"] < 2:
        pytest.skip(f"{rule['id']} fires on one event; there is nothing to split")
    engine, _ = _engine(rule)
    tenant = str(uuid4())
    per_entity = rule["threshold"] - 1
    for entity in ("entity-a", "entity-b"):
        for index in range(per_entity):
            hits = await engine.evaluate(_event_for(rule, tenant, entity, f"value-{index}"))
            assert not hits, f"{rule['id']} fired at {index + 1} events for {entity}, below its threshold of {rule['threshold']}"


@pytest.mark.parametrize("rule", [r for r in TRANSLATED if r.get("distinct_by")], ids=[r["id"] for r in TRANSLATED if r.get("distinct_by")])
@pytest.mark.asyncio
async def test_a_distinct_rule_does_not_fire_on_one_value_repeated(rule: dict[str, Any]) -> None:
    """The difference between a script retrying and a vault being walked.

    `wd-secret-enumeration`'s comment makes the distinction and nothing was
    asserting it for the translated rules, where it is the whole point of the
    `distinct_by` the decision table chose.
    """
    engine, _ = _engine(rule)
    tenant = str(uuid4())
    for index in range(rule["threshold"] * 2):
        hits = await engine.evaluate(_event_for(rule, tenant, "entity-a", "one-value"))
        assert not hits, f"{rule['id']} fired after {index + 1} events carrying one distinct value"


@pytest.mark.asyncio
async def test_every_translated_rule_is_loaded_by_the_engine() -> None:
    """Guards the artefact, not a fixture: a rule the loader rejects is silent."""
    loaded = {r.id for r in load_window_rules()}
    missing = sorted(r["id"] for r in TRANSLATED if r["id"] not in loaded)
    assert not missing, f"the loader skipped {len(missing)} translated rules: {missing}"


def test_the_translated_corpus_is_not_empty_by_accident() -> None:
    """A replay suite over zero rules passes; say so rather than report clean."""
    assert len(TRANSLATED) >= 50, f"only {len(TRANSLATED)} translated rules found; the exporter or the decision table shrank"


@pytest.mark.asyncio
async def test_a_translated_rule_reads_a_tenant_allowlist_boolean() -> None:
    """Two translated rules carry an `<x>_in_allowlist` clause.

    The stateless engine resolves those from the tenant overlay. The windowed
    engine did not consult the overlay at all, so translating those rules
    would have moved them from one engine that could not fire them to
    another.
    """
    rule = next(r for r in TRANSLATED if any("_in_allowlist" in k for k in (r.get("match_when") or {})))
    clause = next(k for k in rule["match_when"] if "_in_allowlist" in k)

    class _Overlay:
        tenant_id = "t"

        def derived_allowlist_fields(self, fields: dict[str, Any]) -> dict[str, Any]:
            return {clause: False}

    loaded = {r.id: r for r in load_window_rules()}
    engine = WindowedDetectionEngine(_FakeRedis(), rules=(loaded[rule["id"]],))
    tenant = str(uuid4())

    def event() -> dict[str, Any]:
        raw = {k: v for k, v in rule["match_when"].items() if k != clause}
        raw[rule["group_by"]] = "entity-a"
        return {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps(raw)}}

    # Without the overlay the allowlist clause is unresolvable, so the rule
    # must stay silent rather than treat "unknown" as "not allowlisted".
    for _ in range(rule["threshold"] + 2):
        assert not await engine.evaluate(event())

    engine_with_overlay = WindowedDetectionEngine(_FakeRedis(), rules=(loaded[rule["id"]],))
    hits: list[Any] = []
    for _ in range(rule["threshold"]):
        hits = await engine_with_overlay.evaluate(event(), _Overlay())
    assert [h.rule_id for h in hits] == [rule["id"]]


@pytest.mark.asyncio
async def test_enrichment_runs_before_the_window_counts() -> None:
    """A windowed rule may read a derived field, as a stateless rule may.

    Asserted on a rule declared here rather than on the corpus, because no
    shipped windowed rule reads one yet and a test that silently covers
    nothing is the failure this suite exists to avoid.
    """
    rule = WindowRule(
        id="wd-test-derived",
        name="derived",
        severity="low",
        category="identity",
        mitre=[],
        match_when={"actor_eq_target": True},
        group_by="actor",
        threshold=2,
        window_seconds=60,
    )
    engine = WindowedDetectionEngine(_FakeRedis(), rules=(rule,))
    tenant = str(uuid4())
    same = {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps({"actor": "u1", "target": "u1"})}}
    different = {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "raw_data": json.dumps({"actor": "u1", "target": "u2"})}}

    assert not await engine.evaluate(different)
    assert not await engine.evaluate(different)
    assert not await engine.evaluate(same)
    assert [h.rule_id for h in await engine.evaluate(same)] == ["wd-test-derived"]
