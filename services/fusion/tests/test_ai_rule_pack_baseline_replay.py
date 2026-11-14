"""The four baseline-backed AI rules, end to end.

Depth plan wave 2, Phase 7.4 — the targets Phase 7.3 unblocked.

What this drives
----------------
The real connector output → the shape ingest really produces → the **real**
`BaselineStore` over a real history → the **real** `DetectionEngine` over
the real compiled ruleset. Nothing is stubbed and no derived field is
injected.

That last point is the one that matters. These four rules clause on
`baseline_agent_*` and `baseline_gateway_key_*`, which are produced by a
different module from the one that reads them. Handing the engine a
hand-written `{"baseline_agent_tool_rarity": 0.99}` would prove the matcher
compares floats and would say nothing about whether the baseline module
ever produces that key — which is the only way these rules can be wrong,
and is exactly how `baseline_client_family_rarity` came to name three
fields no connector emits.

Novelty needs a history, so each test builds one first
-------------------------------------------------------
A rarity against an empty history is `0.0` by design — the module refuses
to claim more confidence than the history supports — so a test that fired
one event and expected a novelty score would be asserting against the
wrong semantics rather than against the rule.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from app.services.baselines import BaselineStore
from app.services.detection_engine import DetectionEngine

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "ai_gateway"
RULESET = pathlib.Path(__file__).parents[1] / "app" / "data" / "detection_ruleset.json"
TENANT = "11111111-1111-1111-1111-111111111111"


def _compiled() -> list[dict]:
    blob = json.loads(RULESET.read_text())
    return blob["rules"] if isinstance(blob, dict) and "rules" in blob else blob


#: The engine reports a hit by rule id; everything else speaks slugs. Mapped
#: through the artefact rather than hardcoded, because ids are positional
#: and a rule inserted earlier in a category shifts every later one.
_ID_TO_SLUG: dict[str, str] = {r["id"]: r["slug"] for r in _compiled()}


class _FakeRedis:
    """A real dict, not a mock that answers anything.

    A double returning a plausible value for any key cannot notice a
    baseline keyed on the wrong subject, which is the defect this file
    exists to catch.
    """

    def __init__(self) -> None:
        self.hashes: dict[str, dict] = {}

    async def hincrby(self, key: str, field: str, amount: int) -> int:
        bucket = self.hashes.setdefault(key, {})
        bucket[field] = int(bucket.get(field, 0)) + amount
        return bucket[field]

    async def hget(self, key: str, field: str):
        value = self.hashes.get(key, {}).get(field)
        return None if value is None else str(value)

    async def hlen(self, key: str) -> int:
        return len(self.hashes.get(key, {}))

    async def hgetall(self, key: str):
        return {k: str(v) for k, v in self.hashes.get(key, {}).items()}

    async def hset(self, key: str, field: str | None = None, value=None, *, mapping: dict | None = None):
        bucket = self.hashes.setdefault(key, {})
        if mapping:
            bucket.update(mapping)
        if field is not None:
            bucket[field] = value
        return 1

    async def expire(self, key: str, ttl: int) -> bool:
        return True

    async def sadd(self, key: str, member: str) -> int:
        self.hashes.setdefault(f"{key}:set", {})[member] = 1
        return 1

    async def scard(self, key: str) -> int:
        return len(self.hashes.get(f"{key}:set", {}))


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _message(event: dict) -> dict:
    """What `services/ingest` hands fusion for a connector-pulled event.

    `raw_data` is a JSON **string** — `json.Marshal` then `string` on the
    Go side. A test that puts a dict here exercises a branch the
    production path does not take.
    """
    return {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 6003,
            "source_type": "ai_gateway",
            "activity_name": event.get("tool_name") or "",
            "actor": {"user": {"name": event.get("on_behalf_of")}},
            "metadata": {"product": {"name": "AI Gateway", "vendor_name": "AI Gateway"}},
            "message": event.get("title") or "",
            "finding": {"uid": event.get("external_id") or ""},
            "raw_data": json.dumps(event),
        },
    }


@pytest.fixture
def engine() -> DetectionEngine:
    return DetectionEngine()


@pytest.fixture
def store() -> BaselineStore:
    return BaselineStore(_FakeRedis(), min_observations=1)


async def _derived(store: BaselineStore, event: dict) -> dict:
    """The derived namespace the engine will see, from the real store."""
    message = _message(event)
    fields = _message_fields(message)
    return await store.derived_fields(TENANT, fields)


def _message_fields(message: dict) -> dict:
    """The connector namespace the engine reconstructs from `raw_data`.

    Re-derived here the same way `DetectionEngine._raw_fields` does, so the
    baseline store is fed exactly what the engine will match against — if
    the two disagreed, a rule could clause on a field the baseline never
    saw and this test would not notice.
    """
    raw = message["ocsf_event"]["raw_data"]
    decoded = json.loads(raw)
    nested = decoded.get("raw_event")
    if isinstance(nested, dict):
        merged = dict(nested)
        merged.update(decoded)
        return merged
    return decoded


async def _fire(engine: DetectionEngine, store: BaselineStore, event: dict) -> set[str]:
    """Slugs that fire, with the baseline computed by the real store."""
    derived = await _derived(store, event)
    hits = engine.evaluate(_message(event), _extra_fields=derived)
    return {_ID_TO_SLUG.get(getattr(h, "rule_id", "") or getattr(h, "id", ""), "") for h in hits}


async def _build_history(store: BaselineStore, *, turns: int = 25, vary_cost: bool = False) -> None:
    routine = _load("routine.json")
    for index in range(turns):
        event = dict(routine)
        if vary_cost:
            # A constant has no z-score, by design — `z_score` refuses a
            # collapsed standard deviation so the most automated agent in
            # the estate is not the least suspicious one.
            event["request_cost_usd"] = 0.02 + (index % 5) * 0.002
        await _derived(store, event)


# ---------------------------------------------------------------------------
# The rules are in the artefact the engine loads
# ---------------------------------------------------------------------------

SLUGS = (
    "ai-agent-new-high-risk-tool",
    "ai-agent-guardrail-violation-rate",
    "ai-agent-token-spend-anomaly",
    "ai-gateway-key-spend-anomaly",
)


def test_all_four_rules_are_compiled():
    """`detections/*.yaml` is generated output; the engine loads the JSON.

    A rule in one and not the other is a published figure describing
    something that does not run.
    """
    missing = sorted(set(SLUGS) - {r["slug"] for r in _compiled()})
    assert not missing, f"declared but not compiled: {missing}"


# ---------------------------------------------------------------------------
# Positive and negative, through the real baseline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_never_used_high_risk_tool_fires(engine: DetectionEngine, store: BaselineStore):
    await _build_history(store)
    assert "ai-agent-new-high-risk-tool" in await _fire(engine, store, _load("high_risk_tool.json"))


@pytest.mark.asyncio
async def test_a_novel_but_benign_tool_does_not_fire(engine: DetectionEngine, store: BaselineStore):
    """The negative twin, differing in exactly one field: the tool name.

    Equally novel, equally unseen. If this fired, the rule would be a
    novelty detector rather than a high-risk-tool detector, and every
    agent's first use of anything would be an alert.
    """
    await _build_history(store)
    assert "ai-agent-new-high-risk-tool" not in await _fire(engine, store, _load("novel_benign_tool.json"))


@pytest.mark.asyncio
async def test_the_agents_routine_tool_does_not_fire(engine: DetectionEngine, store: BaselineStore):
    """The other negative: familiar, and therefore not novel.

    This is the one that proves the *baseline* is doing the work rather
    than the tool list.
    """
    await _build_history(store)
    assert "ai-agent-new-high-risk-tool" not in await _fire(engine, store, _load("routine.json"))


@pytest.mark.asyncio
async def test_a_high_risk_tool_the_agent_uses_constantly_does_not_fire(engine: DetectionEngine, store: BaselineStore):
    """Novelty, not the verb.

    A deployment bot whose job is `execute_command` must not alert on
    every run. Without this the rule is a list of scary tool names, which
    is the thing an operator switches off in week one.
    """
    high_risk = _load("high_risk_tool.json")
    for _ in range(30):
        await _derived(store, high_risk)
    assert "ai-agent-new-high-risk-tool" not in await _fire(engine, store, high_risk)


@pytest.mark.asyncio
async def test_a_blocked_turn_fires_only_once_the_rate_is_abnormal(engine: DetectionEngine, store: BaselineStore):
    """A single guardrail violation is noise; a rise against the agent's
    own history is someone probing for a phrasing that gets through."""
    blocked = _load("guardrail_blocked.json")
    assert "ai-agent-guardrail-violation-rate" not in await _fire(engine, store, blocked)


@pytest.mark.asyncio
async def test_spend_far_above_the_agents_baseline_fires(engine: DetectionEngine, store: BaselineStore):
    await _build_history(store, turns=30, vary_cost=True)
    fired = await _fire(engine, store, _load("expensive.json"))
    assert "ai-agent-token-spend-anomaly" in fired
    # The same event moves the key's baseline too, and that is deliberate:
    # a leaked key driving inference from outside the estate moves the
    # key's figure while every agent on it looks ordinary.
    assert "ai-gateway-key-spend-anomaly" in fired


@pytest.mark.asyncio
async def test_a_routine_cost_does_not_fire(engine: DetectionEngine, store: BaselineStore):
    """The negative twin for spend, differing only in the cost."""
    await _build_history(store, turns=30, vary_cost=True)
    fired = await _fire(engine, store, _load("routine.json"))
    assert "ai-agent-token-spend-anomaly" not in fired
    assert "ai-gateway-key-spend-anomaly" not in fired


@pytest.mark.asyncio
async def test_nothing_fires_before_there_is_a_history(engine: DetectionEngine, store: BaselineStore):
    """A deployment's first week must be quiet.

    "Not enough history" and "anomalous" must never look the same. All
    four rules read a baseline that withholds a score until it has one, so
    an estate that has just switched this on gets silence rather than a
    page per agent.
    """
    fired = await _fire(engine, store, _load("expensive.json"))
    assert not (set(SLUGS) & fired), f"fired with no history: {sorted(set(SLUGS) & fired)}"
