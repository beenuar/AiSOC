"""Baselines per sub-principal, with the AI agent as one kind.

Depth plan wave 2, Phase 7.3 (depth 6.4, parity 6.7).

The gap
-------
`baselines.py` had exactly one sub-principal: `baseline_oauth_app_volume_z`,
with the OAuth application's field chain hardcoded into `derived_fields`.
Nothing keyed a baseline on an AI agent, so depth 6.4's "per-agent baselines
(tools, resources, volume, token spend, hours)" had nowhere to live — and
four of 7.4's targets, which all turn on *novelty* or *rate per agent*, had
no input.

Why this is one mechanism and not two
--------------------------------------
Wave-2 Phase 1.4 (Lane A) asks for baselines per sub-principal — OAuth app,
personal access token, service account, and **an AI agent acting for a
human**. An AI agent is a sub-principal in exactly that sense. Two items
building two mechanisms in the same module would give the console two ways
to say the same thing, which is the drift this repository keeps finding.

So the OAuth application stops being special-cased and becomes the first
entry in `SUB_PRINCIPAL_FIELDS`; the AI agent and the gateway key are the
second and third. Lane A's remaining two kinds are a dict entry each, and
`baseline_oauth_app_volume_z` keeps its published name because the generic
naming produces it.

Every chain here names a field a connector really emits
--------------------------------------------------------
That is the module's own rule, and the reason it exists: the first draft of
`baseline_client_family_rarity` listed three names no connector emitted, so
it could never have been computed on any deployment while reading as
working. `test_every_sub_principal_chain_is_emitted_by_something` holds this
file to it.
"""

from __future__ import annotations

import pytest
from app.services.baselines import (
    DERIVED_FIELDS,
    SUB_PRINCIPAL_FIELDS,
    BaselineStore,
    resolve_sub_principals,
)

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"

#: One gateway span, with the field names `ai_gateway.normalize()` emits.
AGENT_EVENT = {
    "agent_id": "release-bot",
    "agent_name": "release-bot",
    "on_behalf_of": "alice@example.com",
    "tool_name": "execute_command",
    "model": "claude-opus-5-5",
    "gateway_key": "release-bot-key",
    "prompt_tokens": 20,
    "completion_tokens": 80,
    "total_tokens": 100,
    "request_cost_usd": 0.02,
    "session_id": "s-1",
    "user": "alice@example.com",
}


class _FakeRedis:
    """Enough Redis for the store, with the counters readable by a test.

    Deliberately a real dict rather than a mock that answers anything: a
    double that returns a plausible value for any key cannot notice a
    baseline keyed on the wrong subject, which is the defect class this
    whole file exists to prevent.
    """

    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, int]] = {}
        self.zsets: dict[str, dict[str, float]] = {}

    async def hincrby(self, key: str, field: str, amount: int) -> int:
        bucket = self.hashes.setdefault(key, {})
        bucket[field] = bucket.get(field, 0) + amount
        return bucket[field]

    async def hget(self, key: str, field: str):
        value = self.hashes.get(key, {}).get(field)
        return None if value is None else str(value)

    async def hlen(self, key: str) -> int:
        return len(self.hashes.get(key, {}))

    async def expire(self, key: str, ttl: int) -> bool:
        return True

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        self.zsets.setdefault(key, {}).update(mapping)
        return len(mapping)

    async def zremrangebyscore(self, key: str, lo: float, hi: float) -> int:
        return 0

    async def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    async def zrangebyscore(self, key: str, lo: float, hi: float):
        return list(self.zsets.get(key, {}))

    async def hgetall(self, key: str):
        return {k: str(v) for k, v in self.hashes.get(key, {}).items()}

    async def hset(self, key: str, field: str | None = None, value=None, *, mapping: dict | None = None):
        """Both call shapes, because the production code uses the positional one.

        The first draft of this double accepted only `mapping=`, so every
        `hset(key, field, value)` raised `TypeError` — which the store's
        fail-soft path swallowed into a `debug` log and returned `None`
        from. The tests then failed with "no spend field", which reads as a
        missing feature rather than as a broken double. A fake less capable
        than the real thing is the mirror of the usual trap and fails in a
        way that blames the code under test.
        """
        bucket = self.hashes.setdefault(key, {})
        if mapping:
            bucket.update(mapping)
        if field is not None:
            bucket[field] = value
        return 1

    async def sadd(self, key: str, member: str) -> int:
        self.hashes.setdefault(f"{key}:set", {})[member] = 1
        return 1

    async def scard(self, key: str) -> int:
        return len(self.hashes.get(f"{key}:set", {}))


@pytest.fixture
def store() -> BaselineStore:
    return BaselineStore(_FakeRedis(), min_observations=1)


# ---------------------------------------------------------------------------
# One mechanism
# ---------------------------------------------------------------------------


def test_the_oauth_application_is_one_sub_principal_kind_among_several():
    """Not a special case in `derived_fields` any more.

    Lane A's 1.4 adds `token` and `service_account` as dict entries. If the
    OAuth app were still hardcoded, those two would each need their own
    block and the module would grow four copies of one idea.
    """
    assert "oauth_app" in SUB_PRINCIPAL_FIELDS
    assert "agent" in SUB_PRINCIPAL_FIELDS
    assert "gateway_key" in SUB_PRINCIPAL_FIELDS


def test_the_published_oauth_field_name_is_unchanged():
    """`baseline_oauth_app_volume_z` is already a published derived field.

    Renaming it as a side effect of generalising would break every rule
    reading it, which is a regression dressed as a refactor.
    """
    assert "baseline_oauth_app_volume_z" in DERIVED_FIELDS


def test_every_sub_principal_chain_is_emitted_by_something():
    """The module's own rule, applied to the new entries.

    A chain naming no emitted field is a signal structurally incapable of
    firing. `agent_id`, `agent_name` and `gateway_key` come from
    `ai_gateway.normalize()` and the `ai-runtime` ingest template; the
    OAuth names were already proven.
    """
    emitted = {
        "agent_id",
        "agent_name",
        "gateway_key",
        "application",
        "applicationName",
        "app_name",
        "client_id",
        "oauth_app",
    }
    for kind, chain in SUB_PRINCIPAL_FIELDS.items():
        assert set(chain) & emitted, f"{kind}: no field in {chain} is emitted by any connector"


def test_a_gateway_span_resolves_to_both_its_agent_and_its_key():
    """One event, two sub-principals, which is the point of the generalisation.

    A compromised key used by a well-behaved agent and a misbehaving agent
    on a normal key are different incidents, and only a baseline per
    subject separates them.
    """
    resolved = dict(resolve_sub_principals(AGENT_EVENT))
    assert resolved["agent"] == "release-bot"
    assert resolved["gateway_key"] == "release-bot-key"


# ---------------------------------------------------------------------------
# The five per-agent baselines depth 6.4 names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "baseline_agent_tool_rarity",
        "baseline_agent_model_rarity",
        "baseline_agent_hour_rarity",
        "baseline_agent_volume_z",
        "baseline_agent_token_spend_z",
        "baseline_gateway_key_token_spend_z",
    ],
)
def test_the_field_is_declared(field: str):
    assert field in DERIVED_FIELDS


async def test_a_new_tool_for_this_agent_is_rarer_than_its_routine_one(store: BaselineStore):
    """The input 7.4's "a *new* high-risk tool" rule needs.

    Rarity is per agent, not global: `execute_command` is routine for a
    deployment bot and alarming for a summariser, and a global count cannot
    tell them apart.
    """
    for _ in range(20):
        await store.derived_fields(TENANT, dict(AGENT_EVENT, tool_name="search_logs"))

    routine = await store.derived_fields(TENANT, dict(AGENT_EVENT, tool_name="search_logs"))
    novel = await store.derived_fields(TENANT, dict(AGENT_EVENT, tool_name="execute_command"))

    assert novel["baseline_agent_tool_rarity"] > routine["baseline_agent_tool_rarity"]


async def test_the_same_tool_on_a_different_agent_is_still_novel(store: BaselineStore):
    """The negative twin: the subject is the agent, not the tool.

    If the counter were keyed on the tool alone, a tool made routine by one
    agent would be scored routine for every agent — which is how a
    compromised agent inherits the estate's good behaviour.

    Both agents are given a history first, because `rarity` deliberately
    scores a first-ever sighting `1 - 1/total`, i.e. `0.0` on a subject
    with no history. A subject nobody has observed is not "maximally
    anomalous", it is unmeasured, and the module refuses to claim more
    confidence than the history supports. Comparing two fresh subjects
    would therefore compare 0.0 with 0.0 and prove nothing.
    """
    for _ in range(20):
        await store.derived_fields(TENANT, dict(AGENT_EVENT, tool_name="execute_command"))
    for _ in range(20):
        await store.derived_fields(TENANT, dict(AGENT_EVENT, agent_id="summariser", agent_name="summariser", tool_name="search_logs"))

    other = await store.derived_fields(
        TENANT, dict(AGENT_EVENT, agent_id="summariser", agent_name="summariser", tool_name="execute_command")
    )
    familiar = await store.derived_fields(TENANT, dict(AGENT_EVENT, tool_name="execute_command"))

    assert other["baseline_agent_tool_rarity"] > familiar["baseline_agent_tool_rarity"]


async def test_token_spend_is_tracked_per_agent_and_per_key(store: BaselineStore):
    """Both subjects from one event, which 7.4 asks for by name.

    A history is fed first, and a *varying* one. Two guards decide whether
    a score exists at all, and both are deliberate: `observe_amount`
    withholds below `MIN_VOLUME_SAMPLES`, and `z_score` refuses a
    distribution whose standard deviation has collapsed to zero. The second
    is the one that bites — feeding the same cost fifteen times produces a
    constant, and a constant has no z-score. Real gateway traffic varies.
    """
    for index in range(15):
        await store.derived_fields(TENANT, dict(AGENT_EVENT, request_cost_usd=0.01 + index * 0.001))

    fields = await store.derived_fields(TENANT, dict(AGENT_EVENT, request_cost_usd=0.02))
    assert "baseline_agent_token_spend_z" in fields
    assert "baseline_gateway_key_token_spend_z" in fields


async def test_a_spend_signal_is_withheld_until_there_is_a_history(store: BaselineStore):
    """The other direction, stated rather than left implicit.

    "Not enough history" and "normal spend" must not look the same. A
    z-score published over three observations would be a confident number
    about nothing, which is the failure mode this repository calls a
    vacuous zero.
    """
    fields = await store.derived_fields(TENANT, AGENT_EVENT)
    assert "baseline_agent_token_spend_z" not in fields


async def test_an_unusually_expensive_request_scores_above_a_routine_one(store: BaselineStore):
    """The signal 7.4's token-spend rule reads.

    Asserted as a comparison between two measured scores rather than
    against a threshold, so it keeps meaning if the floor moves.
    """
    for index in range(20):
        await store.derived_fields(TENANT, dict(AGENT_EVENT, request_cost_usd=0.02 + (index % 5) * 0.002))

    routine = await store.derived_fields(TENANT, dict(AGENT_EVENT, request_cost_usd=0.022))
    spike = await store.derived_fields(TENANT, dict(AGENT_EVENT, request_cost_usd=25.0))

    assert spike["baseline_agent_token_spend_z"] > routine["baseline_agent_token_spend_z"]


async def test_a_perfectly_constant_spender_gets_no_score_rather_than_zero(store: BaselineStore):
    """The module's documented refusal, pinned for the spend path too.

    A batch agent billing the identical amount every run converges on zero
    variance. Returning `0.0` there would make the most automated agent in
    the estate the least suspicious one it is possible to be — which is
    exactly what `z_score`'s docstring says it refuses to do, and this
    asserts the new caller inherits that rather than working around it.
    """
    for _ in range(20):
        await store.derived_fields(TENANT, dict(AGENT_EVENT, request_cost_usd=0.02))

    fields = await store.derived_fields(TENANT, dict(AGENT_EVENT, request_cost_usd=0.02))
    assert "baseline_agent_token_spend_z" not in fields


async def test_an_event_with_no_cost_contributes_no_spend_signal(store: BaselineStore):
    """Unknown is not zero.

    A gateway that did not price a request must not teach the baseline that
    the request was free, because a spend baseline fed zeros learns that
    this agent costs nothing and then flags nothing ever again.
    """
    event = {k: v for k, v in AGENT_EVENT.items() if k != "request_cost_usd"}
    fields = await store.derived_fields(TENANT, event)
    assert "baseline_agent_token_spend_z" not in fields


async def test_an_event_naming_no_agent_produces_no_agent_fields(store: BaselineStore):
    """A baseline with no subject is not a baseline.

    Every ordinary cloud or identity event reaches this module, and none of
    them names an agent. Emitting an agent field for those would make the
    signal meaningless and the Redis key space unbounded.
    """
    fields = await store.derived_fields(TENANT, {"user": "alice@example.com", "action": "GetObject"})
    assert not [f for f in fields if "agent" in f]


async def test_the_hour_of_day_is_baselined_per_agent(store: BaselineStore):
    """ "Hours" in depth 6.4's list.

    An agent that has only ever run inside a nightly window and suddenly
    runs at midday is the signal; a human's working hours are already
    covered by the principal baseline.
    """
    fields = await store.derived_fields(TENANT, AGENT_EVENT)
    assert "baseline_agent_hour_rarity" in fields
