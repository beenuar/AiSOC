"""Item 2.4: templating, per-endpoint profiles, and the three signals."""

from __future__ import annotations

import time

import pytest

from app.services.api_behaviour import (
    DERIVED_FIELDS,
    ApiBehaviourProfiler,
    parse_query,
    template_path,
    value_type,
)


class FakeRedis:
    def __init__(self) -> None:
        self.h: dict[str, dict[str, str]] = {}
        self.s: dict[str, set[str]] = {}
        self.unreachable = False

    def _guard(self) -> None:
        if self.unreachable:
            raise ConnectionError("redis down")

    async def hincrby(self, key: str, field: str, amount: int) -> int:
        self._guard()
        bucket = self.h.setdefault(key, {})
        bucket[field] = str(int(bucket.get(field, "0")) + amount)
        return int(bucket[field])

    async def hset(self, key: str, field: str, value: str) -> int:
        self._guard()
        self.h.setdefault(key, {})[field] = value
        return 1

    async def hgetall(self, key: str) -> dict[str, str]:
        self._guard()
        return dict(self.h.get(key, {}))

    async def sadd(self, key: str, value: str) -> int:
        self._guard()
        self.s.setdefault(key, set()).add(value)
        return 1

    async def scard(self, key: str) -> int:
        self._guard()
        return len(self.s.get(key, ()))

    async def expire(self, key: str, ttl: int) -> bool:
        self._guard()
        return True


def test_templating_replaces_identifiers_and_nothing_else() -> None:
    """Over-templating merges unrelated endpoints; under-templating learns nothing."""
    assert template_path("/api/users/4821/orders")[0] == "/api/users/{id}/orders"
    assert template_path("/api/users/3fa85f64-5717-4562-b3fc-2c963f66afa6")[0] == "/api/users/{id}"
    # Words stay words, however unusual. A segment is replaced because it is
    # an identifier, not because it looks odd.
    assert template_path("/api/admin/settings")[0] == "/api/admin/settings"
    assert template_path("/v2/reports/quarterly-summary")[0] == "/v2/reports/quarterly-summary"
    assert template_path("/api/users/4821")[1] == ["4821"]


def test_value_types_are_coarse_enough_to_be_meaningful() -> None:
    assert value_type("42") == "int"
    assert value_type("true") == "bool"
    assert value_type("' OR 1=1--") == "string"
    assert value_type("") == "empty"


def test_query_parsing_keeps_valueless_parameters() -> None:
    assert parse_query("?a=1&b=&c") == {"a": "1", "b": "", "c": ""}


@pytest.mark.asyncio
async def test_disabled_tenant_does_no_work() -> None:
    redis = FakeRedis()
    redis.unreachable = True  # any Redis call would raise
    profiler = ApiBehaviourProfiler(redis, enabled_for=frozenset())
    assert await profiler.observe("t1", {"http_path": "/api/users/1"}) == []


@pytest.mark.asyncio
async def test_cold_endpoint_reports_no_unknown_parameter() -> None:
    """Every parameter is new on a new endpoint. That is history, not novelty."""
    profiler = ApiBehaviourProfiler(FakeRedis(), enabled_for=frozenset({"t1"}), min_requests=50)
    signals = await profiler.observe("t1", {"http_path": "/api/users/1", "http_query": "?page=1"})
    assert signals == []


@pytest.mark.asyncio
async def test_unknown_parameter_on_a_warm_endpoint() -> None:
    profiler = ApiBehaviourProfiler(FakeRedis(), enabled_for=frozenset({"t1"}), min_requests=5)
    for _ in range(6):
        await profiler.observe("t1", {"http_path": "/api/users/1", "http_query": "?page=1"})
    signals = await profiler.observe("t1", {"http_path": "/api/users/1", "http_query": "?page=1&debug=1"})
    assert [s.kind for s in signals] == ["unknown_parameter"]
    assert signals[0].detail == "debug"
    assert signals[0].template == "GET /api/users/{id}"


@pytest.mark.asyncio
async def test_type_change_on_a_known_parameter() -> None:
    profiler = ApiBehaviourProfiler(FakeRedis(), enabled_for=frozenset({"t1"}), min_requests=5)
    for _ in range(6):
        await profiler.observe("t1", {"http_path": "/api/users/1", "http_query": "?id=7"})
    signals = await profiler.observe("t1", {"http_path": "/api/users/1", "http_query": "?id=' OR 1=1--"})
    assert [s.kind for s in signals] == ["parameter_type_change"]
    assert "int -> string" in signals[0].detail


@pytest.mark.asyncio
async def test_enumeration_across_templated_identifiers() -> None:
    """One client walking many identifiers through one template."""
    from app.services import api_behaviour as module

    original = module.ENUMERATION_THRESHOLD
    module.ENUMERATION_THRESHOLD = 10
    try:
        profiler = ApiBehaviourProfiler(FakeRedis(), enabled_for=frozenset({"t1"}), min_requests=5)
        now = time.time()
        signals: list = []
        for identifier in range(12):
            signals = await profiler.observe(
                "t1", {"http_path": f"/api/users/{identifier}", "src_ip": "203.0.113.5"}, now=now
            )
        kinds = [s.kind for s in signals]
        assert "identifier_enumeration" in kinds
    finally:
        module.ENUMERATION_THRESHOLD = original


@pytest.mark.asyncio
async def test_two_clients_do_not_pool_into_one_walk() -> None:
    """The signal is about one client, so the key must carry the client."""
    from app.services import api_behaviour as module

    original = module.ENUMERATION_THRESHOLD
    module.ENUMERATION_THRESHOLD = 10
    try:
        profiler = ApiBehaviourProfiler(FakeRedis(), enabled_for=frozenset({"t1"}), min_requests=5)
        now = time.time()
        signals: list = []
        for identifier in range(12):
            client = "203.0.113.5" if identifier % 2 else "203.0.113.6"
            signals = await profiler.observe("t1", {"http_path": f"/api/users/{identifier}", "src_ip": client}, now=now)
        assert [s.kind for s in signals if s.kind == "identifier_enumeration"] == []
    finally:
        module.ENUMERATION_THRESHOLD = original


@pytest.mark.asyncio
async def test_unreachable_store_yields_no_signal() -> None:
    redis = FakeRedis()
    profiler = ApiBehaviourProfiler(redis, enabled_for=frozenset({"t1"}), min_requests=1)
    redis.unreachable = True
    assert await profiler.derived_fields("t1", {"http_path": "/api/users/1"}) == {}


def test_derived_field_set_matches_the_gate() -> None:
    import ast
    import pathlib

    gate = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "check_detection_fields.py"
    tree = ast.parse(gate.read_text(encoding="utf-8"))
    pinned: set[str] | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "_API_BEHAVIOUR_DERIVED_FIELDS" for t in node.targets):
            pinned = set(ast.literal_eval(node.value.args[0]))  # type: ignore[attr-defined]
    assert pinned is not None, "the gate no longer pins _API_BEHAVIOUR_DERIVED_FIELDS"
    assert pinned == set(DERIVED_FIELDS)
