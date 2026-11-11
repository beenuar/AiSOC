"""Negative controls for caller-scoped, bounded Copilot data access."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from types import SimpleNamespace

import httpx
import pytest
from app.llm import contract
from app.llm.tool_loop import run_with_tools
from app.security.agent_identity import issue_identity
from app.tools.copilot import MAX_EVIDENCE_BYTES, MAX_RESPONSE_BYTES, CopilotReads
from langchain_core.messages import AIMessage

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000111")
RECORD = "00000000-0000-0000-0000-000000000222"


@pytest.fixture
def http(monkeypatch):
    calls = []
    answer = {"response": httpx.Response(200, json={"items": [], "total": 0})}

    async def handle(req):
        calls.append(req)
        value = answer["response"]
        if isinstance(value, Exception):
            raise value
        return value

    real = httpx.AsyncClient

    class Client(real):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("transport", httpx.MockTransport(handle))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    monkeypatch.setenv("AISOC_API_URL", "http://api.test")
    return calls, answer


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 401, 403, 404, 429, 500, 503])
async def test_refusal_is_not_an_empty_success_or_a_citation(http, status):
    calls, answer = http
    answer["response"] = httpx.Response(status, headers={"Location": "https://attacker.invalid"}, text="SECRET must not enter model")
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await reads.record("alert", RECORD)
    assert result["available"] is False
    assert "SECRET" not in json.dumps(result)
    assert reads.sources == []
    assert reads.calls[0]["status"] == "could_not_check"
    assert len(calls) == 1, "redirect must not receive the bearer"
    assert calls[0].headers["authorization"] == "Bearer analyst-token"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not JSON"),
        httpx.Response(200, json=[]),
        httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)),
        httpx.ReadTimeout("SECRET from an upstream connection"),
    ],
)
async def test_transport_and_schema_failures_remain_unknown(http, response):
    _, answer = http
    answer["response"] = response
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await reads.alerts()
    assert result["available"] is False
    assert not reads.sources
    assert "SECRET" not in json.dumps(result)


@pytest.mark.asyncio
async def test_missing_caller_never_falls_back_to_deployment_credentials(http, monkeypatch):
    calls, _ = http
    monkeypatch.setenv("AISOC_AGENTS_API_KEY", "privileged-service-credential")
    result = await CopilotReads(None, TENANT).alerts()
    assert result["available"] is False
    assert not calls


@pytest.mark.asyncio
async def test_pagination_has_one_fixed_event_time_window_and_explicit_coverage(http):
    calls, answer = http
    answer["response"] = httpx.Response(200, json={"items": [{"id": RECORD, "title": "signal"}], "total": 21})
    reads = CopilotReads("Bearer analyst-token", TENANT)
    first = await reads.alerts(hours=72, hostname="WS-42", severity="high")
    await reads.alerts(hours=72, hostname="WS-42", severity="high", page=2)
    assert first["next_page"] == 2
    assert first["window"]["field"] == "event_time"
    since = calls[0].url.params["event_since"]
    until = calls[0].url.params["event_until"]
    assert (datetime.fromisoformat(until) - datetime.fromisoformat(since)).total_seconds() == 72 * 3600
    assert calls[1].url.params["event_since"] == since
    assert calls[1].url.params["event_until"] == until
    assert calls[0].url.params["hostname"] == "WS-42"
    assert "upstream" in first["coverage"]
    assert len(reads.sources) == 2


@pytest.mark.asyncio
async def test_actual_empty_result_is_a_success_not_an_outage(http):
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await reads.alerts()
    assert result["available"] is True and result["records"] == []
    assert reads.calls[0]["status"] == "ok"


@pytest.mark.asyncio
async def test_risk_is_filtered_sorted_and_bounded_not_claimed_fleet_complete(http):
    _, answer = http
    answer["response"] = httpx.Response(
        200,
        json={
            "entities": [
                {"entity_type": "host", "entity_value": "WS-low", "score": 1},
                {"entity_type": "user", "entity_value": "user", "score": 100},
                {"entity_type": "host", "entity_value": "WS-high", "score": 40, "contributing_alerts": [RECORD]},
            ]
        },
    )
    reads = CopilotReads("Bearer analyst-token", TENANT)
    result = await reads.entity_risk()
    assert [r["entity_value"] for r in result["records"]] == ["WS-high", "WS-low"]
    assert "top 200" in result["coverage"]
    assert result["records"][0]["contributing_alerts"] == [RECORD]


@pytest.mark.asyncio
async def test_unregistered_paths_tenants_and_writes_cannot_be_model_arguments(http):
    calls, _ = http
    registry = CopilotReads("Bearer analyst-token", TENANT).registry()
    identity = issue_identity("copilot", run_id="r")
    for name, args in [
        ("copilot_alerts", {"tenant_id": str(uuid.uuid4())}),
        ("copilot_record", {"kind": "alert", "record_id": "../../secrets"}),
        ("copilot_alerts", {"url": "https://attacker.invalid"}),
        ("isolate_host", {"hostname": "WS-42"}),
        ("copilot_alerts", {"hours": 1000000}),
    ]:
        result = await registry.execute(name, args, identity=identity)
        assert "error" in result or result.get("available") is False
    assert not calls


def test_evidence_budget_is_cumulative_and_citations_use_only_retained_fields():
    reads = CopilotReads()
    result = reads._records(
        "copilot_alerts",
        "alert",
        [{"id": str(uuid.uuid4()), "title": "x" * 2000, "description": "y" * 2000, "not_projected": "203.0.113.99"} for _ in range(20)],
    )
    assert result["truncated"] is True
    assert reads._evidence_bytes <= MAX_EVIDENCE_BYTES
    assert all("203.0.113.99" not in source.text for source in reads.sources)
    before = reads._evidence_bytes
    reads._records("copilot_alerts", "alert", [{"id": RECORD, "title": "x" * 2000}])
    assert before <= reads._evidence_bytes <= MAX_EVIDENCE_BYTES


@pytest.mark.asyncio
async def test_tool_budget_never_publishes_raw_evidence_as_a_final_answer():
    class Model:
        def bind_tools(self, tools):
            return self

        async def ainvoke(self, messages):
            return SimpleNamespace(content="", tool_calls=[{"name": "copilot_alerts", "args": {}, "id": "t"}] * 10)

    reads = CopilotReads()
    result = await run_with_tools(
        Model(),
        system="s",
        user="u",
        registry=reads.registry(),
        identity=issue_identity("copilot", run_id="r"),
        max_iters=4,
        max_tool_calls=2,
    )
    assert result["truncated"] is True
    assert result["content"] == ""
    assert len(reads.calls) == 2


@pytest.mark.asyncio
async def test_bound_tools_do_not_use_the_text_only_response_cache(monkeypatch):
    class Cache:
        def lookup(self, **kwargs):
            pytest.fail("a cached text answer would discard the required tool call")

        def store(self, **kwargs):
            pytest.fail("structured tool calls cannot be stored as text")

    monkeypatch.setattr(contract, "_RESPONSE_CACHE_ENABLED", True)
    monkeypatch.setattr(contract, "_RESPONSE_CACHE", Cache())

    class Bound:
        model_name = "test-model"
        kwargs = {"tools": [{"type": "function"}]}

        async def ainvoke(self, messages):
            return AIMessage(content="Looking up evidence.", tool_calls=[{"name": "copilot_alerts", "args": {}, "id": "c"}])

    from langchain_core.messages import HumanMessage

    result = await contract.safe_ainvoke(Bound(), [HumanMessage(content="Read my alerts.")])
    assert result.tool_calls


def test_failed_completion_does_not_deny_that_partial_reads_happened():
    from app.api.copilot import CALL_FAILED, _fallback_reply

    reply = _fallback_reply(CALL_FAILED, model="aisoc-copilot", detail="tool-call budget reached")
    assert "was looked at" not in reply
    assert "completed reads are listed separately" in reply
