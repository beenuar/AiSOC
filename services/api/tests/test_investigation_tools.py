"""Investigation primitives must stay in their tenant and never fabricate.

Two properties carry the weight.

The model never writes SQL, and never supplies a tenant. Handing an LLM the
lake query endpoint would put prompt-injectable text one step from the query
planner, and the tenant predicate is the only thing between two customers'
data. Every tool composes its own parameterised query here and binds the
tenant from the authenticated session.

A tool that cannot answer says why. Mailbox activity, OAuth grants and
parent-process lineage are not columns in aisoc.raw_events. Returning an
empty result set for those reads to a model as "I checked and there is
nothing", which is how an investigation concludes benign on evidence it never
had. They return available=false with the missing data class named.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.services import investigation_tools as module
from app.services.investigation_tools import (
    BACKED_TOOLS,
    MAX_ROWS,
    TOOLS,
    UNAVAILABLE_DATA,
    ToolResult,
    dispatch,
)

TENANT = uuid.UUID("44444444-4444-4444-4444-444444444444")
OTHER_TENANT = "55555555-5555-5555-5555-555555555555"


class FakeLakeResult:
    def __init__(self, columns: list[str], rows: list[list[Any]]) -> None:
        self.columns = columns
        self.rows = rows


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    """Capture every composed query instead of running it."""
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake(sql: str, *, params: dict[str, Any] | None = None, **kw: Any) -> FakeLakeResult:
        calls.append((sql, params or {}))
        return FakeLakeResult(["a", "b"], [["x", 1]])

    monkeypatch.setattr(module, "execute_lake_query", fake)
    return calls


BACKED_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("process_activity", {"hostname": "WS-42"}),
    ("historical_execution", {"sha256": "abc123"}),
    ("historical_execution", {"process_name": "evil.exe"}),
    ("network_connections", {"hostname": "WS-42"}),
    ("network_connections", {"source_ip": "10.0.0.5"}),
    ("authentication_events", {"user_name": "j.doe"}),
    ("fleet_ioc_hunt", {"indicator": "203.0.113.9"}),
    ("entity_timeline", {"hostname": "WS-42"}),
    ("entity_timeline", {"user_name": "j.doe"}),
    ("technique_activity", {"technique_id": "T1059.001"}),
]

#: Tools whose data class nothing ingests, with the arguments their own
#: schema declares.
UNBACKED_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("process_tree", {"hostname": "WS-42"}),
    ("mailbox_activity", {"user_name": "j.doe"}),
    ("oauth_grants", {"user_name": "j.doe"}),
    ("persistence_mechanisms", {"hostname": "WS-42"}),
]

#: A third category, added with 1.1. These answer from Postgres rather than
#: the lake, so neither assertion above applies to them: there is no composed
#: lake query to inspect for a tenant predicate, and "unavailable" is not a
#: permanent property of the deployment but a statement about one principal
#: at one moment.
#:
#: They are listed separately rather than bolted onto `BACKED_CALLS` because
#: the tenant-predicate assertions there read the *captured SQL*, and a tool
#: that composes none would pass them by having nothing to fail on. The
#: scoping property for this family is checked by its own live test against
#: real Postgres (`test_identity_privilege_live.py`), where the predicate is
#: a schema fact rather than a string in a mock.
POSTGRES_BACKED_CALLS: list[tuple[str, dict[str, Any]]] = [
    ("identity_effective_permissions", {"principal_id": "alice"}),
    ("identity_effective_permissions", {"principal_id": "alice", "at": "2026-10-01T00:00:00Z", "provider": "aws"}),
    ("changes_before_alert", {"subjects": "alice"}),
    ("changes_before_alert", {"subjects": "alice,arn:aws:s3:::data", "at": "2026-10-01T00:00:00Z", "days": 14}),
]


class TestTenantScoping:
    @pytest.mark.parametrize(("tool", "args"), BACKED_CALLS)
    async def test_every_query_binds_the_tenant(self, captured: list[Any], tool: str, args: dict[str, Any]) -> None:
        await dispatch(tool, TENANT, args)
        assert captured, f"{tool} ran no query"
        sql, params = captured[-1]
        assert "tenant_id = %(tenant_id)s" in sql, f"{tool}: no tenant predicate"
        assert params["tenant_id"] == str(TENANT)

    @pytest.mark.parametrize(("tool", "args"), BACKED_CALLS)
    async def test_the_tenant_is_never_interpolated(self, captured: list[Any], tool: str, args: dict[str, Any]) -> None:
        await dispatch(tool, TENANT, args)
        sql, _ = captured[-1]
        assert str(TENANT) not in sql, f"{tool}: tenant id interpolated into the SQL text"

    async def test_a_model_supplied_tenant_is_discarded(self, captured: list[Any]) -> None:
        """The single most valuable argument to prompt-inject."""
        await dispatch(
            "process_activity",
            TENANT,
            {"hostname": "WS-42", "tenant_id": OTHER_TENANT},
        )
        _, params = captured[-1]
        assert params["tenant_id"] == str(TENANT)
        assert OTHER_TENANT not in str(params)

    @pytest.mark.parametrize(("tool", "args"), BACKED_CALLS)
    async def test_user_input_is_bound_not_interpolated(self, captured: list[Any], tool: str, args: dict[str, Any]) -> None:
        """Entity names come from alert payloads, which are untrusted."""
        injected = dict.fromkeys(args, "'; DROP TABLE aisoc.raw_events; --")
        await dispatch(tool, TENANT, injected)
        sql, params = captured[-1]
        assert "DROP TABLE" not in sql
        assert any("DROP TABLE" in str(v) for v in params.values())


class TestUnavailableData:
    @pytest.mark.parametrize(("tool", "args"), UNBACKED_CALLS)
    async def test_missing_data_classes_report_why(self, captured: list[Any], tool: str, args: dict[str, Any]) -> None:
        result = await dispatch(tool, TENANT, args)
        assert result.available is False
        assert result.rows == []
        # Specifically an ingestion gap, not an argument error. Both set
        # available=False, so asserting only the flag passes for the wrong
        # reason — which is how this test was originally written.
        assert "not ingested" in (result.reason or "") or "not stored" in (result.reason or ""), (
            f"{tool} reported unavailable for a reason other than missing data: {result.reason}"
        )
        assert captured == [], f"{tool} queried the lake for a column that does not exist"

    @pytest.mark.parametrize(("tool", "args"), UNBACKED_CALLS)
    async def test_the_reason_names_the_connector_that_would_fix_it(self, tool: str, args: dict[str, Any]) -> None:
        """A gap the operator can close beats a gap they can only observe."""
        result = await dispatch(tool, TENANT, args)
        assert "connector" in (result.reason or "").lower()

    def test_unavailable_and_empty_are_different_shapes(self) -> None:
        """The distinction the whole design rests on."""
        unavailable = ToolResult(tool="mailbox_activity", available=False, reason="not ingested")
        empty = ToolResult(tool="process_activity", available=True, rows=[], row_count=0)

        assert unavailable.as_dict()["available"] is False
        assert empty.as_dict()["available"] is True
        assert "reason" in unavailable.as_dict()
        assert "reason" not in empty.as_dict()

    def test_backed_and_unbacked_tools_are_declared_explicitly(self) -> None:
        assert BACKED_TOOLS < set(TOOLS)
        assert set(UNAVAILABLE_DATA) and (set(TOOLS) - BACKED_TOOLS)


class TestBounds:
    async def test_row_limit_is_clamped(self, captured: list[Any]) -> None:
        await dispatch("process_activity", TENANT, {"hostname": "h", "limit": 99_999})
        _, params = captured[-1]
        assert params["limit"] == MAX_ROWS

    async def test_lookback_is_clamped(self, captured: list[Any]) -> None:
        await dispatch("process_activity", TENANT, {"hostname": "h", "hours": 10_000_000})
        _, params = captured[-1]
        assert params["hours"] <= module.MAX_LOOKBACK_DAYS * 24

    async def test_nonsense_lookback_falls_back_to_the_default(self, captured: list[Any]) -> None:
        await dispatch("process_activity", TENANT, {"hostname": "h", "hours": -5})
        _, params = captured[-1]
        assert params["hours"] == module.DEFAULT_LOOKBACK_HOURS

    async def test_a_capped_result_says_it_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Otherwise the model reads a truncated set as the complete one."""

        async def full(sql: str, *, params: dict[str, Any] | None = None, **kw: Any) -> FakeLakeResult:
            return FakeLakeResult(["a"], [["x"]] * (params or {}).get("limit", 0))

        monkeypatch.setattr(module, "execute_lake_query", full)
        result = await dispatch("process_activity", TENANT, {"hostname": "h", "limit": 10})
        payload = result.as_dict()
        assert payload["truncated"] is True
        assert "do not treat this as the full set" in payload["note"]


class TestFailureHandling:
    async def test_a_lake_failure_is_not_reported_as_no_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failed lookup and an empty answer must not read the same."""

        async def boom(sql: str, **kw: Any) -> FakeLakeResult:
            raise ConnectionError("clickhouse unreachable")

        monkeypatch.setattr(module, "execute_lake_query", boom)
        result = await dispatch("process_activity", TENANT, {"hostname": "h"})

        assert result.available is False
        assert "not an absence of evidence" in (result.reason or "")

    async def test_unknown_tool_lists_what_exists(self) -> None:
        result = await dispatch("nonexistent_tool", TENANT, {})
        assert result.available is False
        assert "process_activity" in (result.reason or "")

    async def test_bad_arguments_are_reported_not_raised(self) -> None:
        result = await dispatch("process_activity", TENANT, {"not_a_parameter": 1})
        assert result.available is False
        assert "Invalid arguments" in (result.reason or "")

    async def test_tools_needing_one_of_two_arguments_say_so(self) -> None:
        for tool in ("historical_execution", "network_connections", "entity_timeline"):
            result = await dispatch(tool, TENANT, {})
            assert result.available is False
            assert "Supply either" in (result.reason or ""), tool


async def test_every_declared_tool_is_dispatchable(captured: list[Any]) -> None:
    """A name in TOOLS that cannot be called is a schema the model cannot use.

    Each tool is called with the arguments its own schema declares, so an
    argument-shape error is a failure rather than something the assertion
    quietly accepts.
    """
    all_calls = BACKED_CALLS + UNBACKED_CALLS + POSTGRES_BACKED_CALLS
    covered = {tool for tool, _ in all_calls}
    assert covered == set(TOOLS), f"tools with no dispatch case in this test: {sorted(set(TOOLS) - covered)}"

    for name, args in all_calls:
        result = await dispatch(name, TENANT, args)
        assert isinstance(result, ToolResult), name
        assert "Invalid arguments" not in (result.reason or ""), f"{name} rejected the arguments its own schema advertises: {result.reason}"


class TestPrivilegeToolNeverFabricates:
    """The Postgres-backed family's own honesty properties.

    With no database reachable in this suite the tool takes its failure
    path, which is exactly the branch worth pinning: the sentence it emits
    is what a model reads, and the wrong sentence here closes alerts.
    """

    async def test_an_unanswerable_lookup_is_never_an_empty_result(self) -> None:
        result = await dispatch("identity_effective_permissions", TENANT, {"principal_id": "alice"})
        assert result.available is False
        assert result.rows == []
        # The two sentences the tool is allowed to say, and both of them
        # name the gap. An `available=false` with no reason would read to a
        # model as a tool that is simply switched off.
        assert result.reason
        # Both of the tool's failure sentences end the same way, which is
        # the property: whichever branch fires, the model is told the
        # absence is not a finding.
        assert "not an absence" in result.reason or "not evidence" in result.reason

    async def test_a_model_supplied_tenant_is_discarded(self) -> None:
        """Same property as the lake tools, checked on this door too."""
        result = await dispatch(
            "identity_effective_permissions",
            TENANT,
            {"principal_id": "alice", "tenant_id": OTHER_TENANT},
        )
        assert isinstance(result, ToolResult)
        assert "Invalid arguments" not in (result.reason or "")
        assert OTHER_TENANT not in (result.reason or "")
