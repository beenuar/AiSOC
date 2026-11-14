"""Gap-closure Phase 8.3: the API half of the hunting agent.

``services/agents`` decides what a model may *propose*. This decides what that
proposal *becomes*, and it is the only half that runs on the path reaching the
warehouse. The compiler says so itself: a boundary enforced only on the far
side of a network hop is not a boundary. So the agents-side suite proving the
vocabulary is closed proves nothing about this file, and these tests exist
because that suite passing is not evidence this one is safe.

``scripts/check_hunt_agent_boundary.py`` reads both files as source and fails
when the vocabularies drift or when a predicate interpolates a value. It
cannot tell whether the statement the compiler *runs* scopes to a tenant, puts
every model-supplied byte in a parameter, or reports an unreachable lake as a
gap rather than as zero sightings. Those are behaviours, and they are here.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import agent_tools
from app.services.retro_hunt.hunt_plan_sql import (
    LAKE_TABLE,
    MAX_ROWS,
    HuntPlanCompileError,
    compile_plan,
)
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = "22222222-2222-2222-2222-222222222222"
USER = uuid.UUID("33333333-3333-3333-3333-333333333333")


def _clause(field: str, operator: str, value: str) -> dict[str, str]:
    return {"field": field, "operator": operator, "value": value}


# ------------------------------------------------------------ tenant scoping


def test_the_tenant_predicate_is_generated_and_bound() -> None:
    """Structural, not rewritten in afterwards, and never interpolated.

    ``rewrite_for_tenant`` constrains SQL an operator wrote and cannot help a
    caller who forgets to call it, which is how every fresh tenant once read
    the same global figures off the funnel.
    """
    compiled = compile_plan([_clause("user_name", "eq", "svc_deploy")], tenant_id=str(TENANT))
    assert "tenant_id = %(tenant_id)s" in compiled.sql
    assert compiled.params["tenant_id"] == str(TENANT)
    assert str(TENANT) not in compiled.sql


def test_a_window_predicate_is_always_present() -> None:
    """A plan with no time bound is a full-history scan nobody budgeted for."""
    compiled = compile_plan([_clause("user_name", "eq", "a")], tenant_id=str(TENANT))
    assert "event_time >= now() - INTERVAL %(hours)s HOUR" in compiled.sql
    assert compiled.params["hours"] == 168


# ------------------------------------------------------- values stay values


@pytest.mark.parametrize(
    "hostile",
    [
        "'; DROP TABLE aisoc.raw_events; --",
        "a' OR 1=1 --",
        "\\' UNION ALL SELECT tenant_id FROM aisoc.raw_events --",
        "%(tenant_id)s",
    ],
)
def test_a_value_shaped_like_sql_travels_as_a_parameter(hostile: str) -> None:
    """The value is the one thing a model fully controls.

    A hypothesis can be lifted from an advisory or a customer email, so the
    string reaching this function is attacker-influenceable even when the
    field and operator are not.
    """
    compiled = compile_plan([_clause("user_name", "eq", hostile)], tenant_id=str(TENANT))
    benign = compile_plan([_clause("user_name", "eq", "benign")], tenant_id=str(TENANT))
    # Compared against a benign compile rather than asserting the value is
    # simply absent from the SQL: one of these payloads is `%(tenant_id)s`,
    # which the compiler legitimately emits for its own tenant binding, so a
    # bare `not in` would fail on a string the compiler put there itself.
    # Identical SQL is the stronger claim anyway — whatever the value is, it
    # does not reach the statement at all, only the parameter map.
    assert compiled.sql == benign.sql
    assert compiled.params["c0"] == hostile


def test_every_clause_gets_its_own_placeholder() -> None:
    compiled = compile_plan(
        [
            _clause("user_name", "eq", "svc_deploy"),
            _clause("process_name", "eq", "powershell.exe"),
            _clause("dst_port", "gte", "1024"),
        ],
        tenant_id=str(TENANT),
    )
    assert compiled.params["c0"] == "svc_deploy"
    assert compiled.params["c1"] == "powershell.exe"
    assert compiled.params["c2"] == 1024
    assert compiled.fields_searched == ("user_name", "process_name", "dst_port")


def test_contains_cannot_smuggle_a_wildcard() -> None:
    """``position`` rather than ``LIKE``.

    Under a ``LIKE`` a model-supplied ``%`` is a wildcard the analyst never
    asked for, and the scan it provokes is charged to the customer.
    """
    compiled = compile_plan([_clause("file_path", "contains", "%secret%")], tenant_id=str(TENANT))
    assert "position(file_path, %(c0)s) > 0" in compiled.sql
    assert "LIKE" not in compiled.sql.upper()
    assert compiled.params["c0"] == "%secret%"


def test_an_address_is_normalised_the_way_the_writer_stored_it() -> None:
    """The lake holds an IPv4 address in its IPv4-mapped form.

    Comparing the needle as text matches nothing, which reads as "not present"
    rather than as "compared wrongly".
    """
    compiled = compile_plan([_clause("source_ip", "eq", "203.0.113.9")], tenant_id=str(TENANT))
    assert "source_ip = toIPv6(%(c0)s)" in compiled.sql
    assert compiled.params["c0"] == "203.0.113.9"


def test_a_numeric_field_binds_a_number_rather_than_its_text() -> None:
    compiled = compile_plan([_clause("severity_id", "gte", "4")], tenant_id=str(TENANT))
    assert compiled.params["c0"] == 4
    assert compiled.params["c0"] != "4"


# ------------------------------------------------------------- what it refuses


def test_a_field_outside_the_vocabulary_is_refused() -> None:
    with pytest.raises(HuntPlanCompileError, match="raw_payload"):
        compile_plan([_clause("raw_payload", "eq", "x")], tenant_id=str(TENANT))


def test_an_operator_outside_the_vocabulary_is_refused() -> None:
    with pytest.raises(HuntPlanCompileError, match="regex"):
        compile_plan([_clause("user_name", "regex", ".*")], tenant_id=str(TENANT))


def test_the_compiler_refuses_independently_of_the_agent_side_validator() -> None:
    """A clause the agents-side validator would have caught still gets caught.

    The agents service cannot import this module and this module cannot import
    it, so the two checks are genuinely independent. That is the point: a
    caller reaching this route directly with a credential is not going through
    the validator at all.
    """
    with pytest.raises(HuntPlanCompileError):
        compile_plan([_clause("mitre_techniques", "contains", "T1059")], tenant_id=str(TENANT))
    with pytest.raises(HuntPlanCompileError):
        compile_plan([_clause("source_ip", "starts_with", "203.")], tenant_id=str(TENANT))


def test_a_plan_with_no_clauses_is_refused_rather_than_matching_the_window() -> None:
    with pytest.raises(HuntPlanCompileError, match="whole window"):
        compile_plan([], tenant_id=str(TENANT))


def test_a_numeric_field_refuses_a_value_it_cannot_hold() -> None:
    with pytest.raises(HuntPlanCompileError, match="not a number"):
        compile_plan([_clause("dst_port", "eq", "eighty")], tenant_id=str(TENANT))


# -------------------------------------------------------------------- bounds


def test_the_row_cap_and_the_window_are_clamped_rather_than_trusted() -> None:
    compiled = compile_plan(
        [_clause("user_name", "eq", "a")],
        tenant_id=str(TENANT),
        lookback_hours=99_999,
        limit=10_000,
    )
    assert f"LIMIT {MAX_ROWS}" in compiled.sql
    assert compiled.params["hours"] == 2160


def test_the_projection_is_explicit() -> None:
    """Never ``SELECT *``.

    It bounds warehouse cost, and it bounds how much connector-supplied text
    reaches a prompt, which is the half that matters here.
    """
    compiled = compile_plan([_clause("user_name", "eq", "a")], tenant_id=str(TENANT))
    assert "SELECT *" not in compiled.sql
    assert compiled.sql.startswith("SELECT event_time,")
    assert f"FROM {LAKE_TABLE}" in compiled.sql


# --------------------------------------------------------------------- route


class _Result:
    def __init__(self, columns: list[str], rows: list[tuple[Any, ...]]) -> None:
        self.columns = columns
        self.rows = rows


def _app(user: CurrentUser | None = None) -> FastAPI:
    app = FastAPI()
    # `/api/v1` only: the router already declares `prefix="/agent-tools"`, so
    # repeating it here mounted everything a level deeper than production and
    # every request in this file 404'd. This mirrors what router.py does.
    app.include_router(agent_tools.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user or _agent_user()
    return app


def _agent_user() -> CurrentUser:
    return CurrentUser(
        user_id=USER,
        tenant_id=TENANT,
        role="analyst",
        email="agent@example.invalid",
        scopes=["lake:query"],
    )


def test_the_tenant_comes_from_the_credential_and_not_from_the_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """There is no tenant field on the request model, and a smuggled one is dropped.

    ``additionalProperties`` is not the control here; the control is that the
    only tenant this route can reach is the one the credential resolved.
    """
    seen: dict[str, Any] = {}

    async def _fake(sql: str, **kwargs: Any) -> _Result:
        seen["sql"] = sql
        seen["params"] = kwargs.get("params")
        return _Result(["event_time"], [])

    monkeypatch.setattr(agent_tools, "execute_lake_query", _fake)
    response = TestClient(_app()).post(
        "/api/v1/agent-tools/hunt-plan/execute",
        json={
            "clauses": [_clause("user_name", "eq", "svc_deploy")],
            "tenant_id": OTHER_TENANT,
        },
    )

    assert response.status_code == 200
    assert seen["params"]["tenant_id"] == str(TENANT)
    assert OTHER_TENANT not in seen["sql"]
    assert OTHER_TENANT not in str(seen["params"])


def test_a_refused_clause_is_a_422_with_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not an empty result.

    A model that reads "your clause was wrong" as "nothing matched" reports an
    estate clean on a question nobody asked the warehouse.
    """

    async def _never(*_args: Any, **_kwargs: Any) -> _Result:
        raise AssertionError("the lake must not be queried when the plan was refused")

    monkeypatch.setattr(agent_tools, "execute_lake_query", _never)
    response = TestClient(_app()).post(
        "/api/v1/agent-tools/hunt-plan/execute",
        json={"clauses": [_clause("raw_payload", "eq", "x")]},
    )

    assert response.status_code == 422
    assert "raw_payload" in response.json()["detail"]


@pytest.mark.parametrize(
    ("raised", "because"),
    [
        (agent_tools.LakeQueryNotConfiguredError, "No event lake is configured"),
        (agent_tools.LakeQueryTimeoutError, "time budget"),
        (agent_tools.LakeQueryError, "refused or failed"),
    ],
)
def test_a_lake_that_could_not_answer_is_a_gap_and_not_zero_findings(
    monkeypatch: pytest.MonkeyPatch,
    raised: type[Exception],
    because: str,
) -> None:
    """Three outcomes, kept apart: findings, no findings, could not check.

    The response carries no ``rows`` key at all in this branch, so a caller
    reading ``rows`` without checking ``available`` gets a KeyError rather
    than an empty list it would report as a clean estate.
    """

    async def _fail(*_args: Any, **_kwargs: Any) -> _Result:
        raise raised("boom")

    monkeypatch.setattr(agent_tools, "execute_lake_query", _fail)
    body = (
        TestClient(_app())
        .post(
            "/api/v1/agent-tools/hunt-plan/execute",
            json={"clauses": [_clause("user_name", "eq", "a")]},
        )
        .json()
    )

    assert body["available"] is False
    assert because in body["reason"]
    assert "NOT" in body["reason"]
    assert "rows" not in body


def test_rows_come_back_keyed_by_the_projection(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _rows(*_args: Any, **_kwargs: Any) -> _Result:
        return _Result(["event_time", "user_name"], [("2026-09-01T00:00:00Z", "svc_deploy")])

    monkeypatch.setattr(agent_tools, "execute_lake_query", _rows)
    body = (
        TestClient(_app())
        .post(
            "/api/v1/agent-tools/hunt-plan/execute",
            json={"clauses": [_clause("user_name", "eq", "svc_deploy")]},
        )
        .json()
    )

    assert body["available"] is True
    assert body["row_count"] == 1
    assert body["rows"] == [{"event_time": "2026-09-01T00:00:00Z", "user_name": "svc_deploy"}]
    assert body["fields_searched"] == ["user_name"]
    assert body["truncated"] is False


def test_a_full_page_is_reported_as_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Otherwise a capped hunt reads as an exhaustive one."""

    async def _rows(*_args: Any, **_kwargs: Any) -> _Result:
        return _Result(["user_name"], [("u",), ("v",)])

    monkeypatch.setattr(agent_tools, "execute_lake_query", _rows)
    body = (
        TestClient(_app())
        .post(
            "/api/v1/agent-tools/hunt-plan/execute",
            json={"clauses": [_clause("user_name", "eq", "u")], "limit": 2},
        )
        .json()
    )

    assert body["truncated"] is True


def test_the_route_refuses_a_caller_without_the_lake_permission() -> None:
    """``lake:query``, the permission the operator-facing lake API already uses."""
    unscoped = CurrentUser(
        user_id=USER,
        tenant_id=TENANT,
        role="analyst",
        email="agent@example.invalid",
        scopes=["alerts:read"],
    )
    response = TestClient(_app(unscoped)).post(
        "/api/v1/agent-tools/hunt-plan/execute",
        json={"clauses": [_clause("user_name", "eq", "a")]},
    )

    assert response.status_code == 403
