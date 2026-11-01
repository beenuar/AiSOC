"""`/nl-query/execute` must report the query it actually sent.

Wave 2, Phase 5.3.

The console could only ever show the ES|QL translation, and for a lake
execution that is **not what ran**: the lake speaks SQL and the question is
compiled separately by `app.services.lake_hunt.compile_hunt`. Showing ES|QL
beside lake rows is a query that did not produce them — an analyst checking
whether their question was understood would be reading the wrong artefact.

Two properties are asserted, and both are about what a reader can trust:

* the response carries the text that was sent and says which language it is
  in, so "the query" is never ambiguous between two of them;
* bound values stay **out** of that text. The compiler binds rather than
  interpolates, and rendering an interpolated string would both misreport
  what ran and re-introduce string-building in a display path.

These call `_execute_against_lake` rather than reading its source. The
recorded failure here is a test that substitutes `inspect.getsource` plus a
substring assertion for calling the handler: it can never notice that the
code does not run, which is the very family this phase keeps finding. The
two collaborators the function reaches out to — the compiler and the lake
client — are substituted, so the assertion is about what the function does
with their answers.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from app.api.v1.endpoints import nl_query


@dataclass
class _Compiled:
    sql: str
    params: dict[str, Any]
    unsupported_fields: list[str]


@dataclass
class _LakeRows:
    """Mirrors what `execute_lake_query` really returns.

    `row_count` and `elapsed_ms` are both read by the handler. A double
    missing either one fails loudly here, which is the right direction — a
    double that is *more* forgiving than the real object is the recorded
    trap, and one that quietly supplies a default would hide a field the
    handler depends on.
    """

    columns: list[str]
    rows: list[list[Any]]
    row_count: int = 0
    elapsed_ms: int = 11


@dataclass
class _Translated:
    esql: str = 'FROM logs-* | WHERE severity == "critical" | LIMIT 10'
    spl: str = ""
    kql: str = ""
    explanation: str = ""
    intents: Any = None


@dataclass
class _User:
    tenant_id: uuid.UUID


@dataclass
class _Body:
    time_range_hours: int = 24
    max_rows: int = 500


def _base() -> nl_query.NLQueryExecuteResponse:
    return nl_query.NLQueryExecuteResponse(
        request_id=uuid.uuid4(),
        question="show critical events",
        esql=_Translated().esql,
        spl="",
        kql="",
        explanation="",
        created_at=datetime.now(UTC),
    )


SQL = "SELECT event_time, severity FROM aisoc.raw_events WHERE tenant_id = {tenant:String} LIMIT {limit:UInt32}"
PARAMS = {"tenant": "aaaaaaaa-0000-0000-0000-000000000001", "limit": 500}


def test_a_fresh_response_discloses_nothing_rather_than_guessing():
    """No store reached means no query to show, not an empty string.

    `None` and `""` read differently on the page: one says nothing was sent,
    the other looks like a query that was sent and happened to be blank.
    """
    response = _base()
    assert response.executed_query is None
    assert response.executed_query_language is None
    assert response.executed_query_params == {}
    assert response.executed_against is None


@pytest.mark.asyncio
async def test_the_lake_path_discloses_compiled_sql_not_the_esql(monkeypatch: pytest.MonkeyPatch):
    translated = _Translated()
    monkeypatch.setattr(
        nl_query,
        "compile_hunt",
        lambda *a, **k: _Compiled(sql=SQL, params=dict(PARAMS), unsupported_fields=[]),
    )

    async def _rows(sql, params=None):
        return _LakeRows(columns=["event_time", "severity"], rows=[["t", "critical"]], row_count=1)

    monkeypatch.setattr(nl_query, "execute_lake_query", _rows)

    out = await nl_query._execute_against_lake(_base(), translated, _Body(), _User(tenant_id=uuid.UUID(PARAMS["tenant"])))

    assert out.executed_against == "lake"
    assert out.executed_query == SQL
    assert out.executed_query_language == "sql"
    assert out.executed_query_params == PARAMS
    # The ES|QL is a different query and did not produce these rows.
    assert out.executed_query != translated.esql


@pytest.mark.asyncio
async def test_bound_values_are_not_inside_the_disclosed_text(monkeypatch: pytest.MonkeyPatch):
    """The point of binding, preserved on the display path."""
    monkeypatch.setattr(
        nl_query,
        "compile_hunt",
        lambda *a, **k: _Compiled(sql=SQL, params=dict(PARAMS), unsupported_fields=[]),
    )

    async def _rows(sql, params=None):
        return _LakeRows(columns=[], rows=[])

    monkeypatch.setattr(nl_query, "execute_lake_query", _rows)

    out = await nl_query._execute_against_lake(_base(), _Translated(), _Body(), _User(tenant_id=uuid.UUID(PARAMS["tenant"])))
    assert PARAMS["tenant"] not in (out.executed_query or "")
    assert out.executed_query_params["tenant"] == PARAMS["tenant"]


@pytest.mark.asyncio
async def test_a_failed_query_is_still_disclosed(monkeypatch: pytest.MonkeyPatch):
    """The query that errored is exactly the one worth reading.

    Recording the disclosure only after a successful run would leave the
    error state with no query at all — the state an analyst is debugging.
    """
    monkeypatch.setattr(
        nl_query,
        "compile_hunt",
        lambda *a, **k: _Compiled(sql=SQL, params=dict(PARAMS), unsupported_fields=[]),
    )

    async def _boom(sql, params=None):
        raise RuntimeError("lake unreachable")

    monkeypatch.setattr(nl_query, "execute_lake_query", _boom)

    out = await nl_query._execute_against_lake(_base(), _Translated(), _Body(), _User(tenant_id=uuid.UUID(PARAMS["tenant"])))
    assert out.result is None
    assert out.execution_error
    assert out.executed_query == SQL


@pytest.mark.asyncio
async def test_unsupported_filters_are_reported(monkeypatch: pytest.MonkeyPatch):
    """Dropped filters widen the result, so silence is the wrong default."""
    monkeypatch.setattr(
        nl_query,
        "compile_hunt",
        lambda *a, **k: _Compiled(sql=SQL, params=dict(PARAMS), unsupported_fields=["process.name"]),
    )

    async def _rows(sql, params=None):
        return _LakeRows(columns=[], rows=[])

    monkeypatch.setattr(nl_query, "execute_lake_query", _rows)

    out = await nl_query._execute_against_lake(_base(), _Translated(), _Body(), _User(tenant_id=uuid.UUID(PARAMS["tenant"])))
    assert out.unsupported_filters == ["process.name"]
