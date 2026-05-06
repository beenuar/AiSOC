"""
Tests for the federated-search layer (``app.federated``).

These run as the eval-harness scenario for the ``w3-fed`` capability:
the unified-query model and its three translators (SPL/KQL/ES|QL) all
need to round-trip a representative query into syntactically
plausible backend strings, and the ``ElasticConnector.query()`` method
needs to flatten an ES|QL ``columns``/``values`` response shape into
plain dicts that the merging layer in ``services/api`` can consume.

We don't talk to a real Splunk/Sentinel/Elastic here — the goal is to
prove that the translation surface is safe (no operator silently
dropped, no value silently un-quoted) and that the connector glue
correctly assembles the request and parses the response. End-to-end
backend smoke tests live with the integration suite.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.elastic import ElasticConnector
from app.connectors.microsoft_sentinel import MicrosoftSentinelConnector
from app.connectors.splunk import SplunkConnector
from app.federated.query import (
    Indicator,
    QueryError,
    UnifiedQuery,
    parse_unified_query,
)
from app.federated.translators import to_esql, to_kql, to_spl

# ------------------------------------------------------------------ query model


def test_parse_unified_query_accepts_minimal_payload():
    q = parse_unified_query({"free_text": "lateral movement"})
    assert q.free_text == "lateral movement"
    assert q.indicators == ()
    # Defaults from the contract.
    assert q.since_seconds == 3600
    assert q.limit == 100


def test_parse_unified_query_accepts_indicators_alias():
    # ``filters`` is the legacy key; the model accepts either name.
    q = parse_unified_query(
        {
            "filters": [
                {"field": "user.name", "operator": "eq", "value": "alice"},
                {"field": "src_ip", "operator": "eq", "value": "10.0.0.5"},
            ]
        }
    )
    assert len(q.indicators) == 2
    assert q.indicators[0].field == "user.name"
    assert q.indicators[1].operator == "eq"


def test_parse_unified_query_rejects_non_object_payload():
    with pytest.raises(QueryError):
        parse_unified_query("not an object")  # type: ignore[arg-type]


def test_parse_unified_query_rejects_missing_indicator_fields():
    with pytest.raises(QueryError):
        parse_unified_query({"indicators": [{"field": "user.name", "operator": "eq"}]})


# ------------------------------------------------------------------- translators


_SAMPLE_QUERY = UnifiedQuery(
    free_text="kerberoasting",
    indicators=(
        Indicator(field="user.name", operator="eq", value="alice"),
        Indicator(field="event.code", operator="in", value=[4769, 4770]),
        Indicator(field="process.name", operator="contains", value="mimikatz"),
    ),
    since_seconds=900,
    limit=50,
)


def test_spl_translator_renders_indicators_and_time_window():
    spl = to_spl(_SAMPLE_QUERY)

    # All three indicators must appear; we don't assert exact whitespace,
    # only that no operator was silently dropped.
    assert "user.name" in spl
    assert "event.code" in spl
    assert "process.name" in spl
    # SPL renders an "in" operator as IN(...) with the value list intact.
    assert "4769" in spl and "4770" in spl
    # Time window must collapse to an SPL-native earliest specifier.
    assert "earliest" in spl.lower()
    # The free_text should appear somewhere as a search term.
    assert "kerberoasting" in spl


def test_kql_translator_renders_pipeline_form():
    kql = to_kql(_SAMPLE_QUERY)

    # KQL is pipeline-shaped; we should see the | take/limit clause and a where.
    lowered = kql.lower()
    assert "where" in lowered
    assert "user.name" in kql
    assert "event.code" in kql
    # ``in`` becomes ``in (4769, 4770)`` — both values must survive.
    assert "4769" in kql and "4770" in kql
    # ``take`` or ``limit`` caps the rows. (Translator may pick either.)
    assert "take" in lowered or "limit" in lowered


def test_esql_translator_renders_from_and_where():
    esql = to_esql(_SAMPLE_QUERY)

    # ES|QL queries always start with FROM and pipe through WHERE/LIMIT.
    assert esql.strip().upper().startswith("FROM")
    assert "user.name" in esql
    assert "event.code" in esql
    assert "process.name" in esql
    # ``contains`` on ES|QL maps to ``LIKE "%value%"``; check that the value
    # made it through somewhere in the rendered string.
    assert "mimikatz" in esql
    assert "LIKE" in esql.upper()


def test_translators_handle_empty_indicators_safely():
    # Free-text-only query — translators must still produce *some* valid output,
    # not crash.  The merge layer relies on this for natural-language pivots.
    q = UnifiedQuery(
        free_text="brute force",
        indicators=(),
        since_seconds=300,
        limit=10,
    )
    assert "brute force" in to_spl(q)
    assert "brute force" in to_kql(q)
    assert "brute force" in to_esql(q)


# ------------------------------------------------------------- connector wiring


def test_federated_capable_connectors_are_registered_and_advertised():
    """``services/api`` pre-filters by ``supports_federated_search``; if a
    connector is supposed to be queryable, it must opt in *and* be in the
    registry. This test catches both halves at once."""
    for connector_id in ("splunk", "microsoft_sentinel", "elastic"):
        cls = CONNECTOR_REGISTRY.get(connector_id)
        assert cls is not None, f"connector '{connector_id}' missing from registry"
        assert getattr(cls, "supports_federated_search", False), f"connector '{connector_id}' must opt into federated search"


def test_elastic_connector_flattens_esql_columns_and_values():
    """ES|QL responses come back as ``{"columns": [...], "values": [[...]]}``.
    The fan-out merge in ``services/api`` only knows how to consume rows of
    dicts, so the connector has to flatten before returning."""
    sample_response: dict[str, Any] = {
        "columns": [
            {"name": "@timestamp", "type": "date"},
            {"name": "user.name", "type": "keyword"},
            {"name": "event.code", "type": "long"},
        ],
        "values": [
            ["2026-05-05T12:00:00Z", "alice", 4769],
            ["2026-05-05T12:01:00Z", "bob", 4770],
        ],
    }

    rows = ElasticConnector._rows_from_esql(sample_response)
    assert rows == [
        {"@timestamp": "2026-05-05T12:00:00Z", "user.name": "alice", "event.code": 4769},
        {"@timestamp": "2026-05-05T12:01:00Z", "user.name": "bob", "event.code": 4770},
    ]


def test_elastic_connector_flatten_handles_empty_response():
    # Edge case: empty ES|QL result must produce an empty list, not crash.
    assert ElasticConnector._rows_from_esql({"columns": [], "values": []}) == []
    # And missing keys must also be handled defensively.
    assert ElasticConnector._rows_from_esql({}) == []


# --------------------------------------------------------------- live-call shape


@pytest.mark.asyncio
async def test_splunk_query_assembles_post_body(monkeypatch):
    """Confirm ``SplunkConnector.query()`` builds the right Splunk REST call:
    the SPL string lands in the body, the time window survives, and we read
    rows out of the JSON ``results`` array.  We patch the HTTP layer so this
    stays hermetic."""
    captured: dict[str, Any] = {}

    class _StubResponse:
        status_code = 200

        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict[str, Any]:
            return {"results": [{"_time": "2026-05-05T00:00:00Z", "user": "alice"}]}

    class _StubAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            captured["url"] = url
            captured["data"] = kwargs.get("data") or kwargs.get("params") or {}
            return _StubResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _StubAsyncClient)

    connector = SplunkConnector(
        base_url="https://splunk.example.com:8089",
        token="fake-token",
        saved_search="AiSOC_Alerts",
    )

    rows = await connector.query(_SAMPLE_QUERY)
    assert rows == [{"_time": "2026-05-05T00:00:00Z", "user": "alice"}]
    # Splunk REST search lands at /services/search/jobs.
    assert "search" in captured["url"]
    # The translated SPL must have made it into the request body.
    body = captured["data"]
    body_str = str(body)
    assert "user.name" in body_str
    assert "kerberoasting" in body_str


@pytest.mark.asyncio
async def test_sentinel_query_assembles_loganalytics_call(monkeypatch):
    captured: dict[str, Any] = {}

    class _StubResponse:
        status_code = 200

        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict[str, Any]:
            # Log Analytics API shape: tables[].columns[] + rows[].
            return {
                "tables": [
                    {
                        "columns": [
                            {"name": "TimeGenerated"},
                            {"name": "UserPrincipalName"},
                        ],
                        "rows": [["2026-05-05T00:00:00Z", "alice@example.com"]],
                    }
                ]
            }

    class _StubAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json") or {}
            return _StubResponse()

        async def get(self, url, **kwargs):
            # Token-mint or workspace-info call — return empty body to keep
            # the auth path happy without modeling the full OAuth dance.
            return _StubResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _StubAsyncClient)

    connector = MicrosoftSentinelConnector(
        tenant_id="tenant-uuid",
        client_id="client-uuid",
        client_secret="fake-secret",
        subscription_id="sub-uuid",
        resource_group="rg",
        workspace="workspace-uuid",
    )
    # Bypass the OAuth token mint so we go straight to the query.
    connector._access_token = "fake-bearer"  # noqa: SLF001

    rows = await connector.query(_SAMPLE_QUERY)
    assert rows == [{"TimeGenerated": "2026-05-05T00:00:00Z", "UserPrincipalName": "alice@example.com"}]
    # Log Analytics API path; workspace id must appear in the URL.
    assert "loganalytics" in captured["url"].lower()
    assert "workspace-uuid" in captured["url"]
    # The KQL string must be in the request body.
    body = captured["json"]
    assert "query" in body
    assert "user.name" in body["query"]


@pytest.mark.asyncio
async def test_elastic_query_assembles_esql_call(monkeypatch):
    captured: dict[str, Any] = {}

    class _StubResponse:
        status_code = 200

        @staticmethod
        def raise_for_status() -> None:
            return None

        @staticmethod
        def json() -> dict[str, Any]:
            return {
                "columns": [{"name": "@timestamp"}, {"name": "user.name"}],
                "values": [["2026-05-05T00:00:00Z", "alice"]],
            }

    class _StubAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json") or {}
            return _StubResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _StubAsyncClient)

    connector = ElasticConnector(
        base_url="https://elastic.example.com:9200",
        api_key="fake-key",
    )

    rows = await connector.query(_SAMPLE_QUERY)
    assert rows == [{"@timestamp": "2026-05-05T00:00:00Z", "user.name": "alice"}]
    assert "_query" in captured["url"]
    body = captured["json"]
    assert "query" in body
    # Translated ES|QL must have survived into the request body.
    assert "FROM" in body["query"].upper()
    assert "user.name" in body["query"]
