"""Wave 3b — QRadar AQL federated-search backend."""

from __future__ import annotations

from app.connectors.qradar import QRadarConnector
from app.federated.query import parse_unified_query
from app.federated.translators import to_aql


def _q(payload: dict):
    return parse_unified_query(payload)


def test_to_aql_basic_eq_and_window():
    aql = to_aql(_q({"indicators": [{"field": "sourceip", "operator": "eq", "value": "1.2.3.4"}], "since_seconds": 600, "limit": 50}))
    assert aql.startswith("SELECT * FROM events WHERE ")
    assert "sourceip = '1.2.3.4'" in aql
    assert "LAST 10 MINUTES" in aql
    assert "LIMIT 50" in aql


def test_to_aql_operators_and_free_text():
    aql = to_aql(
        _q(
            {
                "free_text": "malware",
                "indicators": [
                    {"field": "username", "operator": "contains", "value": "svc"},
                    {"field": "magnitude", "operator": "gte", "value": 7},
                    {"field": "category", "operator": "in", "value": ["a", "b"]},
                ],
                "since_seconds": 300,
                "limit": 10,
            }
        )
    )
    assert "TEXT SEARCH 'malware'" in aql
    assert "username ILIKE '%svc%'" in aql
    assert "magnitude >= 7" in aql
    assert "category IN ('a', 'b')" in aql


def test_to_aql_escapes_single_quotes():
    aql = to_aql(_q({"indicators": [{"field": "user", "operator": "eq", "value": "o'brien"}], "since_seconds": 60, "limit": 5}))
    assert "user = 'o''brien'" in aql


def test_qradar_declares_federated_search():
    assert QRadarConnector.supports_federated_search is True
    assert hasattr(QRadarConnector, "query")
