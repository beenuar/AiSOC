"""
Unit tests for the Wazuh connector.

Pattern mirrors ``test_osquery_connectors.py``:

  1. Schema sanity — wizard form has the fields the docs promise and
     the secret-typed fields are masked.
  2. ``normalize()`` produces the canonical AiSOC alert shape and applies
     the four-tier severity collapse exactly as documented.
  3. HTTP routing through ``respx`` exercises the real ``httpx`` paths
     and proves we hit the documented Wazuh indexer endpoints.

We intentionally do not test against a live Wazuh stack here — that is
covered by integration smoke tests in the docker-compose harness.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.base import Capability
from app.connectors.wazuh import WazuhConnector, _severity_from_level

INDEXER = "https://wazuh.test.local:9200"
USERNAME = "admin"
PASSWORD = "wazuh-fake-password"
INDEX_PATTERN = "wazuh-alerts-*"


# ---------------------------------------------------------------------------
# Schema + capability surface
# ---------------------------------------------------------------------------


def test_wazuh_schema_has_required_fields():
    schema = WazuhConnector.schema()
    names = {f.name for f in schema.fields}
    assert {"indexer_url", "username", "password", "index_pattern", "min_rule_level", "verify_tls"} <= names
    assert schema.category == "siem"
    pwd = next(f for f in schema.fields if f.name == "password")
    assert pwd.type == "secret"


def test_wazuh_capabilities_cover_pull_query_search_pivot():
    caps = set(WazuhConnector.capabilities())
    assert Capability.PULL_ALERTS in caps
    assert Capability.QUERY_LOGS in caps
    assert Capability.SEARCH_SIEM in caps
    assert Capability.PIVOT_HOST in caps


# ---------------------------------------------------------------------------
# Severity collapse: 0-15 → info | low | medium | high
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "level,expected",
    [
        (0, "info"),
        (3, "info"),
        (4, "low"),
        (7, "low"),
        (8, "medium"),
        (11, "medium"),
        (12, "high"),
        (14, "high"),
        # Wazuh level 15 is the maximum band and represents the most
        # severe attack signatures — it now maps to AiSOC's ``critical``
        # (P1, 15-minute MTTD SLA) so it lands in the top lane.
        (15, "critical"),
        # Out-of-band / weird inputs — must not raise.
        (None, "info"),
        ("not-a-number", "info"),
        ("9", "medium"),
        (-3, "info"),
        # Values above 15 are clamped to the top tier (``critical``).
        (99, "critical"),
    ],
)
def test_severity_band_collapse(level, expected):
    assert _severity_from_level(level) == expected


# ---------------------------------------------------------------------------
# normalize()
# ---------------------------------------------------------------------------


def _hit(level: int = 12, **rule_extra) -> dict:
    """Minimal indexer hit envelope mimicking a real Wazuh alert."""
    return {
        "_id": "doc-abc",
        "_index": "wazuh-alerts-4.x-2026.05.12",
        "_source": {
            "@timestamp": "2026-05-12T08:00:00.000Z",
            "agent": {"id": "001", "name": "web-01.corp", "ip": "10.0.0.5"},
            "rule": {
                "id": "100100",
                "level": level,
                "description": "Possible rootkit installation",
                "groups": ["rootcheck", "intrusion_attempt"],
                "mitre": {"id": ["T1547"], "tactic": ["Persistence"]},
                **rule_extra,
            },
            "data": {"command": "modprobe evil"},
            "decoder": {"name": "rootcheck"},
            "full_log": "rootcheck: detected suspicious kernel module",
        },
    }


def test_normalize_high_severity_rule_maps_to_high():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    normalized = connector.normalize(_hit(level=14))
    assert normalized["source"] == "wazuh"
    assert normalized["category"] == "siem"
    assert normalized["event_type"] == "wazuh_alert"
    assert normalized["severity"] == "high"
    assert normalized["title"] == "Possible rootkit installation"
    assert normalized["hostname"] == "web-01.corp"
    assert normalized["host"] == "web-01.corp"
    assert normalized["agent_id"] == "001"
    assert normalized["agent_ip"] == "10.0.0.5"
    assert normalized["rule_id"] == "100100"
    assert normalized["rule_level"] == 14
    assert normalized["mitre_techniques"] == ["T1547"]
    assert normalized["mitre_tactics"] == ["Persistence"]
    assert normalized["alert_id"] == "doc-abc"
    # raw_event must be the original _source so rule authors can pivot
    # into vendor-specific fields the canonical shape doesn't expose.
    assert normalized["raw_event"]["decoder"]["name"] == "rootcheck"


def test_normalize_low_signal_rule_maps_to_low():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    normalized = connector.normalize(_hit(level=5, description="sshd: failed password"))
    assert normalized["severity"] == "low"
    assert normalized["title"] == "sshd: failed password"


def test_normalize_synthesises_alert_id_when_doc_id_missing():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    raw = _hit(level=8)
    raw.pop("_id")
    normalized = connector.normalize(raw)
    # Composite fallback must include rule + agent + timestamp so retries
    # de-duplicate without the indexer doc id.
    assert "100100" in normalized["alert_id"]
    assert "001" in normalized["alert_id"]


def test_normalize_handles_missing_mitre_block():
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
    raw = _hit(level=8)
    del raw["_source"]["rule"]["mitre"]
    normalized = connector.normalize(raw)
    assert normalized["mitre_techniques"] == []
    assert normalized["mitre_tactics"] == []


# ---------------------------------------------------------------------------
# test_connection — auth, network, success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_test_connection_success(respx_mock):
    respx_mock.get(f"{INDEXER}/_cluster/health").mock(return_value=httpx.Response(200, json={"status": "green"}))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    result = await connector.test_connection()
    assert result == {"success": True, "connector": "wazuh"}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_test_connection_auth_failure(respx_mock):
    respx_mock.get(f"{INDEXER}/_cluster/health").mock(return_value=httpx.Response(401))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "auth" in result["error"].lower()


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_test_connection_network_error(respx_mock):
    respx_mock.get(f"{INDEXER}/_cluster/health").mock(side_effect=httpx.ConnectError("dns"))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "network" in result["error"].lower()


# ---------------------------------------------------------------------------
# fetch_alerts — wires through to OpenSearch search + applies the threshold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_fetch_alerts_returns_normalized_events(respx_mock):
    payload = {
        "hits": {
            "hits": [
                _hit(level=12),
                _hit(level=8),
            ]
        }
    }
    route = respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(200, json=payload))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 2
    # Must have routed through the search API
    assert route.called
    # Severity collapse must run on the way out
    assert {e["severity"] for e in events} == {"high", "medium"}


@pytest.mark.asyncio
@respx.mock(assert_all_called=True)
async def test_fetch_alerts_returns_empty_on_5xx(respx_mock):
    respx_mock.post(f"{INDEXER}/{INDEX_PATTERN}/_search").mock(return_value=httpx.Response(503))
    connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, verify_tls=False)
    events = await connector.fetch_alerts(since_seconds=300)
    assert events == []
