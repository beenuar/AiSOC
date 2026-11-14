"""Tests for the Sublime Security email-security connector (T4.4).

Brings the wave-2 ``sublime_security`` connector up to wave-1 test parity:
schema + registry wiring, the full verdict→severity collapse (including the
attack-rule escalation and the nested ``review.classification`` fallback),
cursor pagination, and the ``test_connection`` happy/sad paths. Network is
mocked with :mod:`respx` so the suite stays offline-safe.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.sublime_security import SublimeSecurityConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sublime_security" / "sample_event.json"
_BASE = "https://api.platform.sublimesecurity.com"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = SublimeSecurityConnector.schema()
    assert schema.connector_id == "sublime_security"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"base_url", "api_key"} <= names
    assert Capability.PULL_ALERTS in SublimeSecurityConnector.capabilities()


def test_registry_contains_sublime_security():
    assert "sublime_security" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["sublime_security"] is SublimeSecurityConnector


def test_normalize_malicious_to_high(fixture):
    c = SublimeSecurityConnector(api_key="t")
    out = c.normalize(fixture[0])
    assert out["severity"] == "high"
    assert out["source"] == "sublime_security"
    assert out["external_id"] == "msg-malicious"
    assert out["actor"] == "attacker@evil.test"
    assert out["actor_email"] == "attacker@evil.test"
    assert out["target"] == "alice@corp.test"
    assert out["event_type"] == "sublime_security.malicious"


def test_normalize_suspicious_to_medium(fixture):
    c = SublimeSecurityConnector(api_key="t")
    assert c.normalize(fixture[1])["severity"] == "medium"


def test_normalize_graymail_to_low(fixture):
    c = SublimeSecurityConnector(api_key="t")
    assert c.normalize(fixture[2])["severity"] == "low"


def test_normalize_benign_to_info(fixture):
    c = SublimeSecurityConnector(api_key="t")
    assert c.normalize(fixture[3])["severity"] == "info"


def test_normalize_bec_rule_escalates_spam_to_high(fixture):
    """A low-ish verdict still escalates to high when an attack-shaped rule
    (BEC / credential / phishing / impersonation) fires."""
    c = SublimeSecurityConnector(api_key="t")
    out = c.normalize(fixture[4])
    assert out["severity"] == "high"


def test_normalize_reads_nested_review_classification(fixture):
    """Verdict can arrive as ``review.classification``; sender can arrive as
    a flat ``from_email`` rather than a ``from`` object."""
    c = SublimeSecurityConnector(api_key="t")
    out = c.normalize(fixture[5])
    assert out["severity"] == "medium"
    assert out["external_id"] == "msg-nested-review"
    assert out["actor_email"] == "phish@lookalike.test"
    assert out["target"] == "eve@corp.test"


def test_normalize_unknown_verdict_defaults_to_info():
    c = SublimeSecurityConnector(api_key="t")
    out = c.normalize({"id": "x", "classification": "totally-unknown"})
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_cursor_pagination(fixture, monkeypatch):
    # Shrink the page size so two small fixture pages exercise the cursor
    # advance (the loop only continues on a full page + a next cursor).
    monkeypatch.setattr("app.connectors.sublime_security._PER_PAGE", 2)
    c = SublimeSecurityConnector(api_key="t")

    page1 = {"messages": [fixture[0], fixture[1]], "next_cursor": "cur1"}
    page2 = {"messages": [fixture[2]]}
    route = respx.get(f"{_BASE}/v1/messages")
    route.side_effect = [
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ]

    out = await c.fetch_alerts(since_seconds=300)

    # 2 from page 1 (full page + cursor → continue), 1 from page 2 (short → stop).
    assert len(out) == 3
    assert all(e["source"] == "sublime_security" for e in out)
    # The second request must carry the cursor returned by page 1.
    assert "cur1" in str(route.calls[1].request.url)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_stops_on_non_200():
    c = SublimeSecurityConnector(api_key="t")
    respx.get(f"{_BASE}/v1/messages").respond(401, json={"error": "unauthorized"})
    out = await c.fetch_alerts(since_seconds=300)
    assert out == []


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = SublimeSecurityConnector(api_key="t")
    respx.get(f"{_BASE}/v1/me").respond(200, json={"organization": {"name": "Acme Corp"}})
    res = await c.test_connection()
    assert res["success"] is True
    assert res["tenant"] == "Acme Corp"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_failure():
    c = SublimeSecurityConnector(api_key="t")
    respx.get(f"{_BASE}/v1/me").respond(403, json={"error": "forbidden"})
    res = await c.test_connection()
    assert res["success"] is False
    assert "403" in res["error"]
