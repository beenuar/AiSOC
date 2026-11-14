"""Phase D1 — SIEM connector expansion tests (QRadar, Exabeam, Securonix, Devo).

Pins schema validity, registry membership, and the severity-ladder mapping for
each SIEM's native risk signal → the five-tier ladder, plus a mocked pull.
"""

from __future__ import annotations

import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.devo import DevoConnector
from app.connectors.exabeam import ExabeamConnector
from app.connectors.qradar import QRadarConnector
from app.connectors.securonix import SecuronixConnector


def _assert_ladder(sev: str) -> None:
    assert sev in {"info", "low", "medium", "high", "critical"}


# ── QRadar ────────────────────────────────────────────────────────────────────


def test_qradar_registered_and_schema():
    assert CONNECTOR_REGISTRY["qradar"] is QRadarConnector
    s = QRadarConnector.schema()
    assert s.category == "siem"
    assert {"console_url", "sec_token"} <= {f.name for f in s.fields}
    assert Capability.PULL_ALERTS in QRadarConnector.capabilities()


@pytest.mark.parametrize(
    "magnitude,expected",
    [(10, "critical"), (9, "critical"), (8, "high"), (7, "high"), (5, "medium"), (3, "low"), (1, "info")],
)
def test_qradar_magnitude_mapping(magnitude, expected):
    c = QRadarConnector(console_url="https://q", sec_token="t")
    out = c.normalize({"id": 1, "magnitude": magnitude, "description": "off"})
    assert out["severity"] == expected
    assert out["external_id"] == "1"


@pytest.mark.asyncio
@respx.mock
async def test_qradar_fetch():
    c = QRadarConnector(console_url="https://q", sec_token="t")
    respx.get("https://q/api/siem/offenses").respond(200, json=[{"id": 5, "magnitude": 9, "description": "x"}])
    out = await c.fetch_alerts(since_seconds=300)
    assert len(out) == 1
    assert out[0]["severity"] == "critical"


# ── Exabeam ─────────────────────────────────────────────────────────────────


def test_exabeam_registered_and_secret_field():
    assert CONNECTOR_REGISTRY["exabeam"] is ExabeamConnector
    s = ExabeamConnector.schema()
    # api_key is secret-shaped → must be type=secret (conformance gate).
    assert next(f for f in s.fields if f.name == "api_key").type == "secret"


@pytest.mark.parametrize(
    "risk,expected",
    [(160, "critical"), (95, "high"), (50, "medium"), (12, "low"), (2, "info")],
)
def test_exabeam_risk_mapping(risk, expected):
    c = ExabeamConnector(base_url="https://e", api_key="k", api_secret="s")
    out = c.normalize({"username": "alice", "riskScore": risk, "sessionId": "s1"})
    assert out["severity"] == expected
    assert out["username"] == "alice"


# ── Securonix ─────────────────────────────────────────────────────────────────


def test_securonix_priority_mapping():
    c = SecuronixConnector(tenant_url="https://s", api_token="t")
    for prio, expected in [("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low"), ("None", "info")]:
        out = c.normalize({"incidentId": "1", "priority": prio, "entity": "bob", "entityType": "Users"})
        assert out["severity"] == expected
    assert out["username"] == "bob"


# ── Devo ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "sev,expected",
    [(5, "critical"), (4, "high"), (3, "medium"), (2, "low"), (1, "info"), ("High", "high"), ("Very High", "critical")],
)
def test_devo_severity_mapping(sev, expected):
    c = DevoConnector(api_url="https://d/alerts", api_token="t")
    out = c.normalize({"alertId": "a1", "severity": sev, "summary": "x", "context": {"srcIp": "1.2.3.4"}})
    assert out["severity"] == expected
    assert out["src_ip"] == "1.2.3.4"


def test_all_siem_expansion_categories_are_siem():
    for cid in ("qradar", "exabeam", "securonix", "devo"):
        assert CONNECTOR_REGISTRY[cid].schema().category == "siem"
