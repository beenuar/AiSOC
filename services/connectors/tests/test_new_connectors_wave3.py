"""Wave 3a — new connectors emit the canonical envelope (so the ingest OCSF
path maps them to a Security Finding) and normalize idempotently."""

from __future__ import annotations

import pytest
from app.connectors.darktrace import DarktraceConnector
from app.connectors.greynoise import GreyNoiseConnector
from app.connectors.imperva import ImpervaConnector
from app.connectors.jumpcloud import JumpCloudConnector
from app.connectors.qualys import QualysConnector

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

_CASES = [
    (QualysConnector(base_url="https://q", username="u", password="p"), {"QID": 42, "SEVERITY": 5, "_ip": "1.2.3.4", "_dns": "h1"}),
    (GreyNoiseConnector(api_key="k"), {"ip": "8.8.8.8", "classification": "malicious", "last_seen": "2026-08-01"}),
    (JumpCloudConnector(api_key="k"), {"id": "e1", "event_type": "admin_login_attempt", "success": False, "client_ip": "1.2.3.4"}),
    (
        DarktraceConnector(base_url="https://d", public_token="pub", private_token="priv"),
        {"pbid": 7, "score": 0.95, "model": {"then": {"name": "Beacon"}}, "device": {"ip": "10.0.0.9"}},
    ),
    (ImpervaConnector(api_id="id", api_key="k"), {"id": "v1", "clientIPAddress": "1.2.3.4", "threats": [{"attackType": "SQL Injection"}]}),
]


@pytest.mark.parametrize("connector,raw", _CASES)
def test_normalize_emits_canonical_envelope(connector, raw):
    out = connector.normalize(raw)
    assert out["source"] == connector.connector_id
    assert out["raw_event"] == raw
    assert out["severity"] in _VALID_SEVERITIES
    assert "title" in out and out["title"]
    # Idempotent: re-normalizing the canonical envelope is a no-op.
    assert connector.normalize(out) == out


def test_severity_ladders_preserve_critical():
    # Qualys native 5 -> critical (not collapsed to high).
    q = QualysConnector(base_url="https://q", username="u", password="p")
    assert q.normalize({"QID": 1, "SEVERITY": 5})["severity"] == "critical"
    # Darktrace score >= 0.9 -> critical.
    d = DarktraceConnector(base_url="https://d", public_token="a", private_token="b")
    assert d.normalize({"pbid": 1, "score": 0.95})["severity"] == "critical"
