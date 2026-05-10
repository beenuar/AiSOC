"""Integration tests for the MITRE ATT&CK-based attack reasoning HTTP API."""

from __future__ import annotations

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from main import app  # noqa: E402

client = TestClient(app)


def test_analyze_attack_endpoint_returns_full_state():
    payload = {
        "incident_id": "TEST-001",
        "observed_indicators": [
            {"type": "ip", "value": "192.168.1.100", "context": "Suspicious outbound traffic"},
            {"type": "hash", "value": "abc123", "context": "Malicious payload detected"},
        ],
    }
    response = client.post("/api/v1/attack-reasoning/analyze", json=payload)
    assert response.status_code == 200, response.text
    data = response.json()
    for key in (
        "incident_id",
        "observed_indicators",
        "identified_techniques",
        "predicted_techniques",
        "kill_chain_analysis",
        "threat_actors",
        "mitigations",
        "tactical_recommendations",
        "confidence_scores",
        "status",
    ):
        assert key in data, f"missing key: {key}"
    assert data["incident_id"] == "TEST-001"
    assert data["status"] in {"completed", "failed"}


def test_predict_next_techniques_endpoint_uses_progression_map():
    """Posting T1566 must yield T1059 and T1078 per the v0 progression map."""
    response = client.post(
        "/api/v1/attack-reasoning/predict-next-techniques",
        json={"identified_techniques": ["T1566"]},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["input_techniques"] == ["T1566"]
    predicted_ids = {p["id"] for p in data["predictions"]}
    assert {"T1059", "T1078"}.issubset(predicted_ids)


def test_predict_next_techniques_endpoint_unknown_input():
    response = client.post(
        "/api/v1/attack-reasoning/predict-next-techniques",
        json={"identified_techniques": ["T9999"]},
    )
    assert response.status_code == 200
    assert response.json()["predictions"] == []


def test_get_technique_details_endpoint_known_or_404():
    """Either the corpus has T1059 (200) or it doesn't (404). Never 500."""
    response = client.get("/api/v1/attack-reasoning/technique/T1059")
    assert response.status_code in {200, 404}, response.text
    if response.status_code == 200:
        body = response.json()
        assert "technique" in body
        assert body["technique"].get("id") == "T1059"


def test_get_technique_details_endpoint_unknown_returns_404():
    response = client.get("/api/v1/attack-reasoning/technique/T9999")
    assert response.status_code == 404


def test_get_actor_profile_endpoint_known_or_404():
    """G0016 is APT29's MITRE ID. Returns 200 if loaded, 404 otherwise."""
    response = client.get("/api/v1/attack-reasoning/actor/G0016")
    assert response.status_code in {200, 404}, response.text
    if response.status_code == 200:
        body = response.json()
        assert "actor" in body
        assert "techniques" in body


def test_get_actor_profile_endpoint_unknown_returns_404():
    response = client.get("/api/v1/attack-reasoning/actor/G99999")
    assert response.status_code == 404


def test_analyze_attack_invalid_input_rejected_with_422():
    response = client.post("/api/v1/attack-reasoning/analyze", json={})
    assert response.status_code == 422


def test_predict_next_techniques_invalid_input_rejected_with_422():
    response = client.post("/api/v1/attack-reasoning/predict-next-techniques", json={})
    assert response.status_code == 422


if __name__ == "__main__":
    pytest.main([__file__])
