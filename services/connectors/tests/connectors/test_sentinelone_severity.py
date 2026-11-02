"""SentinelOne threat severity follows the agent's confidence verdict."""

from __future__ import annotations

import pytest
from app.connectors.sentinelone import SentinelOneConnector


def _normalize(confidence: str | None) -> dict:
    connector = SentinelOneConnector(api_token="t", base_url="https://s1.example")  # noqa: S106 — test
    threat_info = {"threatName": "Trojan.GenericKD", "classification": "Malware"}
    if confidence is not None:
        threat_info["confidenceLevel"] = confidence
    return connector.normalize({"id": "threat-1", "threatInfo": threat_info, "agentRealtimeInfo": {}})


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [("malicious", "high"), ("Malicious", "high"), ("suspicious", "medium"), ("n/a", "medium"), (None, "medium")],
)
def test_confidence_level_sets_severity(confidence: str | None, expected: str) -> None:
    assert _normalize(confidence)["severity"] == expected


def test_malicious_outranks_suspicious() -> None:
    assert _normalize("malicious")["severity"] != _normalize("suspicious")["severity"]
