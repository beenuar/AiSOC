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
    [
        ("malicious", "high"),
        ("Malicious", "high"),
        ("suspicious", "medium"),
        ("n/a", "medium"),
        (None, "medium"),
        # The Low/Medium/High/Critical ladder stays reachable for any payload
        # that carries it, and ``Critical`` keeps its own tier rather than
        # collapsing into ``high`` -- the platform's severity ladder is five
        # tiers and a vendor-native critical has to survive end to end.
        ("Critical", "critical"),
    ],
)
def test_confidence_level_sets_severity(confidence: str | None, expected: str) -> None:
    assert _normalize(confidence)["severity"] == expected


def test_malicious_outranks_suspicious() -> None:
    assert _normalize("malicious")["severity"] != _normalize("suspicious")["severity"]
