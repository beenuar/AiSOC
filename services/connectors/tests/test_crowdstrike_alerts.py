"""CrowdStrike must poll the Alerts API, not the decommissioned Detects API.

`/detects/queries/detects/v1` was removed on 2025-09-30. A client that still
calls it authenticates, the console test reports success, and every poll
404s. The replacement is `POST /alerts/combined/alerts/v1`.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from app.connectors.crowdstrike import CrowdStrikeConnector

_BASE = "https://api.eu-1.crowdstrike.com"
_ALERTS = f"{_BASE}/alerts/combined/alerts/v1"


def _connector() -> CrowdStrikeConnector:
    connector = CrowdStrikeConnector(client_id="id", client_secret="secret", base_url=_BASE)
    connector._access_token = "token"  # noqa: SLF001 — skip OAuth; this test is the query path
    return connector


def _alert() -> dict:
    return {
        "composite_id": "cid:ind:abc",
        "severity_name": "Critical",
        "display_name": "Credential dumping",
        "description": "LSASS access from an unsigned binary.",
        "technique_id": "T1003.001",
        "user_name": "alice",
        "device": {"hostname": "WKSTN-01", "external_ip": "203.0.113.9"},
        "created_timestamp": "2026-11-04T15:00:00Z",
    }


class TestAlertShape:
    def test_alert_fields_survive_normalization(self):
        event = CrowdStrikeConnector(client_id="id", client_secret="secret").normalize(_alert())
        assert event["external_id"] == "cid:ind:abc"
        assert event["severity"] == "critical"
        assert event["title"] == "Credential dumping"
        assert event["actor"] == "alice"
        assert event["hostname"] == "WKSTN-01"
        assert event["mitre_techniques"] == ["T1003.001"]
        assert event["description"] == "LSASS access from an unsigned binary."


class TestFetch:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_posts_to_the_alerts_api_not_detects(self):
        route = respx.post(_ALERTS).mock(return_value=httpx.Response(200, json={"resources": [_alert()]}))
        detects = respx.get(url__regex=r".*/detects/.*").mock(return_value=httpx.Response(404))

        events = await _connector().fetch_alerts(since_seconds=300)

        assert route.called
        assert not detects.called
        body = route.calls.last.request.content.decode()
        assert "created_timestamp:>" in body
        assert body.endswith("Z'") or "Z'" in body
        assert events[0]["external_id"] == "cid:ind:abc"

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_missing_alerts_scope_names_the_permission(self):
        respx.post(_ALERTS).mock(return_value=httpx.Response(403, json={"errors": [{"message": "access denied"}]}))

        with pytest.raises(RuntimeError, match="Alerts: Read"):
            await _connector().fetch_alerts()

    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_fails_when_alerts_are_forbidden(self):
        respx.post(_ALERTS).mock(return_value=httpx.Response(403, text="forbidden"))

        result = await _connector().test_connection()

        assert result["success"] is False
        assert "Alerts: Read" in result["error"]
