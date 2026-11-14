"""Tests for FleetDMClient — respx-mocked HTTP calls."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from app.clients.fleetdm_client import FleetDMClient, FleetDMError
from app.clients.osquery_allowlist import AllowlistError

BASE = "https://fleet.example.com"
TOKEN = "fleet-api-token-xyz"


def _make_client_token(**kwargs: Any) -> FleetDMClient:
    return FleetDMClient(
        base_url=BASE,
        api_token=TOKEN,
        verify_tls=False,
        poll_interval=0.01,
        **kwargs,
    )


def _make_client_password(**kwargs: Any) -> FleetDMClient:
    return FleetDMClient(
        base_url=BASE,
        username="admin@example.com",
        password="s3cr3t",
        verify_tls=False,
        poll_interval=0.01,
        **kwargs,
    )


LOGIN_URL = f"{BASE}/api/v1/fleet/login"
CAMPAIGN_URL = f"{BASE}/api/v1/fleet/queries/run"
CAMPAIGN_STATUS_TMPL = f"{BASE}/api/v1/fleet/queries/run/{{}}"


class TestAllowlistRejection:
    @pytest.mark.asyncio
    async def test_unknown_template_raises(self) -> None:
        client = _make_client_token()
        with pytest.raises(AllowlistError):
            await client.live_query(["host1"], template="DROP TABLE users;")


class TestTokenAuth:
    @pytest.mark.asyncio
    async def test_token_sent_in_header(self) -> None:
        campaign_id = 42
        captured: dict[str, str] = {}

        def capture_campaign(request: httpx.Request) -> httpx.Response:
            captured.update(dict(request.headers))
            return httpx.Response(200, json={"campaign": {"id": campaign_id}})

        with respx.mock:
            respx.post(CAMPAIGN_URL).mock(side_effect=capture_campaign)
            respx.get(CAMPAIGN_STATUS_TMPL.format(campaign_id)).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": {"total_results_count": 1},
                        "results": [
                            {
                                "rows": [{"pid": "1", "name": "init"}],
                                "host": {"hostname": "host1"},
                            }
                        ],
                    },
                )
            )

            client = _make_client_token()
            result = await client.live_query(["host1"], template="running_processes", timeout_seconds=5)

        assert captured.get("authorization") == f"Bearer {TOKEN}"
        assert result["partial"] is False
        assert "host1" in result["results"]


class TestPasswordAuth:
    @pytest.mark.asyncio
    async def test_login_called_then_campaign(self) -> None:
        campaign_id = 99
        session_token = "session-tok-001"

        with respx.mock:
            respx.post(LOGIN_URL).mock(return_value=httpx.Response(200, json={"token": session_token}))
            respx.post(CAMPAIGN_URL).mock(return_value=httpx.Response(200, json={"campaign": {"id": campaign_id}}))
            respx.get(CAMPAIGN_STATUS_TMPL.format(campaign_id)).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": {"total_results_count": 1},
                        "results": [
                            {
                                "rows": [],
                                "host": {"hostname": "host1"},
                            }
                        ],
                    },
                )
            )

            client = _make_client_password()
            result = await client.live_query(["host1"], template="active_connections")

        assert result["partial"] is False


class TestPollingTimeout:
    @pytest.mark.asyncio
    async def test_partial_when_results_incomplete(self) -> None:
        campaign_id = 7
        with respx.mock:
            respx.post(CAMPAIGN_URL).mock(return_value=httpx.Response(200, json={"campaign": {"id": campaign_id}}))
            # Returns only 0/2 results
            respx.get(CAMPAIGN_STATUS_TMPL.format(campaign_id)).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": {"total_results_count": 0},
                        "results": [],
                    },
                )
            )

            client = _make_client_token()
            result = await client.live_query(
                ["host1", "host2"],
                template="logged_in_users",
                timeout_seconds=0,
            )

        assert result["partial"] is True


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_login_failure_raises(self) -> None:
        with respx.mock:
            respx.post(LOGIN_URL).mock(return_value=httpx.Response(401, json={"error": "bad creds"}))

            client = _make_client_password()
            with pytest.raises(FleetDMError, match="login failed"):
                await client.live_query(["host1"], template="running_processes")

    @pytest.mark.asyncio
    async def test_campaign_creation_failure_raises(self) -> None:
        with respx.mock:
            respx.post(CAMPAIGN_URL).mock(return_value=httpx.Response(500, text="error"))

            client = _make_client_token()
            with pytest.raises(FleetDMError, match="campaign creation failed"):
                await client.live_query(["host1"], template="running_processes")

    @pytest.mark.asyncio
    async def test_missing_campaign_id_raises(self) -> None:
        with respx.mock:
            respx.post(CAMPAIGN_URL).mock(return_value=httpx.Response(200, json={"campaign": {}}))

            client = _make_client_token()
            with pytest.raises(FleetDMError, match="no campaign ID"):
                await client.live_query(["host1"], template="active_connections")


class TestPartialResponse:
    @pytest.mark.asyncio
    async def test_partial_result_structure(self) -> None:
        campaign_id = 55

        with respx.mock:
            respx.post(CAMPAIGN_URL).mock(return_value=httpx.Response(200, json={"campaign": {"id": campaign_id}}))
            # host1 responds, host2 never does; we poll until timeout.
            respx.get(CAMPAIGN_STATUS_TMPL.format(campaign_id)).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "status": {"total_results_count": 1},
                        "results": [{"rows": [{"pid": "42"}], "host": {"hostname": "host1"}}],
                    },
                )
            )

            client = _make_client_token()
            result = await client.live_query(
                ["host1", "host2"],
                template="running_processes",
                timeout_seconds=1,  # non-zero so at least one poll happens
            )

        assert result["partial"] is True
        assert "host1" in result["results"]
        assert result["results"]["host1"][0]["pid"] == "42"
