"""Tests for OsctrlClient — respx-mocked HTTP calls."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx
from app.clients.osctrl_client import OsctrlClient, OsctrlError
from app.clients.osquery_allowlist import AllowlistError

BASE = "https://osctrl.example.com"
ENV = "prod"
TOKEN = "test-token-abc"


def _make_client(**kwargs: Any) -> OsctrlClient:
    return OsctrlClient(
        base_url=BASE,
        environment=ENV,
        api_token=TOKEN,
        verify_tls=False,
        poll_interval=0.01,
        **kwargs,
    )


SUBMIT_URL = f"{BASE}/api/v1/queries/{ENV}"
RESULTS_URL_TMPL = f"{BASE}/api/v1/queries/{ENV}/{{}}/results"


class TestAllowlistRejection:
    @pytest.mark.asyncio
    async def test_unknown_template_raises_allowlist_error(self) -> None:
        client = _make_client()
        with pytest.raises(AllowlistError):
            await client.live_query(["host1"], template="not_a_template")


class TestSuccessPath:
    @pytest.mark.asyncio
    async def test_single_host_all_respond(self) -> None:
        query_id = "qid-001"
        results_url = RESULTS_URL_TMPL.format(query_id)

        with respx.mock:
            respx.post(SUBMIT_URL).mock(return_value=httpx.Response(201, json={"id": query_id}))
            respx.get(results_url).mock(
                return_value=httpx.Response(
                    200,
                    json=[{"node": "host1", "rows": [{"pid": "123", "name": "bash"}]}],
                )
            )

            client = _make_client()
            result = await client.live_query(["host1"], template="running_processes", timeout_seconds=5)

        assert result["partial"] is False
        assert "host1" in result["results"]
        rows = result["results"]["host1"]
        assert rows[0]["pid"] == "123"

    @pytest.mark.asyncio
    async def test_submit_uses_bearer_token(self) -> None:
        query_id = "qid-bearer"
        results_url = RESULTS_URL_TMPL.format(query_id)

        captured_headers: dict[str, str] = {}

        def capture_submit(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json={"id": query_id})

        with respx.mock:
            respx.post(SUBMIT_URL).mock(side_effect=capture_submit)
            respx.get(results_url).mock(return_value=httpx.Response(200, json=[{"node": "host1", "rows": []}]))

            client = _make_client()
            await client.live_query(["host1"], template="active_connections")

        assert captured_headers.get("authorization") == f"Bearer {TOKEN}"


class TestPollingTimeout:
    @pytest.mark.asyncio
    async def test_partial_true_when_timeout_before_all_respond(self) -> None:
        query_id = "qid-timeout"
        results_url = RESULTS_URL_TMPL.format(query_id)

        with respx.mock:
            respx.post(SUBMIT_URL).mock(return_value=httpx.Response(200, json={"id": query_id}))
            # Only host1 responds; host2 never appears.
            respx.get(results_url).mock(
                return_value=httpx.Response(
                    200,
                    json=[{"node": "host1", "rows": [{"pid": "1"}]}],
                )
            )

            client = _make_client()
            result = await client.live_query(
                ["host1", "host2"],
                template="running_processes",
                timeout_seconds=0,  # immediate timeout
            )

        assert result["partial"] is True


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_submit_500_raises_osctrl_error(self) -> None:
        with respx.mock:
            respx.post(SUBMIT_URL).mock(return_value=httpx.Response(500, text="server error"))

            client = _make_client()
            with pytest.raises(OsctrlError, match="query submission failed"):
                await client.live_query(["host1"], template="logged_in_users")

    @pytest.mark.asyncio
    async def test_poll_non_200_non_404_raises(self) -> None:
        query_id = "qid-poll-err"
        results_url = RESULTS_URL_TMPL.format(query_id)

        with respx.mock:
            respx.post(SUBMIT_URL).mock(return_value=httpx.Response(200, json={"id": query_id}))
            respx.get(results_url).mock(return_value=httpx.Response(503, text="unavailable"))

            client = _make_client()
            with pytest.raises(OsctrlError, match="result poll failed"):
                await client.live_query(["host1"], template="active_connections", timeout_seconds=5)

    @pytest.mark.asyncio
    async def test_no_query_id_in_response_raises(self) -> None:
        with respx.mock:
            respx.post(SUBMIT_URL).mock(return_value=httpx.Response(200, json={}))

            client = _make_client()
            with pytest.raises(OsctrlError, match="no query ID"):
                await client.live_query(["host1"], template="logged_in_users")


class TestTemplateParams:
    @pytest.mark.asyncio
    async def test_custom_limit_forwarded(self) -> None:
        """Ensure the rendered SQL (with custom params) is sent to the API."""
        query_id = "qid-params"
        results_url = RESULTS_URL_TMPL.format(query_id)
        captured_body: dict[str, Any] = {}

        def capture(request: httpx.Request) -> httpx.Response:
            import json

            captured_body.update(json.loads(request.content))
            return httpx.Response(201, json={"id": query_id})

        with respx.mock:
            respx.post(SUBMIT_URL).mock(side_effect=capture)
            respx.get(results_url).mock(return_value=httpx.Response(200, json=[{"node": "h1", "rows": []}]))

            client = _make_client()
            await client.live_query(
                ["h1"],
                template="running_processes",
                template_params={"limit": 10},
            )

        assert "LIMIT 10" in captured_body.get("query", "")
