"""
Tests for ``app.services.aisoc_clients``.

We use ``respx`` to mock the HTTP transport so the tests stay hermetic — no
live FastAPI app needed. The goal is to lock in:

* request shape (headers, JSON body, URL path)
* response parsing for happy-path payloads
* AisocClientError translation for non-2xx responses and transport errors
* the open-cases filter excludes ``closed`` rows even when the API returns them
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.core.config import SlackBotSettings
from app.services.aisoc_clients import (
    AisocActionsClient,
    AisocApiClient,
    AisocClientError,
)

API_BASE = "http://api.test"
ACTIONS_BASE = "http://actions.test"
TENANT = "11111111-2222-3333-4444-555555555555"
TOKEN = "aisoc_test_key"


def _settings() -> SlackBotSettings:
    return SlackBotSettings(
        SLACK_BOT_TOKEN="xoxb-test",
        SLACK_SIGNING_SECRET="shhh",
        AISOC_API_BASE_URL=API_BASE,
        AISOC_ACTIONS_BASE_URL=ACTIONS_BASE,
        AISOC_API_SERVICE_TOKEN=TOKEN,
        AISOC_ACTIONS_SERVICE_TOKEN=TOKEN,
        AISOC_DEFAULT_TENANT_ID=TENANT,
    )


# ────────────────────────────────────────────────────────────────────────────
# AisocApiClient
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_open_cases_filters_closed_and_caps_to_limit():
    settings = _settings()

    sample = [
        {"id": "c1", "title": "Active", "status": "investigating", "severity": "high"},
        {"id": "c2", "title": "Done", "status": "closed", "severity": "low"},
        {"id": "c3", "title": "New", "status": "new", "severity": "medium"},
        {"id": "c4", "title": "Triaged", "status": "triaged", "severity": "high"},
    ]

    with respx.mock() as router:
        route = router.get(f"{API_BASE}/api/v1/cases").mock(return_value=httpx.Response(200, json=sample))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            cases = await client.list_open_cases(limit=2)
        finally:
            await client.aclose()

    assert route.called
    request = route.calls.last.request
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert request.headers["X-Tenant-Id"] == TENANT
    # Query expansion: limit=2 should request more rows so post-filter we still
    # have 2 active cases even when ``closed`` rows are interleaved.
    assert request.url.params["limit"] == "6"
    assert [c["id"] for c in cases] == ["c1", "c3"]


@pytest.mark.asyncio
async def test_list_open_cases_propagates_severity_filter():
    settings = _settings()
    with respx.mock() as router:
        route = router.get(f"{API_BASE}/api/v1/cases").mock(return_value=httpx.Response(200, json=[]))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            await client.list_open_cases(limit=5, severity="high")
        finally:
            await client.aclose()

    assert route.calls.last.request.url.params["severity"] == "high"


@pytest.mark.asyncio
async def test_get_case_url_encodes_identifier():
    settings = _settings()
    with respx.mock() as router:
        # User passes a case-number that contains a slash; the client must
        # quote it so the path stays inside ``/api/v1/cases/…``.
        route = router.get(f"{API_BASE}/api/v1/cases/CASE%2F1").mock(return_value=httpx.Response(200, json={"id": "abc", "title": "ok"}))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            case = await client.get_case("CASE/1")
        finally:
            await client.aclose()

    assert route.called
    assert case["title"] == "ok"


@pytest.mark.asyncio
async def test_launch_investigation_posts_alert_summary():
    settings = _settings()
    with respx.mock() as router:
        route = router.post(f"{API_BASE}/api/v1/cases/abc/investigate").mock(return_value=httpx.Response(202, json={"run_id": "run-1"}))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            result = await client.launch_investigation("abc", alert_summary="ransomware?")
        finally:
            await client.aclose()

    assert route.called
    sent = route.calls.last.request
    import json

    body = json.loads(sent.content)
    assert body == {"alert_summary": "ransomware?"}
    assert result == {"run_id": "run-1"}


@pytest.mark.asyncio
async def test_get_case_summary_requests_json_format():
    settings = _settings()
    with respx.mock() as router:
        route = router.get(f"{API_BASE}/api/v1/cases/abc/summary").mock(return_value=httpx.Response(200, json={"summary": "..."}))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            await client.get_case_summary("abc")
        finally:
            await client.aclose()

    assert route.calls.last.request.url.params["format"] == "json"


@pytest.mark.asyncio
async def test_non_2xx_raises_aisoc_client_error_with_status():
    settings = _settings()
    with respx.mock() as router:
        router.get(f"{API_BASE}/api/v1/cases").mock(return_value=httpx.Response(503, text="upstream down"))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            with pytest.raises(AisocClientError) as exc:
                await client.list_open_cases()
        finally:
            await client.aclose()

    assert exc.value.status_code == 503
    assert "list cases failed" in str(exc.value)


@pytest.mark.asyncio
async def test_transport_error_raises_without_status():
    settings = _settings()
    with respx.mock() as router:
        router.get(f"{API_BASE}/api/v1/cases").mock(side_effect=httpx.ConnectError("nope"))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            with pytest.raises(AisocClientError) as exc:
                await client.list_open_cases()
        finally:
            await client.aclose()

    assert exc.value.status_code is None


@pytest.mark.asyncio
async def test_invalid_json_raises_client_error():
    settings = _settings()
    with respx.mock() as router:
        router.get(f"{API_BASE}/api/v1/cases/abc").mock(return_value=httpx.Response(200, text="not json", headers={"content-type": "text/plain"}))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            with pytest.raises(AisocClientError):
                await client.get_case("abc")
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_list_open_cases_rejects_non_list_response():
    settings = _settings()
    with respx.mock() as router:
        router.get(f"{API_BASE}/api/v1/cases").mock(return_value=httpx.Response(200, json={"oops": "object"}))
        client = AisocApiClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            with pytest.raises(AisocClientError):
                await client.list_open_cases()
        finally:
            await client.aclose()


# ────────────────────────────────────────────────────────────────────────────
# AisocActionsClient
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_action_posts_full_payload_with_tenant():
    settings = _settings()
    with respx.mock() as router:
        route = router.post(f"{ACTIONS_BASE}/api/v1/actions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "a1",
                    "status": "awaiting_approval",
                    "blast_radius": "high",
                    "action_type": "isolate_host",
                },
            )
        )
        client = AisocActionsClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            result = await client.submit_action(
                action_type="isolate_host",
                target="host-42",
                case_id="case-7",
                rationale="confirmed beacon",
                requested_by="U_SLACK_USER",
            )
        finally:
            await client.aclose()

    assert route.called
    request = route.calls.last.request
    import json

    body = json.loads(request.content)
    assert body == {
        "incident_id": "case-7",
        "tenant_id": TENANT,
        "action_type": "isolate_host",
        "target": "host-42",
        "rationale": "confirmed beacon",
        "requested_by": "U_SLACK_USER",
        "parameters": {},
    }
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert result["status"] == "awaiting_approval"


@pytest.mark.asyncio
async def test_actions_client_falls_back_to_api_token_when_actions_token_missing():
    settings = SlackBotSettings(
        AISOC_API_BASE_URL=API_BASE,
        AISOC_ACTIONS_BASE_URL=ACTIONS_BASE,
        AISOC_API_SERVICE_TOKEN="aisoc_api_only",
        AISOC_ACTIONS_SERVICE_TOKEN="",
        AISOC_DEFAULT_TENANT_ID=TENANT,
    )
    with respx.mock() as router:
        route = router.post(f"{ACTIONS_BASE}/api/v1/actions/aaa/approve").mock(return_value=httpx.Response(200, json={"id": "aaa", "status": "completed"}))
        client = AisocActionsClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            await client.approve_action("aaa")
        finally:
            await client.aclose()

    assert route.calls.last.request.headers["Authorization"] == "Bearer aisoc_api_only"


@pytest.mark.asyncio
async def test_approve_and_reject_url_encode_action_id():
    settings = _settings()
    with respx.mock() as router:
        approve = router.post(f"{ACTIONS_BASE}/api/v1/actions/a%2F1/approve").mock(
            return_value=httpx.Response(200, json={"id": "a/1", "status": "approved"})
        )
        reject = router.post(f"{ACTIONS_BASE}/api/v1/actions/a%2F1/reject").mock(
            return_value=httpx.Response(200, json={"id": "a/1", "status": "rejected"})
        )
        client = AisocActionsClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            await client.approve_action("a/1")
            await client.reject_action("a/1")
        finally:
            await client.aclose()

    assert approve.called and reject.called


@pytest.mark.asyncio
async def test_actions_client_propagates_4xx_with_message_snippet():
    settings = _settings()
    with respx.mock() as router:
        router.post(f"{ACTIONS_BASE}/api/v1/actions").mock(
            return_value=httpx.Response(400, text="invalid action_type"),
        )
        client = AisocActionsClient.from_settings(settings, transport=httpx.MockTransport(router.handler))
        try:
            with pytest.raises(AisocClientError) as exc:
                await client.submit_action(
                    action_type="not_a_real_action",
                    target="host-1",
                    case_id="c1",
                    rationale="x",
                    requested_by="u1",
                )
        finally:
            await client.aclose()

    assert exc.value.status_code == 400
    assert "invalid action_type" in str(exc.value)
