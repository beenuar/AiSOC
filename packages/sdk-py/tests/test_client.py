"""Unit tests for the aisoc-sdk Python client.

Uses pytest-httpx to intercept outgoing requests — no real server needed.
"""

from __future__ import annotations

import json
import pytest
from pytest_httpx import HTTPXMock

from aisoc_sdk import AiSOCClient, AiSOCError
from aisoc_sdk.models import AlertSeverity, AlertStatus


BASE_URL = "https://aisoc.test"
TOKEN = "aisoc_test_token"


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
async def client():
    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as c:
        yield c


# ─── Alert tests ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_list(httpx_mock: HTTPXMock):
    page_data = {
        "items": [
            {
                "id": "a1",
                "tenant_id": "t1",
                "title": "Test Alert",
                "severity": "critical",
                "status": "open",
                "source": "siem",
                "mitre_tactics": [],
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
            }
        ],
        "total": 1,
        "page": 1,
        "page_size": 20,
    }
    httpx_mock.add_response(json=page_data)

    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as client:
        page = await client.alerts.list()

    assert page.total == 1
    assert page.items[0].id == "a1"
    assert page.items[0].severity == AlertSeverity.CRITICAL


@pytest.mark.asyncio
async def test_alerts_get(httpx_mock: HTTPXMock):
    alert_data = {
        "id": "a42",
        "tenant_id": "t1",
        "title": "Critical Alert",
        "severity": "high",
        "status": "in_progress",
        "source": "edr",
        "mitre_tactics": ["TA0001"],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    httpx_mock.add_response(json=alert_data)

    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as client:
        alert = await client.alerts.get("a42")

    assert alert.id == "a42"
    assert alert.status == AlertStatus.IN_PROGRESS


# ─── Case tests ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cases_create(httpx_mock: HTTPXMock):
    case_data = {
        "id": "c1",
        "tenant_id": "t1",
        "case_number": "CASE-001",
        "title": "Incident",
        "status": "open",
        "priority": "high",
        "mitre_tactics": [],
        "alert_ids": [],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
    }
    httpx_mock.add_response(status_code=201, json=case_data)

    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as client:
        case = await client.cases.create(title="Incident", priority="high")

    assert case.id == "c1"
    assert case.case_number == "CASE-001"


@pytest.mark.asyncio
async def test_cases_delete(httpx_mock: HTTPXMock):
    httpx_mock.add_response(status_code=204)

    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as client:
        result = await client.cases.delete("c1")

    assert result is None


# ─── Error handling ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_raises_aisoc_error_on_404(httpx_mock: HTTPXMock):
    httpx_mock.add_response(status_code=404, json={"detail": "Not found"})

    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as client:
        with pytest.raises(AiSOCError) as exc_info:
            await client.alerts.get("missing")

    assert exc_info.value.status_code == 404
    assert "Not found" in exc_info.value.detail


@pytest.mark.asyncio
async def test_raises_aisoc_error_on_403(httpx_mock: HTTPXMock):
    httpx_mock.add_response(status_code=403, json={"detail": "Forbidden"})

    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as client:
        with pytest.raises(AiSOCError) as exc_info:
            await client.cases.list()

    assert exc_info.value.status_code == 403


# ─── Auth header ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bearer_token_is_sent(httpx_mock: HTTPXMock):
    httpx_mock.add_response(json={"items": [], "total": 0, "page": 1, "page_size": 20})

    async with AiSOCClient(base_url=BASE_URL, token="aisoc_my_secret") as client:
        await client.alerts.list()

    request = httpx_mock.get_requests()[0]
    assert request.headers["Authorization"] == "Bearer aisoc_my_secret"


# ─── Context manager ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_context_manager_required():
    client = AiSOCClient(base_url=BASE_URL, token=TOKEN)
    with pytest.raises(RuntimeError):
        await client.graphql("{ __typename }")


# ─── GraphQL ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_graphql_query(httpx_mock: HTTPXMock):
    httpx_mock.add_response(json={"data": {"__typename": "Query"}})

    async with AiSOCClient(base_url=BASE_URL, token=TOKEN) as client:
        result = await client.graphql("{ __typename }")

    assert result["data"]["__typename"] == "Query"
