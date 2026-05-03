"""Tests for AiSOCClient using httpx mock transport."""

from __future__ import annotations

import json
import pytest
import httpx

from aisoc_plugin_sdk import AiSOCClient, AiSOCClientError, PluginContext


@pytest.fixture
def ctx() -> PluginContext:
    return PluginContext(
        api_base_url="http://test-api:8000",
        api_token="test-token",
        config={},
    )


def _make_transport(responses: dict[str, tuple[int, dict]]) -> httpx.MockTransport:
    """Build an httpx mock transport from a {path: (status, body)} mapping."""

    def handler(request: httpx.Request) -> httpx.Response:
        key = f"{request.method} {request.url.path}"
        if key in responses:
            status, body = responses[key]
            return httpx.Response(status, json=body)
        return httpx.Response(404, json={"detail": "not found"})

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_get_case(ctx: PluginContext) -> None:
    transport = _make_transport({
        "GET /api/v1/cases/case-1": (200, {"id": "case-1", "title": "Test Case"}),
    })
    async with AiSOCClient(ctx) as client:
        client._http = httpx.AsyncClient(
            base_url=ctx.api_base_url,
            headers={"Authorization": f"Bearer {ctx.api_token}"},
            transport=transport,
        )
        result = await client.get_case("case-1")
    assert result["id"] == "case-1"
    assert result["title"] == "Test Case"


@pytest.mark.asyncio
async def test_add_case_note(ctx: PluginContext) -> None:
    transport = _make_transport({
        "POST /api/v1/cases/case-1/notes": (201, {"id": "note-1", "content": "hello"}),
    })
    async with AiSOCClient(ctx) as client:
        client._http = httpx.AsyncClient(
            base_url=ctx.api_base_url,
            headers={"Authorization": f"Bearer {ctx.api_token}"},
            transport=transport,
        )
        result = await client.add_case_note("case-1", "hello")
    assert result["content"] == "hello"


@pytest.mark.asyncio
async def test_patch_indicator(ctx: PluginContext) -> None:
    transport = _make_transport({
        "PATCH /api/v1/indicators/ind-1": (200, {"id": "ind-1", "enrichments": {"geo": "US"}}),
    })
    async with AiSOCClient(ctx) as client:
        client._http = httpx.AsyncClient(
            base_url=ctx.api_base_url,
            headers={"Authorization": f"Bearer {ctx.api_token}"},
            transport=transport,
        )
        result = await client.patch_indicator("ind-1", {"geo": "US"})
    assert result["enrichments"]["geo"] == "US"


@pytest.mark.asyncio
async def test_client_raises_on_error(ctx: PluginContext) -> None:
    transport = _make_transport({})  # returns 404 for everything

    async with AiSOCClient(ctx) as client:
        client._http = httpx.AsyncClient(
            base_url=ctx.api_base_url,
            headers={"Authorization": f"Bearer {ctx.api_token}"},
            transport=transport,
        )
        with pytest.raises(AiSOCClientError) as exc_info:
            await client.get_case("missing")

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_client_context_manager_required(ctx: PluginContext) -> None:
    client = AiSOCClient(ctx)
    with pytest.raises(RuntimeError, match="context manager"):
        await client.get_case("x")
