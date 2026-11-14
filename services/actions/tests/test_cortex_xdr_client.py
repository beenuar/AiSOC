"""Wave 0 — tests for :class:`CortexXdrClient`.

Locks the wire shapes (hostname -> endpoint_id resolution, isolate/unisolate
endpoints, Advanced-auth headers) so a Cortex XDR API drift breaks the test
before a customer.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.clients.cortex_xdr_client import CortexXdrClient

FQDN = "api-example.xdr.us.paloaltonetworks.com"


def _client() -> CortexXdrClient:
    return CortexXdrClient(api_key_id="42", api_key="secret", fqdn=FQDN)


@pytest.mark.asyncio
@respx.mock
async def test_contain_host_resolves_endpoint_and_isolates() -> None:
    captured: dict[str, object] = {}

    def resolve(request: httpx.Request) -> httpx.Response:
        captured["auth_id"] = request.headers.get("x-xdr-auth-id")
        captured["has_nonce"] = bool(request.headers.get("x-xdr-nonce"))
        return httpx.Response(200, json={"reply": {"endpoints": [{"endpoint_id": "ep-7"}]}})

    def isolate(request: httpx.Request) -> httpx.Response:
        captured["isolate_body"] = request.content.decode()
        return httpx.Response(200, json={"reply": {"action_id": "act-1"}})

    respx.post(f"https://{FQDN}/public_api/v1/endpoints/get_endpoint/").mock(side_effect=resolve)
    respx.post(f"https://{FQDN}/public_api/v1/endpoints/isolate").mock(side_effect=isolate)

    out = await _client().contain_host("ws-9")

    assert out["success"] is True
    assert out["endpoint_id"] == "ep-7"
    assert out["action_id"] == "act-1"
    assert captured["auth_id"] == "42"
    assert captured["has_nonce"] is True
    assert "ep-7" in str(captured["isolate_body"])


@pytest.mark.asyncio
@respx.mock
async def test_contain_host_raises_when_no_endpoint() -> None:
    respx.post(f"https://{FQDN}/public_api/v1/endpoints/get_endpoint/").mock(
        return_value=httpx.Response(200, json={"reply": {"endpoints": []}})
    )
    with pytest.raises(ValueError, match="No Cortex XDR endpoint"):
        await _client().contain_host("ghost")


@pytest.mark.asyncio
@respx.mock
async def test_lift_containment_calls_unisolate() -> None:
    respx.post(f"https://{FQDN}/public_api/v1/endpoints/get_endpoint/").mock(
        return_value=httpx.Response(200, json={"reply": {"endpoints": [{"endpoint_id": "ep-7"}]}})
    )
    route = respx.post(f"https://{FQDN}/public_api/v1/endpoints/unisolate").mock(
        return_value=httpx.Response(200, json={"reply": {"action_id": "act-2"}})
    )
    out = await _client().lift_containment("ws-9")
    assert route.called
    assert out["action"] == "lift_containment"
