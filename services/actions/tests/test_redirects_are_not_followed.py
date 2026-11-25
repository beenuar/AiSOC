"""A redirect is a second URL the SSRF guard never saw (GHSA-hfgq-46wx-m6g5).

The dispatcher validates the caller-supplied ``base_url`` before dispatch,
but validation has single-URL scope: a public host that answers 302 with an
internal ``Location`` would have its redirect followed by the vendor client
— straight past the guard to cloud metadata or an internal service. Every
other outbound path aimed at a caller- or admin-supplied URL already sets
``follow_redirects=False`` (``saml_metadata``, ``llm_model_discovery``,
``hunt/from_report``); these two clients are held to the same rule, proven
through a real redirecting transport rather than a mock of the client.
"""

from __future__ import annotations

import httpx
import pytest
from app.clients.fleetdm_client import FleetDMClient, FleetDMError
from app.clients.osctrl_client import OsctrlClient, OsctrlError


class _RedirectingTransport(httpx.AsyncBaseTransport):
    """Answers 302-to-internal for the first hop; records any second hop."""

    def __init__(self) -> None:
        self.requests: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if request.url.host == "169.254.169.254":
            return httpx.Response(200, text="latest/meta-data")
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})


@pytest.mark.asyncio
async def test_osctrl_client_refuses_a_redirect_instead_of_following_it() -> None:
    transport = _RedirectingTransport()
    client = OsctrlClient(base_url="https://public.example.com", api_token="t", environment="prod")
    http = client._client()
    assert http.follow_redirects is False, (
        "the client must not follow redirects: the Location is a URL the dispatcher's SSRF guard never validated"
    )
    await http.aclose()

    # Through a real transport: the 302 must surface as a vendor error with
    # no second request, never a silent hop to the Location target.
    guarded = httpx.AsyncClient(transport=transport, follow_redirects=http.follow_redirects)
    with pytest.raises(OsctrlError):
        await client._submit_query(guarded, "SELECT 1;", ["h1"])
    assert transport.requests == ["https://public.example.com/api/v1/queries/prod"], f"a second hop was made: {transport.requests}"
    await guarded.aclose()


@pytest.mark.asyncio
async def test_fleetdm_client_refuses_a_redirect_instead_of_following_it() -> None:
    transport = _RedirectingTransport()
    client = FleetDMClient(base_url="https://public.example.com", api_token="t")
    http = client._client()
    assert http.follow_redirects is False
    await http.aclose()

    guarded = httpx.AsyncClient(transport=transport, follow_redirects=http.follow_redirects)
    with pytest.raises(FleetDMError):
        await client._create_campaign(guarded, "SELECT 1;", ["h1"])
    assert transport.requests[0].startswith("https://public.example.com/"), transport.requests
    assert len(transport.requests) == 1, f"a second hop was made: {transport.requests}"
    await guarded.aclose()
