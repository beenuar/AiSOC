"""
Phase 3.1 — tests for :class:`SentinelOneClient`.

We exercise the real HTTP shapes (URLs, payloads, headers) the
client sends to a SentinelOne console via respx, plus the explicit
``NotImplementedError`` paths the client uses for actions S1's
management API doesn't support. The goal is to lock the wire
format down so an API drift on the S1 side breaks the test before
it breaks a customer.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.clients.sentinelone_client import SentinelOneClient

BASE = "https://usea1-partners.sentinelone.net"
TOKEN = "abcdef-fake-token"
PREFIX = f"{BASE}/web/api/v2.1"


def _client() -> SentinelOneClient:
    return SentinelOneClient(console_url=BASE, api_token=TOKEN)


@pytest.mark.asyncio
@respx.mock
async def test_find_agent_uses_apitoken_header_and_returns_agent() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("Authorization", "")
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"data": [{"uuid": "u-1", "computerName": "web-01"}]})

    respx.get(f"{PREFIX}/agents").mock(side_effect=respond)
    agent = await _client().find_agent("web-01")

    assert agent == {"uuid": "u-1", "computerName": "web-01"}
    assert captured["auth"] == f"ApiToken {TOKEN}"
    assert "computerName=web-01" in captured["url"]


@pytest.mark.asyncio
@respx.mock
async def test_find_agent_returns_none_when_no_match() -> None:
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(200, json={"data": []}))
    agent = await _client().find_agent("missing-host")
    assert agent is None


@pytest.mark.asyncio
@respx.mock
async def test_contain_host_disconnects_resolved_uuid() -> None:
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(200, json={"data": [{"uuid": "u-42"}]}))
    captured: dict[str, dict] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"data": {"affected": 1}})

    respx.post(f"{PREFIX}/agents/actions/disconnect").mock(side_effect=respond)

    result = await _client().contain_host("web-01")

    assert result["success"] is True
    assert result["agent_uuid"] == "u-42"
    assert result["affected"] == 1
    assert "u-42" in captured["body"]


@pytest.mark.asyncio
@respx.mock
async def test_contain_host_raises_when_agent_unknown() -> None:
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(200, json={"data": []}))
    with pytest.raises(ValueError, match="No SentinelOne agent found"):
        await _client().contain_host("nope")


@pytest.mark.asyncio
@respx.mock
async def test_lift_containment_reconnects_uuid() -> None:
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(200, json={"data": [{"uuid": "u-7"}]}))
    respx.post(f"{PREFIX}/agents/actions/connect").mock(return_value=httpx.Response(200, json={"data": {"affected": 1}}))

    result = await _client().lift_containment("web-02")
    assert result["action"] == "lift_containment"
    assert result["agent_uuid"] == "u-7"


@pytest.mark.asyncio
@respx.mock
async def test_kill_process_requires_process_name() -> None:
    """SentinelOne can't kill by PID alone — verify the explicit
    NotImplementedError so callers don't get a silent no-op."""
    with pytest.raises(NotImplementedError, match="PID alone"):
        await _client().kill_process("web-01", pid=4321)


@pytest.mark.asyncio
@respx.mock
async def test_kill_process_with_process_name_dispatches() -> None:
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(200, json={"data": [{"uuid": "u-9"}]}))
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"data": {"affected": 1}})

    respx.post(f"{PREFIX}/agents/actions/initiate-scan").mock(side_effect=respond)

    result = await _client().kill_process("web-01", process_name="evil.exe")
    assert result["action"] == "kill_process"
    assert result["process_name"] == "evil.exe"
    assert "evil.exe" in captured["body"]


@pytest.mark.asyncio
@respx.mock
async def test_quarantine_file_enqueues_fetch() -> None:
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(200, json={"data": [{"uuid": "u-12"}]}))
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"data": {"affected": 1}})

    respx.post(f"{PREFIX}/agents/actions/fetch-files").mock(side_effect=respond)

    result = await _client().quarantine_file("web-01", "/tmp/malware.bin")
    assert result["success"] is True
    assert "/tmp/malware.bin" in captured["body"]
    assert "forensics vault" in result["note"]


@pytest.mark.asyncio
@respx.mock
async def test_run_av_scan_dispatches_initiate_scan() -> None:
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(200, json={"data": [{"uuid": "u-55"}]}))
    respx.post(f"{PREFIX}/agents/actions/initiate-scan").mock(return_value=httpx.Response(200, json={"data": {"affected": 1}}))

    result = await _client().run_av_scan("web-01")
    assert result["action"] == "run_av_scan"
    assert result["scan_type"] == "Full"


@pytest.mark.asyncio
async def test_run_script_is_not_supported() -> None:
    with pytest.raises(NotImplementedError, match="non-interactive remote"):
        await _client().run_script("web-01", "Write-Host 'hi'")


@pytest.mark.asyncio
@respx.mock
async def test_http_error_propagates_for_observability() -> None:
    """A 401 from S1 must propagate so the executor logs a vendor
    failure instead of swallowing it as a no-result."""
    respx.get(f"{PREFIX}/agents").mock(return_value=httpx.Response(401, json={"errors": [{"detail": "expired token"}]}))
    with pytest.raises(httpx.HTTPStatusError):
        await _client().find_agent("web-01")
