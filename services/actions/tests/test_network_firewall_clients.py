"""
Phase 3.2 — tests for the new network-firewall clients
(:class:`PanOsClient`, :class:`FortiGateClient`,
:class:`CloudflareClient`).

We verify the wire shape — URLs, payloads, headers, error
handling — that each vendor expects, because these clients are
the contact surface where API drift on the vendor's side will
silently break customer deployments. Wire-shape locking is
what catches that drift in CI before a customer does.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.clients.cloudflare_client import CloudflareClient, CloudflareError
from app.clients.fortigate_client import FortiGateClient
from app.clients.panos_client import PanOsClient

# ────────────────────────────────────────────────────────────────────
# PAN-OS
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_panos_block_ip_sends_register_xml() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, text='<response status="success"/>')

    respx.post("https://panfw.example.com/api/").mock(side_effect=respond)

    client = PanOsClient(
        host="panfw.example.com",
        api_key="K3Y",
        vsys="vsys1",
        verify_tls=False,
    )
    result = await client.block_ip(ip="1.2.3.4", tag="aisoc-blocked")

    assert result["success"] is True
    assert result["ip"] == "1.2.3.4"
    assert "type=user-id" in captured["url"]
    assert "vsys=vsys1" in captured["url"]
    assert "register" in captured["url"]
    assert "1.2.3.4" in captured["url"]


@pytest.mark.asyncio
@respx.mock
async def test_panos_error_status_in_200_body_is_surfaced() -> None:
    """PAN-OS returns 200 with an error envelope when the IP is
    already tagged; the client must propagate that as an exception
    so the executor logs vendor failure instead of pretending
    success."""
    respx.post("https://panfw.example.com/api/").mock(
        return_value=httpx.Response(200, text='<response status="error"><msg>oops</msg></response>')
    )
    client = PanOsClient(host="panfw.example.com", api_key="K3Y", verify_tls=False)

    with pytest.raises(RuntimeError, match="PAN-OS XML API returned error"):
        await client.block_ip(ip="9.9.9.9", tag="aisoc-blocked")


@pytest.mark.asyncio
@respx.mock
async def test_panos_unblock_uses_unregister_payload() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, text='<response status="success"/>')

    respx.post("https://panfw.example.com/api/").mock(side_effect=respond)

    client = PanOsClient(host="panfw.example.com", api_key="K3Y", verify_tls=False)
    result = await client.unblock_ip(ip="1.2.3.4", tag="aisoc-blocked")

    assert result["action"] == "unblock_ip"
    assert "unregister" in captured["url"]


# ────────────────────────────────────────────────────────────────────
# FortiGate
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_fortigate_block_ip_creates_address_and_extends_group() -> None:
    """The happy path: address object doesn't exist yet, group has
    one existing member, both URLs are called with the bearer
    token."""
    name = "aisoc-1.2.3.4"
    base = "https://fgt.example.com/api/v2/cmdb/firewall"
    auth_seen: list[str] = []

    def address_create(request: httpx.Request) -> httpx.Response:
        auth_seen.append(request.headers.get("Authorization", ""))
        return httpx.Response(200, json={"status": "success"})

    def group_get(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": [{"name": "blocked", "member": [{"name": "existing"}]}]})

    def group_put(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "success"})

    respx.post(f"{base}/address/").mock(side_effect=address_create)
    respx.get(f"{base}/addrgrp/blocked").mock(side_effect=group_get)
    respx.put(f"{base}/addrgrp/blocked").mock(side_effect=group_put)

    client = FortiGateClient(host="fgt.example.com", api_token="T0K", verify_tls=False)
    result = await client.block_ip(ip="1.2.3.4", group="blocked")

    assert result["success"] is True
    assert name in result["members"]
    assert "existing" in result["members"]
    assert all(a == "Bearer T0K" for a in auth_seen)


@pytest.mark.asyncio
@respx.mock
async def test_fortigate_block_ip_skips_put_when_already_member() -> None:
    """Idempotency: if the address is already in the group, we
    don't issue a PUT (no-op writes still risk replacing a member
    list that was mutated concurrently)."""
    name = "aisoc-1.2.3.4"
    base = "https://fgt.example.com/api/v2/cmdb/firewall"

    respx.post(f"{base}/address/").mock(return_value=httpx.Response(200, json={"status": "success"}))
    respx.get(f"{base}/addrgrp/blocked").mock(
        return_value=httpx.Response(200, json={"results": [{"name": "blocked", "member": [{"name": name}]}]})
    )
    put_route = respx.put(f"{base}/addrgrp/blocked").mock(return_value=httpx.Response(200, json={"status": "success"}))

    client = FortiGateClient(host="fgt.example.com", api_token="T0K", verify_tls=False)
    await client.block_ip(ip="1.2.3.4", group="blocked")

    assert put_route.call_count == 0


@pytest.mark.asyncio
@respx.mock
async def test_fortigate_unblock_leaves_sentinel_member() -> None:
    """When the only remaining member is the IP we're removing,
    we insert "all" as a sentinel so FortiGate doesn't reject the
    PUT with an empty member list."""
    name = "aisoc-1.2.3.4"
    base = "https://fgt.example.com/api/v2/cmdb/firewall"
    captured_body: dict[str, str] = {}

    def group_put(request: httpx.Request) -> httpx.Response:
        captured_body["body"] = request.read().decode()
        return httpx.Response(200, json={"status": "success"})

    respx.get(f"{base}/addrgrp/blocked").mock(
        return_value=httpx.Response(200, json={"results": [{"name": "blocked", "member": [{"name": name}]}]})
    )
    respx.put(f"{base}/addrgrp/blocked").mock(side_effect=group_put)

    client = FortiGateClient(host="fgt.example.com", api_token="T0K", verify_tls=False)
    result = await client.unblock_ip(ip="1.2.3.4", group="blocked")

    assert result["members"] == ["all"]
    assert '"all"' in captured_body["body"]


@pytest.mark.asyncio
@respx.mock
async def test_fortigate_unknown_group_raises_value_error() -> None:
    base = "https://fgt.example.com/api/v2/cmdb/firewall"

    respx.post(f"{base}/address/").mock(return_value=httpx.Response(200, json={"status": "success"}))
    respx.get(f"{base}/addrgrp/missing").mock(return_value=httpx.Response(200, json={"results": []}))

    client = FortiGateClient(host="fgt.example.com", api_token="T0K", verify_tls=False)
    with pytest.raises(ValueError, match="addrgrp 'missing' not found"):
        await client.block_ip(ip="1.2.3.4", group="missing")


# ────────────────────────────────────────────────────────────────────
# Cloudflare
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_block_ip_zone_returns_rule_id() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        captured["auth"] = request.headers["Authorization"]
        return httpx.Response(
            200,
            json={"success": True, "errors": [], "messages": [], "result": {"id": "rule-001"}},
        )

    url = "https://api.cloudflare.com/client/v4/zones/Z1/rulesets/phases/http_request_firewall_custom/entrypoint/rules"
    respx.post(url).mock(side_effect=respond)

    client = CloudflareClient(api_token="cf-token")
    result = await client.block_ip_zone(ip="1.2.3.4", zone_id="Z1", description="test block")

    assert result["rule_id"] == "rule-001"
    assert captured["auth"] == "Bearer cf-token"
    assert "ip.src eq 1.2.3.4" in captured["body"]


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_unblock_ip_zone_deletes_rule_by_id() -> None:
    url = "https://api.cloudflare.com/client/v4/zones/Z1/rulesets/phases/" "http_request_firewall_custom/entrypoint/rules/rule-001"
    respx.delete(url).mock(return_value=httpx.Response(200, json={"success": True, "result": {}}))

    client = CloudflareClient(api_token="cf-token")
    result = await client.unblock_ip_zone(rule_id="rule-001", zone_id="Z1")
    assert result["success"] is True


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_sinkhole_domain_appends_to_list() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(
            200,
            json={"success": True, "errors": [], "messages": [], "result": {"items_count": 7}},
        )

    url = "https://api.cloudflare.com/client/v4/accounts/A1/gateway/lists/L1/items"
    respx.patch(url).mock(side_effect=respond)

    client = CloudflareClient(api_token="cf-token")
    result = await client.sinkhole_domain(domain="evil.example", account_id="A1", list_id="L1")

    assert result["domain"] == "evil.example"
    assert '"value":"evil.example"' in captured["body"].replace(" ", "")


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_success_false_raises_cloudflareerror() -> None:
    """The unwrap helper must convert ``success: false`` payloads
    into a typed exception so the executor catches them by name."""
    url = "https://api.cloudflare.com/client/v4/zones/Z1/rulesets/phases/http_request_firewall_custom/entrypoint/rules"
    respx.post(url).mock(
        return_value=httpx.Response(
            200,
            json={"success": False, "errors": [{"code": 10000, "message": "bad zone"}], "result": None},
        )
    )

    client = CloudflareClient(api_token="cf-token")
    with pytest.raises(CloudflareError, match="Cloudflare API error"):
        await client.block_ip_zone(ip="1.2.3.4", zone_id="Z1")
