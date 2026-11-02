"""
Cloudflare client for IP block, IP allow, and DNS sinkholing.

Cloudflare exposes three orthogonal block / allow surfaces and the
AiSOC playbook layer wants all three:

1. **Zone-level WAF custom rules** — block IPs from reaching a
   specific domain. Most surgical; what marketing teams want when a
   single tenant is under attack.
2. **Account-level lists + custom rules** — block IPs across every
   zone in the account. What enterprise teams want when an IP is
   bad full-stop.
3. **Cloudflare Gateway DNS policies** — sinkhole an outbound
   domain across the corporate device fleet. The "DNS firewall"
   half of Phase 3.2.

This client implements (1) via the rulesets API and (3) via the
Gateway API. (2) shares the rulesets API with (1) and is exposed
through ``block_ip(scope="account")``. We deliberately do not
implement Cloudflare's "Zone Settings → IP Access Rules" endpoint
because it is the *legacy* surface that Cloudflare is migrating
away from; using rulesets keeps us forward-compatible.

Credentials expected in ``ActionRequest.parameters``:

* ``cf_api_token``    — bearer token. Either an account-scoped
                        token for account-wide blocks or a
                        zone-scoped token for domain-level blocks.
* ``cf_account_id``   — account ID (required for Gateway DNS and
                        account-level WAF).
* ``cf_zone_id``      — zone ID (required for zone-level WAF).
* ``cf_block_list_id``— Gateway destination list to add domains
                        to (must already exist; AiSOC never
                        creates it).
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_BASE = "https://api.cloudflare.com/client/v4"


class CloudflareError(RuntimeError):
    """Raised when Cloudflare returns ``success: false``."""


class CloudflareClient:
    """Async wrapper over Cloudflare REST APIs for AiSOC block actions."""

    def __init__(self, api_token: str) -> None:
        self._token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _unwrap(resp: httpx.Response) -> dict[str, Any]:
        """Cloudflare wraps every payload in ``{success, errors, result}``.

        We unwrap so the executor logs the relevant ``result`` block
        rather than a noisy envelope, and surface ``success: false``
        as a ``CloudflareError`` so the executor's try/except path
        captures the right exception type.
        """
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success", False):
            raise CloudflareError(f"Cloudflare API error: {body.get('errors')}")
        return body.get("result") or {}

    async def block_ip_zone(self, ip: str, zone_id: str, description: str = "AiSOC block") -> dict[str, Any]:
        """Add a zone-level WAF custom rule that blocks ``ip``.

        We use the rulesets API's "entrypoint" (phase
        ``http_request_firewall_custom``) because that's the
        attachment point custom rules live at on every zone.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            rule = {
                "action": "block",
                "expression": f"(ip.src eq {ip})",
                "description": description,
                "enabled": True,
            }
            url = f"{_BASE}/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint/rules"
            resp = await client.post(url, headers=self._headers(), json=rule)
            result = self._unwrap(resp)
            logger.info("cloudflare.block_ip_zone.success", ip=ip, zone_id=zone_id)
            return {"success": True, "action": "block_ip", "ip": ip, "zone_id": zone_id, "rule_id": result.get("id")}

    async def unblock_ip_zone(self, rule_id: str, zone_id: str) -> dict[str, Any]:
        """Remove a WAF custom rule by rule_id."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"{_BASE}/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint/rules/{rule_id}"
            resp = await client.delete(url, headers=self._headers())
            resp.raise_for_status()
            logger.info("cloudflare.unblock_ip_zone.success", rule_id=rule_id, zone_id=zone_id)
            return {"success": True, "action": "unblock_ip", "rule_id": rule_id}

    async def sinkhole_domain(self, domain: str, account_id: str, list_id: str) -> dict[str, Any]:
        """Append ``domain`` to a Cloudflare Gateway destination list.

        The list must already be attached to a Gateway "Block" DNS
        policy (security teams own the policy layer; we just feed
        domains to its target list).
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"{_BASE}/accounts/{account_id}/gateway/lists/{list_id}/items"
            payload = {
                "append": [{"value": domain}],
                "remove": [],
            }
            resp = await client.patch(url, headers=self._headers(), json=payload)
            result = self._unwrap(resp)
            logger.info("cloudflare.sinkhole_domain.success", domain=domain, list_id=list_id)
            return {
                "success": True,
                "action": "block_domain",
                "domain": domain,
                "list_id": list_id,
                "result": result,
            }

    async def unsinkhole_domain(self, domain: str, account_id: str, list_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"{_BASE}/accounts/{account_id}/gateway/lists/{list_id}/items"
            payload = {
                "append": [],
                "remove": [domain],
            }
            resp = await client.patch(url, headers=self._headers(), json=payload)
            result = self._unwrap(resp)
            logger.info("cloudflare.unsinkhole_domain.success", domain=domain, list_id=list_id)
            return {
                "success": True,
                "action": "unblock_domain",
                "domain": domain,
                "list_id": list_id,
                "result": result,
            }

    # ------------------------------------------------------------------
    # Wave-2 Phase 6.1: Gateway URL lists
    # ------------------------------------------------------------------
    #
    # `sinkhole_domain` above feeds a DOMAIN-typed Gateway list. A URL list
    # is the same endpoint against a list whose type is URL, which is what
    # contains a single phishing page without taking down everything else
    # on the host.
    #
    # Reference, fetched before these were written:
    #   https://developers.cloudflare.com/api/resources/zero_trust/subresources/gateway/subresources/lists/methods/edit/
    #   https://developers.cloudflare.com/cloudflare-one/traffic-policies/lists/

    async def _edit_gateway_list(self, account_id: str, list_id: str, *, append: list[str], remove: list[str]) -> dict[str, Any]:
        """PATCH a Gateway list incrementally.

        Incremental rather than replace: two concurrent containments that
        each read, modify and write a shared list lose one of the two
        entries, and the losing action still reports success.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.patch(
                f"{_BASE}/accounts/{account_id}/gateway/lists/{list_id}/items",
                headers=self._headers(),
                json={"append": [{"value": value} for value in append], "remove": remove},
            )
            return self._unwrap(resp)

    async def block_url(self, url: str, account_id: str, list_id: str) -> dict[str, Any]:
        result = await self._edit_gateway_list(account_id, list_id, append=[url], remove=[])
        logger.info("cloudflare.block_url.success", url=url, list_id=list_id)
        return {"success": True, "action": "block_url", "url": url, "list_id": list_id, "result": result}

    async def allow_url(self, url: str, account_id: str, list_id: str) -> dict[str, Any]:
        result = await self._edit_gateway_list(account_id, list_id, append=[], remove=[url])
        logger.info("cloudflare.allow_url.success", url=url, list_id=list_id)
        return {"success": True, "action": "allow_url", "url": url, "list_id": list_id, "result": result}

    async def get_gateway_list_items(self, account_id: str, list_id: str) -> list[str]:
        """Read a Gateway list's entries back. The probe for the arms above."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{_BASE}/accounts/{account_id}/gateway/lists/{list_id}/items",
                headers=self._headers(),
            )
            result = self._unwrap(resp)
        rows = result if isinstance(result, list) else (result or {}).get("result") or []
        return [str(row.get("value")) for row in rows if isinstance(row, dict) and row.get("value")]
