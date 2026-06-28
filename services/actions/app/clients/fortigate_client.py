"""
Fortinet FortiGate REST API client.

Wraps the small surface AiSOC needs: add or remove an IP entry on
an existing address group, so downstream firewall policies that
reference the group either deny or allow the IP. We never create
the group; security teams own that.

Credentials expected in ``ActionRequest.parameters``:

* ``fgt_host``         — firewall management IP / FQDN.
* ``fgt_api_token``    — REST API token from
                         "System → Administrators → REST API Admin".
* ``fgt_address_group``— group name to modify
                         (e.g. ``aisoc-blocked``).
* ``fgt_vdom``         — vdom to address, default ``root``.

API surface
-----------

* ``POST /api/v2/cmdb/firewall/address/{name}`` — create an
  address object named after the IP if it doesn't already exist.
* ``GET /api/v2/cmdb/firewall/addrgrp/{group}`` — fetch current
  members so we can splice the new one in.
* ``PUT /api/v2/cmdb/firewall/addrgrp/{group}`` — write back the
  full member list.

FortiGate has no "append-only" verb for address groups; the whole
member list must be PUT each time. We do a read-modify-write that
is safe under low churn (the typical SOC dispatch rate) but is
*not* safe under concurrent writers. The executor layer is the only
writer in our deployment, so this is fine; if that changes the
caller must wrap us in a lock.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class FortiGateClient:
    """Minimal async REST client for FortiGate address-group management."""

    def __init__(
        self,
        host: str,
        api_token: str,
        *,
        vdom: str = "root",
        verify_tls: bool = True,
    ) -> None:
        self._base_url = f"https://{host}/api/v2"
        self._token = api_token
        self._vdom = vdom
        self._verify_tls = verify_tls

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _params(self) -> dict[str, str]:
        return {"vdom": self._vdom}

    async def _ensure_address(self, client: httpx.AsyncClient, ip: str, name: str) -> None:
        """Create the address object if absent. 200 + existing object
        is also acceptable (we treat that as idempotent), which is
        why we accept a 200 or a 424."""
        resp = await client.post(
            f"{self._base_url}/cmdb/firewall/address/",
            params=self._params(),
            headers=self._headers(),
            json={
                "name": name,
                "type": "ipmask",
                "subnet": f"{ip} 255.255.255.255",
                "comment": "Created by AiSOC",
            },
        )
        # 200 = created. 500/424 with "Entry already exists" = OK.
        if resp.status_code not in (200, 424):
            try:
                body = resp.json()
            except Exception:
                body = {"text": resp.text}
            if not (resp.status_code == 500 and "exists" in str(body).lower()):
                resp.raise_for_status()

    async def _read_group_members(self, client: httpx.AsyncClient, group: str) -> list[str]:
        resp = await client.get(
            f"{self._base_url}/cmdb/firewall/addrgrp/{group}",
            params=self._params(),
            headers=self._headers(),
        )
        resp.raise_for_status()
        body = resp.json()
        results = body.get("results") or []
        if not results:
            raise ValueError(f"FortiGate addrgrp '{group}' not found")
        member_objs = results[0].get("member") or []
        return [m["name"] for m in member_objs]

    async def _write_group_members(self, client: httpx.AsyncClient, group: str, names: list[str]) -> None:
        resp = await client.put(
            f"{self._base_url}/cmdb/firewall/addrgrp/{group}",
            params=self._params(),
            headers=self._headers(),
            json={"member": [{"name": n} for n in names]},
        )
        resp.raise_for_status()

    def _address_name(self, ip: str) -> str:
        """The address-object name we use when registering an IP.

        FortiGate restricts object names to 79 chars, alphanumeric
        + ``-_.`` — IPv4 dotted-quad is fine, IPv6 needs colons
        rewritten to dashes.
        """
        return "aisoc-" + ip.replace(":", "-")

    async def block_ip(self, ip: str, group: str) -> dict[str, Any]:
        """Idempotently add ``ip`` to FortiGate address group ``group``."""
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
            name = self._address_name(ip)
            await self._ensure_address(client, ip, name)
            members = await self._read_group_members(client, group)
            if name not in members:
                members.append(name)
                await self._write_group_members(client, group, members)
            logger.info("fortigate.block_ip.success", ip=ip, group=group, vdom=self._vdom)
            return {
                "success": True,
                "action": "block_ip",
                "ip": ip,
                "group": group,
                "address_name": name,
                "vdom": self._vdom,
                "members": members,
            }

    async def unblock_ip(self, ip: str, group: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
            name = self._address_name(ip)
            members = await self._read_group_members(client, group)
            if name in members:
                members.remove(name)
                if not members:
                    # FortiGate refuses to PUT an empty member list,
                    # so we leave a sentinel "all" entry to keep the
                    # group valid. Operators who want to delete the
                    # group entirely should do so by hand — AiSOC
                    # never removes policy objects.
                    members = ["all"]
                await self._write_group_members(client, group, members)
            logger.info("fortigate.unblock_ip.success", ip=ip, group=group, vdom=self._vdom)
            return {
                "success": True,
                "action": "unblock_ip",
                "ip": ip,
                "group": group,
                "address_name": name,
                "vdom": self._vdom,
                "members": members,
            }
