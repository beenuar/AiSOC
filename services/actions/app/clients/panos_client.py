"""
Palo Alto Networks PAN-OS XML API client.

Wraps the subset of the PAN-OS XML API the AiSOC action layer needs:
add / remove an IP address to a dynamic address group via "register"
and "unregister" tag updates, and commit the candidate config when
the caller asks for it.

Why dynamic address groups (DAGs) instead of editing static address
objects: every reasonable PAN-OS deployment uses DAGs for
SOC-driven blocks because (a) tagged-IP changes don't require a
commit on PA-3000 / PA-5000 series boxes (they take effect inside
seconds via the user-id agent / runtime engine), (b) they round-trip
cleanly through Panorama, and (c) tagging is idempotent so AiSOC
can retry without leaving stale entries.

Credentials expected in ``ActionRequest.parameters``:

* ``panos_host``    — firewall management IP / FQDN.
* ``panos_api_key`` — generated via ``/api/?type=keygen&user=...``.
* ``panos_tag``     — tag the firewall's DAG is matched against
                      (e.g. ``aisoc-blocked``). The DAG itself
                      must already exist; AiSOC never creates it
                      because security teams own the policy layer.
* ``panos_vsys``    — vsys identifier, default ``vsys1``.

The client does not own a long-lived ``httpx.AsyncClient`` because
the PAN-OS XML API has session-bound caching surprises that bite
when the same connection straddles a commit; opening a new
connection per call is cheap (the firewall is on a low-latency
management network) and avoids those.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class PanOsClient:
    """Thin async wrapper over the PAN-OS XML API used by AiSOC."""

    def __init__(
        self,
        host: str,
        api_key: str,
        *,
        vsys: str = "vsys1",
        verify_tls: bool = True,
    ) -> None:
        self._base_url = f"https://{host}/api/"
        self._api_key = api_key
        self._vsys = vsys
        self._verify_tls = verify_tls

    def _xml_register(self, ip: str, tag: str) -> str:
        """Build the user-id message that tags ``ip`` with ``tag``.

        We persist the entry indefinitely (``timeout=0``) because
        AiSOC owns the block lifecycle; the firewall must not
        decide to silently release the block. Operators who want a
        TTL on the block should set it at the AiSOC playbook
        layer where it's auditable.
        """
        return (
            f"<uid-message>"
            f"<version>2.0</version><type>update</type>"
            f"<payload><register>"
            f'<entry ip="{ip}" persistent="1">'
            f"<tag><member>{tag}</member></tag>"
            f"</entry></register></payload></uid-message>"
        )

    def _xml_unregister(self, ip: str, tag: str) -> str:
        return (
            f"<uid-message>"
            f"<version>2.0</version><type>update</type>"
            f"<payload><unregister>"
            f'<entry ip="{ip}">'
            f"<tag><member>{tag}</member></tag>"
            f"</entry></unregister></payload></uid-message>"
        )

    async def _post_user_id(self, cmd: str) -> dict[str, Any]:
        params = {
            "type": "user-id",
            "key": self._api_key,
            "vsys": self._vsys,
            "cmd": cmd,
        }
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
            resp = await client.post(self._base_url, params=params)
            resp.raise_for_status()
            text = resp.text
            # PAN-OS returns 200 even for "status=error" payloads.
            # We surface the body so the executor logs something
            # actionable instead of a misleading success.
            if 'status="error"' in text:
                raise RuntimeError(f"PAN-OS XML API returned error: {text}")
            return {"status": "ok", "raw": text}

    async def block_ip(self, ip: str, tag: str) -> dict[str, Any]:
        """Register ``ip`` against the DAG matching ``tag``."""
        result = await self._post_user_id(self._xml_register(ip, tag))
        logger.info("panos.block_ip.success", ip=ip, tag=tag, vsys=self._vsys)
        return {
            "success": True,
            "action": "block_ip",
            "ip": ip,
            "tag": tag,
            "vsys": self._vsys,
            "raw": result["raw"],
        }

    async def unblock_ip(self, ip: str, tag: str) -> dict[str, Any]:
        result = await self._post_user_id(self._xml_unregister(ip, tag))
        logger.info("panos.unblock_ip.success", ip=ip, tag=tag, vsys=self._vsys)
        return {
            "success": True,
            "action": "unblock_ip",
            "ip": ip,
            "tag": tag,
            "vsys": self._vsys,
            "raw": result["raw"],
        }
