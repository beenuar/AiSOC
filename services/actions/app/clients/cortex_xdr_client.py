"""Cortex XDR client for the AiSOC action executor.

Wraps the Cortex XDR public REST API
(``https://<fqdn>/public_api/v1/``) for the endpoint containment actions the
response layer needs: network-isolate a host and lift that isolation.

Credentials are passed via :class:`ActionRequest.parameters`:

* ``cortex_api_key_id`` — the API key *id* (the integer shown next to the key
  in "Settings -> API Keys").
* ``cortex_api_key``    — the API key secret. Cortex XDR "Advanced" keys sign
  each request with a per-call nonce + timestamp (see :meth:`_headers`), which
  is what this client implements.
* ``cortex_fqdn``       — the tenant API FQDN
  (e.g. ``api-example.xdr.us.paloaltonetworks.com``).

API surface
-----------

We mirror the EDR client method shape (``contain_host`` / ``lift_containment``)
so :class:`IsolateHostExecutor` can dispatch through a uniform interface. Both
verbs first resolve ``hostname -> endpoint_id`` via ``get_endpoint`` because the
isolate/unisolate endpoints act on an endpoint id, not a hostname.

Design notes
------------

* Cortex XDR "Advanced" API keys require the same nonce/timestamp/SHA-256 auth
  the pull connector uses, so this client is self-contained and needs no OAuth
  refresh flow.
* All HTTP traffic uses a 30s timeout; the isolate endpoint schedules the action
  asynchronously on the endpoint, so a 200 means "accepted", not "isolated".
"""

from __future__ import annotations

import hashlib
import secrets
import string
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class CortexXdrClient:
    """Thin async wrapper over the Cortex XDR public API."""

    def __init__(self, *, api_key_id: str, api_key: str, fqdn: str) -> None:
        self._api_key_id = str(api_key_id)
        self._api_key = api_key
        self._fqdn = fqdn.rstrip("/")

    def _headers(self) -> dict[str, str]:
        # Cortex XDR "Advanced" auth: the vendor protocol signs each request by
        # SHA-256'ing (api_key + nonce + timestamp). This is a per-request
        # signature over an ephemeral 64-char nonce — NOT password-at-rest
        # hashing, so a slow password hash (bcrypt/argon2) does not apply.
        # SHA-256 is mandated by the Cortex XDR API; mirrors CortexXDRConnector.
        nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        timestamp = str(int(datetime.now(UTC).timestamp()) * 1000)
        auth_string = f"{self._api_key}{nonce}{timestamp}"
        signature = hashlib.sha256(auth_string.encode()).hexdigest()  # lgtm[py/weak-sensitive-data-hashing]
        return {
            "x-xdr-auth-id": self._api_key_id,
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "Authorization": signature,
            "Content-Type": "application/json",
        }

    async def _resolve_endpoint_id(self, client: httpx.AsyncClient, hostname: str) -> str:
        resp = await client.post(
            f"https://{self._fqdn}/public_api/v1/endpoints/get_endpoint/",
            headers=self._headers(),
            json={"request_data": {"filters": [{"field": "hostname", "operator": "in", "value": [hostname]}]}},
        )
        resp.raise_for_status()
        endpoints = resp.json().get("reply", {}).get("endpoints", [])
        if not endpoints:
            raise ValueError(f"No Cortex XDR endpoint found for hostname: {hostname}")
        return str(endpoints[0]["endpoint_id"])

    async def contain_host(self, hostname: str) -> dict[str, Any]:
        """Network-isolate an endpoint from everything but Cortex XDR."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            endpoint_id = await self._resolve_endpoint_id(client, hostname)
            resp = await client.post(
                f"https://{self._fqdn}/public_api/v1/endpoints/isolate",
                headers=self._headers(),
                json={"request_data": {"endpoint_id": endpoint_id}},
            )
            resp.raise_for_status()
            logger.info("cortex_xdr.contain_host.success", endpoint_id=endpoint_id, hostname=hostname)
            return {
                "success": True,
                "action": "contain_host",
                "endpoint_id": endpoint_id,
                "hostname": hostname,
                "action_id": resp.json().get("reply", {}).get("action_id"),
            }

    async def lift_containment(self, hostname: str) -> dict[str, Any]:
        """Reconnect a previously isolated endpoint."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            endpoint_id = await self._resolve_endpoint_id(client, hostname)
            resp = await client.post(
                f"https://{self._fqdn}/public_api/v1/endpoints/unisolate",
                headers=self._headers(),
                json={"request_data": {"endpoint_id": endpoint_id}},
            )
            resp.raise_for_status()
            logger.info("cortex_xdr.lift_containment.success", endpoint_id=endpoint_id, hostname=hostname)
            return {
                "success": True,
                "action": "lift_containment",
                "endpoint_id": endpoint_id,
                "hostname": hostname,
                "action_id": resp.json().get("reply", {}).get("action_id"),
            }
