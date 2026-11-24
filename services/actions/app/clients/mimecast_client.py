"""Mimecast API 2.0 client: the org-level blocked-senders policy.

The per-mailbox ``block_sender`` contract's own note records the gap this
closes: "neither vendor exposes its organisation-level [block]" — true for
Microsoft 365 and Gmail, and NOT true for a tenant whose gateway is
Mimecast, whose published API carries exactly this verb:

* ``POST /api/policy/blockedsenders/create-policy`` — create an org-level
  Blocked Senders policy (``option: block_sender``) for a sender address
  or domain;
* ``POST /api/policy/blockedsenders/get-policy`` — read policies back
  (the verification probe's leg);
* ``POST /api/policy/blockedsenders/delete-policy`` — remove one by id
  (the rollback leg).

Authentication is API 2.0's OAuth2 ``client_credentials`` grant at
``api.services.mimecast.com`` — client id + secret, no per-request HMAC.
The token is fetched per executor call rather than cached: an action
dispatch is seconds long, and a cached token is a secret with a lifetime
nobody is watching.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("aisoc.actions.mimecast")

BASE_URL = "https://api.services.mimecast.com"
TIMEOUT_SECONDS = 30.0


class MimecastError(RuntimeError):
    pass


class MimecastClient:
    def __init__(self, *, client_id: str, client_secret: str, base_url: str = BASE_URL) -> None:
        if not client_id or not client_secret:
            raise MimecastError("mimecast needs client_id and client_secret (API 2.0 application credentials)")
        self._client_id = client_id
        self._client_secret = client_secret
        self._base = base_url.rstrip("/")

    async def _token(self, http: httpx.AsyncClient) -> str:
        response = await http.post(
            f"{self._base}/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        if response.status_code != 200:
            raise MimecastError(f"token request failed: HTTP {response.status_code}")
        token = str(response.json().get("access_token") or "")
        if not token:
            raise MimecastError("token response carried no access_token")
        return token

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as http:
            token = await self._token(http)
            response = await http.post(
                f"{self._base}{path}",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
            )
        if response.status_code >= 400:
            # Mimecast error bodies carry a fail[] list; surface the codes
            # without echoing the whole payload into a log line.
            raise MimecastError(f"{path} failed: HTTP {response.status_code}")
        payload = response.json()
        failures = (payload.get("fail") or []) if isinstance(payload, dict) else []
        if failures:
            codes = ", ".join(str((f.get("errors") or [{}])[0].get("code", "?")) for f in failures[:3])
            raise MimecastError(f"{path} refused: {codes}")
        return payload

    async def create_blocked_sender_policy(self, *, sender: str, description: str) -> dict[str, Any]:
        """Create the org-level block. Returns the policy row (carries ``id``)."""
        payload = await self._post(
            "/api/policy/blockedsenders/create-policy",
            {
                "data": [
                    {
                        "policy": {
                            "description": description[:200],
                            "fromPart": "envelope_from",
                            "from": {"type": "email_address", "emailAddress": sender},
                            "to": {"type": "everyone"},
                        },
                        "option": "block_sender",
                    }
                ]
            },
        )
        rows = payload.get("data") or []
        if not rows:
            raise MimecastError("create-policy returned no policy row")
        return dict(rows[0])

    async def get_blocked_sender_policies(self) -> list[dict[str, Any]]:
        payload = await self._post("/api/policy/blockedsenders/get-policy", {"data": []})
        return [dict(r) for r in payload.get("data") or []]

    async def delete_blocked_sender_policy(self, *, policy_id: str) -> None:
        await self._post("/api/policy/blockedsenders/delete-policy", {"data": [{"id": policy_id}]})
