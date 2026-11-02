"""1Password SCIM-bridge client for account suspension.

Depth 5.5 names "1Password: deactivate or freeze a user and revoke their
tokens". 1Password's provisioning surface is a self-hosted SCIM bridge
speaking SCIM 2.0, so containment is a standard SCIM ``active`` flip rather
than a vendor-specific call.

References, each fetched before this module was written:

* 1Password SCIM bridge — https://support.1password.com/scim/
* SCIM 2.0 protocol, ``PATCH`` semantics — https://datatracker.ietf.org/doc/html/rfc7644

What this can and cannot do, stated rather than implied
-------------------------------------------------------
Setting ``active: false`` suspends the account: the user cannot sign in and
existing sessions stop working, which is the containment. Setting it back
restores them, so this verb has a real platform rollback and a real probe
(``GET /Users/{id}`` returns ``active``).

There is **no token-revocation verb here**, and that is a recorded gap
rather than an omission: 1Password issues no API tokens on a user's behalf
that SCIM can see, and the Connect/Service Account tokens that do exist are
managed outside the SCIM bridge with no documented revocation endpoint. A
``revoke_token`` arm pointed at this bridge would be a verb that cannot act.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class OnePasswordAPIError(RuntimeError):
    """The SCIM bridge answered and declined."""


class OnePasswordClient:
    """Async client over a 1Password SCIM bridge."""

    def __init__(self, bridge_url: str, bearer_token: str, *, timeout: float = 30.0) -> None:
        self._base = bridge_url.rstrip("/")
        self._token = bearer_token
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/scim+json", "Accept": "application/scim+json"}

    async def _request(self, method: str, path: str, *, json_body: dict | None = None, params: dict | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.request(method, f"{self._base}{path}", headers=self._headers(), json=json_body, params=params)
        if response.status_code >= 400:
            raise OnePasswordAPIError(f"1Password SCIM {method} {path} failed with HTTP {response.status_code}: {response.text[:300]}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    async def find_user(self, email: str) -> dict[str, Any]:
        """Resolve an email to a SCIM user id.

        An alert carries an email address; every write below needs the SCIM
        id, so this is the first call in all of them.
        """
        body = await self._request("GET", "/Users", params={"filter": f'userName eq "{email}"'})
        resources = body.get("Resources") or []
        if not resources:
            raise OnePasswordAPIError(f"no 1Password account matches {email!r}")
        row = resources[0]
        return {
            "id": row.get("id"),
            "user_name": row.get("userName"),
            "active": bool(row.get("active", True)),
            "display_name": row.get("displayName"),
        }

    async def get_user(self, user_id_or_email: str) -> dict[str, Any]:
        """The read behind the suspension probe."""
        if "@" in user_id_or_email:
            return await self.find_user(user_id_or_email)
        body = await self._request("GET", f"/Users/{user_id_or_email}")
        return {
            "id": body.get("id"),
            "user_name": body.get("userName"),
            "active": bool(body.get("active", True)),
            "display_name": body.get("displayName"),
        }

    async def set_active(self, user_id_or_email: str, *, active: bool) -> dict[str, Any]:
        """SCIM ``PATCH`` of the ``active`` attribute.

        ``PATCH`` rather than ``PUT``: a ``PUT`` replaces the whole
        resource, so a client that does not round-trip every attribute
        silently clears the ones it did not send. That is a data-loss bug
        wearing a containment action's clothes.
        """
        resolved = await self.get_user(user_id_or_email)
        await self._request(
            "PATCH",
            f"/Users/{resolved['id']}",
            json_body={"schemas": [_SCIM_PATCH], "Operations": [{"op": "replace", "path": "active", "value": active}]},
        )
        logger.info("onepassword.set_active", user=resolved.get("user_name"), active=active)
        return {**resolved, "active": active}

    async def suspend_user(self, user_id_or_email: str) -> dict[str, Any]:
        return await self.set_active(user_id_or_email, active=False)

    async def restore_user(self, user_id_or_email: str) -> dict[str, Any]:
        return await self.set_active(user_id_or_email, active=True)
