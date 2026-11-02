"""Salesforce client for user freeze and session/token containment.

Depth 5.5 names "Salesforce … deactivate or freeze a user and revoke their
tokens". Freeze rather than deactivate is the right verb and the vendor
makes the distinction load-bearing: deactivating a Salesforce user releases
their licence and breaks record ownership, so it is not an incident action.
Freezing blocks sign-in and leaves everything else intact, and unfreezing is
one field back.

References, each fetched before this module was written:

* freeze or unfreeze a user — https://help.salesforce.com/s/articleView?id=platform.users_freeze.htm&type=5
* revoke an OAuth token — https://help.salesforce.com/s/articleView?id=platform.remoteaccess_revoke_token.htm&type=5
* session management — https://help.salesforce.com/s/articleView?id=platform.identity_auth_session_mgmt.htm&type=5

(`developer.salesforce.com` answers 403 to every non-browser request, so the
URLs cited here are the `help.salesforce.com` pages carrying the same
semantics, which do answer 200.)

The indirection worth knowing about
-----------------------------------
``IsFrozen`` lives on ``UserLogin``, not on ``User``. An alert carries a
username or a User id, so every call here starts with a SOQL lookup from
the User to its UserLogin row. Writing to ``User`` would be a 400 at best
and, with a field that happened to exist, a silent no-op.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

#: Salesforce ids are 15 or 18 characters of base-62. Anything else is not
#: an id, and interpolating it into SOQL is how a lookup becomes an
#: injection. Refused rather than escaped: an escaped value that reaches
#: the query and matches nothing reports a clean result from a query that
#: never ran.
_SF_ID = re.compile(r"\A[a-zA-Z0-9]{15}(?:[a-zA-Z0-9]{3})?\Z")
#: Usernames are email-shaped. The same reasoning applies.
_SF_USERNAME = re.compile(r"\A[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\Z")

DEFAULT_API_VERSION = "v62.0"


class SalesforceAPIError(RuntimeError):
    """Salesforce answered and declined."""


class SalesforceClient:
    """Async client over the Salesforce REST and OAuth endpoints."""

    def __init__(self, instance_url: str, access_token: str, *, api_version: str = DEFAULT_API_VERSION, timeout: float = 30.0) -> None:
        self._base = instance_url.rstrip("/")
        self._token = access_token
        self._version = api_version
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _request(self, method: str, path: str, *, json_body: dict | None = None, params: dict | None = None) -> Any:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.request(method, f"{self._base}{path}", headers=self._headers(), json=json_body, params=params)
        if response.status_code >= 400:
            raise SalesforceAPIError(f"Salesforce {method} {path} failed with HTTP {response.status_code}: {response.text[:300]}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    async def _query(self, soql: str) -> list[dict[str, Any]]:
        body = await self._request("GET", f"/services/data/{self._version}/query", params={"q": soql})
        return list(body.get("records") or [])

    @staticmethod
    def _literal(value: str) -> str:
        """Validate an identifier before it reaches SOQL.

        Not an escaper. Either the value is a Salesforce id or an
        email-shaped username, or this raises — because the alternative is
        a query that runs with attacker-chosen structure.
        """
        if _SF_ID.match(value) or _SF_USERNAME.match(value):
            return value
        raise ValueError(f"{value!r} is neither a Salesforce id nor a username; refusing to build a query from it")

    async def resolve_user_login(self, user: str) -> dict[str, Any]:
        """Find the ``UserLogin`` row for a User id or username.

        Returns the UserLogin id and its current ``IsFrozen``, which is
        both the handle the write needs and the value the probe reads.
        """
        value = self._literal(user)
        field = "Id" if _SF_ID.match(value) else "Username"
        users = await self._query(f"SELECT Id, Username, IsActive FROM User WHERE {field} = '{value}' LIMIT 1")
        if not users:
            raise SalesforceAPIError(f"no Salesforce user matches {user!r}")
        user_id = users[0]["Id"]
        logins = await self._query(f"SELECT Id, UserId, IsFrozen, IsPasswordLocked FROM UserLogin WHERE UserId = '{user_id}' LIMIT 1")
        if not logins:
            raise SalesforceAPIError(f"Salesforce user {user_id} has no UserLogin row, so freeze state cannot be read or set")
        return {
            "user_id": user_id,
            "username": users[0].get("Username"),
            "is_active": users[0].get("IsActive"),
            "user_login_id": logins[0]["Id"],
            "is_frozen": bool(logins[0].get("IsFrozen")),
            "is_password_locked": bool(logins[0].get("IsPasswordLocked")),
        }

    async def set_frozen(self, user: str, *, frozen: bool) -> dict[str, Any]:
        """PATCH ``UserLogin.IsFrozen``. Freeze and unfreeze share one path."""
        resolved = await self.resolve_user_login(user)
        await self._request(
            "PATCH",
            f"/services/data/{self._version}/sobjects/UserLogin/{resolved['user_login_id']}",
            json_body={"IsFrozen": frozen},
        )
        logger.info("salesforce.set_frozen", user=user, frozen=frozen)
        return {**resolved, "is_frozen": frozen}

    async def freeze_user(self, user: str) -> dict[str, Any]:
        return await self.set_frozen(user, frozen=True)

    async def unfreeze_user(self, user: str) -> dict[str, Any]:
        return await self.set_frozen(user, frozen=False)

    async def revoke_oauth_token(self, token: str) -> dict[str, Any]:
        """``/services/oauth2/revoke``: kill one access or refresh token.

        Revoking a refresh token also revokes the access tokens derived
        from it. There is no un-revoke, so the contract declares no
        rollback rather than naming one that would dispatch to nothing.
        """
        if not token:
            raise ValueError("a token value is required")
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._base}/services/oauth2/revoke",
                data={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if response.status_code >= 400:
            raise SalesforceAPIError(f"Salesforce token revocation failed with HTTP {response.status_code}: {response.text[:300]}")
        logger.info("salesforce.revoke_oauth_token.success", http_status=response.status_code)
        return {"revoked": True, "http_status": response.status_code}

    async def revoke_sessions(self, user: str) -> dict[str, Any]:
        """Delete every ``AuthSession`` row the user holds.

        Self-healing: the user signs in again and gets a new session. It is
        the right action when a session cookie is the thing that leaked and
        freezing the account would be too wide.
        """
        resolved = await self.resolve_user_login(user)
        sessions = await self._query(f"SELECT Id, SessionType, LoginType FROM AuthSession WHERE UsersId = '{resolved['user_id']}'")
        deleted: list[str] = []
        for session in sessions:
            await self._request("DELETE", f"/services/data/{self._version}/sobjects/AuthSession/{session['Id']}")
            deleted.append(session["Id"])
        logger.info("salesforce.revoke_sessions.success", user=user, count=len(deleted))
        return {"user_id": resolved["user_id"], "revoked_session_ids": deleted, "count": len(deleted)}
