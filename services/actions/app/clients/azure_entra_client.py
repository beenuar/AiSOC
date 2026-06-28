"""
Microsoft Azure Entra ID (formerly Azure AD) client.

Wraps the Microsoft Graph API surfaces AiSOC needs for the
identity-response action verbs:

* ``disable_user``    — set ``accountEnabled = false`` on the user.
* ``enable_user``     — undoes the above; used by the rollback path.
* ``revoke_sessions`` — invoke ``revokeSignInSessions`` so all
                        existing refresh tokens are invalidated and
                        the user is forced to re-authenticate
                        (effectively a session "suspend").
* ``reset_password``  — emit a temporary password the user is forced
                        to change at next sign-in. We deliberately
                        do not surface that password back to the
                        caller; the IdP delivers it via the OOB
                        channel a tenant has configured (usually
                        SMS or email).
* ``require_mfa``     — toggle the per-user MFA state via the
                        beta endpoint (Entra's general-availability
                        replacement, ``authenticationStrengthPolicy``,
                        is a CA-level construct that AiSOC can't
                        own from a playbook).

Credentials expected in :class:`ActionRequest.parameters`:

* ``azure_tenant_id``
* ``azure_client_id``
* ``azure_client_secret``

All four verbs accept ``user_id`` as either an objectId or a UPN
(email). Graph resolves both, so we don't pre-translate.

Why client_credentials and not delegated auth: the playbook
context has no human in the loop — we're acting on behalf of a
service principal. The tenant admin must grant the principal at
least ``User.ReadWrite.All`` (for disable/enable + reset),
``UserAuthenticationMethod.ReadWrite.All`` (for MFA toggle), and
``Directory.AccessAsUser.All`` is NOT needed (and should not be
granted; it would let the principal act as any user).
"""

from __future__ import annotations

import secrets
import string
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_AUTHORITY = "https://login.microsoftonline.com"
_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_BETA = "https://graph.microsoft.com/beta"


def _gen_temp_password(length: int = 16) -> str:
    """Generate a Microsoft-policy-compliant temporary password.

    Entra's default password policy requires three of: lower, upper,
    digit, symbol. We mix all four to dodge tenant-specific policy
    overrides that bump the minimum to four character classes.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in "!@#$%&*" for c in candidate)
        ):
            return candidate


class AzureEntraClient:
    """Async wrapper over Microsoft Graph for identity actions."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            f"{_AUTHORITY}/{self._tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    async def _ensure_token(self, client: httpx.AsyncClient) -> None:
        if not self._token:
            await self._authenticate(client)

    async def disable_user(self, user_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_GRAPH}/users/{user_id}",
                headers=self._headers(),
                json={"accountEnabled": False},
            )
            resp.raise_for_status()
            logger.info("entra.disable_user.success", user_id=user_id)
            return {"success": True, "action": "disable_user", "user_id": user_id}

    async def enable_user(self, user_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_GRAPH}/users/{user_id}",
                headers=self._headers(),
                json={"accountEnabled": True},
            )
            resp.raise_for_status()
            logger.info("entra.enable_user.success", user_id=user_id)
            return {"success": True, "action": "enable_user", "user_id": user_id}

    async def revoke_sessions(self, user_id: str) -> dict[str, Any]:
        """Invalidate every refresh token the user holds.

        Per-Microsoft, this takes effect within ~5 minutes for
        downstream apps (the access token they already have is still
        valid until its hour-long expiry, but no new tokens will be
        minted).
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_GRAPH}/users/{user_id}/revokeSignInSessions",
                headers=self._headers(),
            )
            resp.raise_for_status()
            body = resp.json() if resp.content else {"value": True}
            logger.info("entra.revoke_sessions.success", user_id=user_id, value=body.get("value"))
            return {"success": True, "action": "revoke_sessions", "user_id": user_id, "value": body.get("value")}

    async def reset_password(self, user_id: str) -> dict[str, Any]:
        """Set a forced-change temporary password.

        The password is generated client-side because Graph requires
        the caller to supply it; the user receives it through
        whatever OOB channel the tenant has configured for password
        resets (the playbook layer never logs the value).
        """
        temp_password = _gen_temp_password()
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_GRAPH}/users/{user_id}",
                headers=self._headers(),
                json={
                    "passwordProfile": {
                        "forceChangePasswordNextSignIn": True,
                        "password": temp_password,
                    }
                },
            )
            resp.raise_for_status()
            logger.info("entra.reset_password.success", user_id=user_id)
            return {
                "success": True,
                "action": "reset_password",
                "user_id": user_id,
                # We intentionally do NOT return the temp_password
                # in the response payload — it'd end up in the
                # action timeline and become a stolen-token-style
                # credential if logs leaked. The user gets the
                # password via the OOB channel Entra is configured
                # to use.
            }

    async def require_mfa(self, user_id: str) -> dict[str, Any]:
        """Force the user into per-user MFA enforcement.

        Uses the legacy per-user MFA toggle (the "Strong
        authentication requirements" array) via the beta endpoint
        because the GA endpoints expect Conditional Access policies,
        which AiSOC can't author from a playbook. Operators on
        Entra Premium licences should pair this with a CA policy
        that requires reauth.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.patch(
                f"{_GRAPH_BETA}/users/{user_id}",
                headers=self._headers(),
                json={"strongAuthenticationRequirements": [{"state": "enforced", "rememberDevicesNotIssuedBefore": None}]},
            )
            resp.raise_for_status()
            logger.info("entra.require_mfa.success", user_id=user_id)
            return {"success": True, "action": "require_mfa", "user_id": user_id}
