"""
Okta management API client for identity response actions.

Supports: suspend session, force MFA enrolment, disable user, password reset,
and clearing active sessions.

Credentials expected in ActionRequest.parameters:
    okta_domain: str      (e.g. https://yourorg.okta.com)
    okta_api_token: str   (SSWS token with okta.users.manage scope)
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class OktaClient:
    """Async wrapper over the Okta Management REST API for identity response actions."""

    def __init__(self, domain: str, api_token: str) -> None:
        self._domain = domain.rstrip("/")
        self._token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"SSWS {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def _find_user(self, client: httpx.AsyncClient, login_or_id: str) -> dict[str, Any]:
        """Look up a user by login (email) or ID."""
        # First try as direct ID
        resp = await client.get(
            f"{self._domain}/api/v1/users/{login_or_id}",
            headers=self._headers(),
        )
        if resp.status_code == 200:
            return resp.json()

        # Fall back to search by login
        resp = await client.get(
            f"{self._domain}/api/v1/users",
            headers=self._headers(),
            params={"filter": f'profile.login eq "{login_or_id}"', "limit": 1},
        )
        resp.raise_for_status()
        users = resp.json()
        if not users:
            raise ValueError(f"No Okta user found for: {login_or_id}")
        return users[0]

    async def get_user_status(self, login_or_id: str) -> str | None:
        """Read the user's lifecycle status, for post-action verification.

        The action APIs return 200 on an accepted request, which says the
        request was accepted and nothing about whether the account is now
        blocked. Okta already returns the status on the user object, so
        verification costs one read.

        Returns ``None`` when the user cannot be found or the read fails:
        indeterminate, never a confirmation. A renamed or deprovisioned
        account is not the same fact as "the disable did not take".
        """
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                user = await self._find_user(client, login_or_id)
                status = user.get("status")
                return str(status) if status else None
        except Exception as exc:  # noqa: BLE001 - indeterminate, never a false VERIFIED
            logger.warning("okta.get_user_status.failed", login=login_or_id, error=str(exc))
            return None

    async def suspend_user(self, login_or_id: str) -> dict[str, Any]:
        """Suspend an Okta user (blocks sign-in without deactivating)."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            user_id = user["id"]
            resp = await client.post(
                f"{self._domain}/api/v1/users/{user_id}/lifecycle/suspend",
                headers=self._headers(),
            )
            resp.raise_for_status()
            logger.info("okta.suspend_user.success", user_id=user_id, login=login_or_id)
            return {"success": True, "action": "suspend_user", "user_id": user_id, "login": login_or_id}

    async def unsuspend_user(self, login_or_id: str) -> dict[str, Any]:
        """Unsuspend (reactivate) an Okta user."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            user_id = user["id"]
            resp = await client.post(
                f"{self._domain}/api/v1/users/{user_id}/lifecycle/unsuspend",
                headers=self._headers(),
            )
            resp.raise_for_status()
            logger.info("okta.unsuspend_user.success", user_id=user_id)
            return {"success": True, "action": "unsuspend_user", "user_id": user_id, "login": login_or_id}

    async def disable_user(self, login_or_id: str) -> dict[str, Any]:
        """Deactivate (disable) an Okta user — more forceful than suspend."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            user_id = user["id"]
            resp = await client.post(
                f"{self._domain}/api/v1/users/{user_id}/lifecycle/deactivate",
                headers=self._headers(),
                params={"sendEmail": "false"},
            )
            resp.raise_for_status()
            logger.info("okta.disable_user.success", user_id=user_id)
            return {"success": True, "action": "disable_user", "user_id": user_id, "login": login_or_id}

    async def enable_user(self, login_or_id: str) -> dict[str, Any]:
        """Reactivate a deactivated Okta user."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            user_id = user["id"]
            resp = await client.post(
                f"{self._domain}/api/v1/users/{user_id}/lifecycle/activate",
                headers=self._headers(),
                params={"sendEmail": "false"},
            )
            resp.raise_for_status()
            logger.info("okta.enable_user.success", user_id=user_id)
            return {"success": True, "action": "enable_user", "user_id": user_id, "login": login_or_id}

    async def clear_sessions(self, login_or_id: str) -> dict[str, Any]:
        """Terminate all active sessions for a user (revoke tokens)."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            user_id = user["id"]
            resp = await client.delete(
                f"{self._domain}/api/v1/users/{user_id}/sessions",
                headers=self._headers(),
            )
            resp.raise_for_status()
            logger.info("okta.clear_sessions.success", user_id=user_id)
            return {"success": True, "action": "clear_sessions", "user_id": user_id, "login": login_or_id}

    async def reset_password(self, login_or_id: str, *, send_email: bool = True) -> dict[str, Any]:
        """Trigger a password reset for the user.

        ``send_email`` maps to Okta's ``sendEmail`` query parameter. It is a
        keyword because ``ResetPasswordExecutor`` has always read
        ``parameters.send_email`` and passed it here — against a signature
        that did not accept it, so every live Okta reset raised ``TypeError``
        and came back as a FAILED action. Simulation mode never constructs
        this client, which is why nothing caught it.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            user_id = user["id"]
            resp = await client.post(
                f"{self._domain}/api/v1/users/{user_id}/lifecycle/reset_password",
                headers=self._headers(),
                params={"sendEmail": "true" if send_email else "false"},
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("okta.reset_password.success", user_id=user_id)
            return {
                "success": True,
                "action": "reset_password",
                "user_id": user_id,
                "login": login_or_id,
                "reset_url": data.get("resetPasswordUrl"),
            }

    async def force_mfa_enrollment(self, login_or_id: str) -> dict[str, Any]:
        """Reset MFA factors for a user, forcing re-enrollment on next login."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            user_id = user["id"]

            # List enrolled factors
            factors_resp = await client.get(
                f"{self._domain}/api/v1/users/{user_id}/factors",
                headers=self._headers(),
            )
            factors_resp.raise_for_status()
            factors = factors_resp.json()

            # Reset (unenroll) each factor
            reset_count = 0
            for factor in factors:
                factor_id = factor.get("id")
                if not factor_id:
                    continue
                del_resp = await client.delete(
                    f"{self._domain}/api/v1/users/{user_id}/factors/{factor_id}",
                    headers=self._headers(),
                )
                if del_resp.status_code in (200, 204, 404):
                    reset_count += 1

            logger.info("okta.force_mfa.success", user_id=user_id, factors_reset=reset_count)
            return {
                "success": True,
                "action": "force_mfa_enrollment",
                "user_id": user_id,
                "login": login_or_id,
                "factors_reset": reset_count,
            }

    # ------------------------------------------------------------------
    # Wave-2 Phase 6.1: OAuth grants and refresh tokens
    # ------------------------------------------------------------------
    #
    # `clear_sessions` ends the browser session. It does not touch the
    # OAuth grants the user has consented to, nor the refresh tokens
    # already issued against them, so an application that holds a refresh
    # token keeps minting access tokens for a user whose sessions were
    # "cleared" — which reads in the timeline as containment that happened.
    #
    # Reference, fetched before these were written:
    #   https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserGrant/

    async def list_grants(self, login_or_id: str) -> list[dict[str, Any]]:
        """OAuth 2.0 grants the user has consented to."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            resp = await client.get(
                f"{self._domain}/api/v1/users/{user['id']}/grants",
                headers=self._headers(),
            )
            resp.raise_for_status()
            rows = resp.json() if resp.content else []
        return [
            {
                "id": row.get("id"),
                "client_id": row.get("clientId"),
                "scope_id": row.get("scopeId"),
                "status": row.get("status"),
                "created": row.get("created"),
            }
            for row in rows
        ]

    async def revoke_grants(self, login_or_id: str, *, grant_id: str | None = None) -> dict[str, Any]:
        """Revoke one grant, or every grant the user holds.

        Not platform-reversible: a revoked consent is re-established by the
        user consenting again at the application's prompt, which AiSOC
        cannot do on their behalf and should not.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            path = f"{self._domain}/api/v1/users/{user['id']}/grants"
            if grant_id:
                path = f"{path}/{grant_id}"
            resp = await client.delete(path, headers=self._headers())
            resp.raise_for_status()
        logger.info("okta.revoke_grants.success", user=login_or_id, grant_id=grant_id or "all")
        return {
            "success": True,
            "action": "revoke_oauth_grant",
            "user_id": user["id"],
            "grant_id": grant_id,
            "scope": "one" if grant_id else "all",
        }

    async def revoke_refresh_tokens(self, login_or_id: str, client_id: str) -> dict[str, Any]:
        """Revoke every refresh token this user holds for one application.

        Narrower than `revoke_grants`: the consent survives, the tokens
        already minted under it do not. That is the right action when the
        application is legitimate and one token leaked.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            user = await self._find_user(client, login_or_id)
            resp = await client.delete(
                f"{self._domain}/api/v1/users/{user['id']}/clients/{client_id}/tokens",
                headers=self._headers(),
            )
            resp.raise_for_status()
        logger.info("okta.revoke_refresh_tokens.success", user=login_or_id, client_id=client_id)
        return {
            "success": True,
            "action": "revoke_token",
            "user_id": user["id"],
            "client_id": client_id,
        }
