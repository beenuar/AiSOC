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
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_AUTHORITY = "https://login.microsoftonline.com"
_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_BETA = "https://graph.microsoft.com/beta"


def _quote_odata_string(value: str) -> str:
    """Escape a value for a single-quoted OData string literal.

    OData escapes a single quote by doubling it, and that is the whole of the
    grammar's escaping rule. Everything else inside the quotes is literal.

    This matters because the read methods below are reachable, through the
    live-action registry, from an investigation agent, and the value it passes
    is a principal name lifted out of alert text. Alert text is
    attacker-influenced. A raw interpolation would let a crafted
    ``userPrincipalName`` close the literal and append a clause, which on a
    read endpoint means reading another principal's sign-ins.

    Control characters are dropped rather than escaped: a newline in a UPN is
    not a principal name, and there is no reading of it that is worth
    preserving.
    """
    cleaned = "".join(ch for ch in str(value) if ch.isprintable())
    return cleaned.replace("'", "''")


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

    async def get_user_enabled(self, user_principal_name: str) -> bool | None:
        """Read ``accountEnabled``, for post-action verification.

        Graph returns 204 on a successful PATCH, which confirms the request
        was accepted rather than that sign-in is blocked. Directory
        replication also means the two can differ briefly, which is exactly
        the window a caller needs to be told about rather than guessed at.

        Returns ``None`` on any failure: indeterminate, never a confirmation.
        """
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                # _ensure_token takes the client and stores the token on the
                # instance; it does not return one. Calling it bare and using
                # the result as a bearer token raised TypeError on every live
                # call — invisible in simulation, which never constructs a
                # client. Same class as the executor/client signature drift
                # the autospec'd tests exist to catch.
                await self._ensure_token(client)
                resp = await client.get(
                    f"{_GRAPH}/users/{user_principal_name}?$select=accountEnabled",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return None
                value = resp.json().get("accountEnabled")
                return bool(value) if value is not None else None
        except Exception as exc:  # noqa: BLE001 - indeterminate, never a false VERIFIED
            logger.warning("entra.get_user_enabled.failed", upn=user_principal_name, error=str(exc))
            return None

    async def list_sign_ins(
        self,
        user_principal_name: str,
        *,
        hours: int = 24,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Recent sign-in attempts for one principal, successes and failures.

        Gap-closure Phase 4.2. Read-only: a GET over ``/auditLogs/signIns``.

        Both outcomes are returned rather than only failures, because the
        question an identity investigation asks is not "did anything fail" but
        "what did the pattern look like": a single success from an unusual
        address after a run of failures is the finding, and filtering to
        failures hides exactly the event that matters.

        The filter is built here from a validated UPN and an integer window,
        never from caller-supplied text. ``$filter`` is OData rather than KQL,
        but it is still a query language and a principal name interpolated raw
        would be an injection point on a surface an agent can reach.
        """
        since = datetime.now(UTC) - timedelta(hours=max(1, min(hours, 720)))
        upn = _quote_odata_string(user_principal_name)
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_GRAPH}/auditLogs/signIns",
                headers=self._headers(),
                params={
                    "$filter": (f"userPrincipalName eq '{upn}' and createdDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"),
                    "$top": min(limit, 100),
                    "$orderby": "createdDateTime desc",
                },
            )
            resp.raise_for_status()
            raw = resp.json().get("value", []) or []
        return [self._project_sign_in(entry) for entry in raw if isinstance(entry, dict)]

    @staticmethod
    def _project_sign_in(entry: dict[str, Any]) -> dict[str, Any]:
        status = entry.get("status") if isinstance(entry.get("status"), dict) else {}
        location = entry.get("location") if isinstance(entry.get("location"), dict) else {}
        code = status.get("errorCode")
        return {
            "at": entry.get("createdDateTime"),
            "ip": entry.get("ipAddress"),
            "app": entry.get("appDisplayName"),
            "client": entry.get("clientAppUsed"),
            # errorCode 0 is Graph's "success". Rendered as a boolean so a
            # model is not invited to interpret a vendor error number, and
            # `None` stays None rather than becoming a confident False.
            "succeeded": (code == 0) if code is not None else None,
            "failure_reason": status.get("failureReason") if code else None,
            "conditional_access": entry.get("conditionalAccessStatus"),
            "risk_level": entry.get("riskLevelDuringSignIn"),
            "risk_state": entry.get("riskState"),
            "country": location.get("countryOrRegion"),
            "city": location.get("city"),
        }

    async def get_risky_user(self, user_principal_name: str) -> dict[str, Any] | None:
        """Entra ID Protection's own risk assessment for one principal.

        Gap-closure Phase 4.2. Read-only.

        ``None`` means Graph answered and holds no risk record for this
        principal, which is a real answer. It is **not** the same as a failed
        read, and the executor above keeps the two apart: a caller that cannot
        tell them apart will report an account as unremarkable because the
        lookup broke.

        ``/identityProtection/riskyUsers`` is a beta endpoint. Microsoft
        publishes it as such, so it is named here rather than being quietly
        pinned to v1.0, where it does not exist.
        """
        upn = _quote_odata_string(user_principal_name)
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_GRAPH_BETA}/identityProtection/riskyUsers",
                headers=self._headers(),
                params={"$filter": f"userPrincipalName eq '{upn}'", "$top": 1},
            )
            resp.raise_for_status()
            rows = resp.json().get("value", []) or []
        if not rows or not isinstance(rows[0], dict):
            return None
        row = rows[0]
        return {
            "risk_level": row.get("riskLevel"),
            "risk_state": row.get("riskState"),
            "risk_detail": row.get("riskDetail"),
            "last_updated": row.get("riskLastUpdatedDateTime"),
            "is_deleted": row.get("isDeleted"),
        }

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
