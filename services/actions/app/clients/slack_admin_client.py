"""Slack Enterprise admin client for user and session containment.

Depth 5.5 names "Slack … deactivate or freeze a user and revoke their
tokens". The tree posts *to* Slack (notifications, ChatOps) and could not
act *on* it, so a compromised Slack account stayed signed in through an
incident whose updates were being posted into Slack.

API references, each fetched before this module was written:

* ``admin.users.remove`` — https://api.slack.com/methods/admin.users.remove
* ``admin.users.assign`` — https://api.slack.com/methods/admin.users.assign
* ``admin.users.session.reset`` — https://api.slack.com/methods/admin.users.session.reset

Two corrections the references forced
-------------------------------------
``admin.users.setInactive`` does not exist — the URL 404s. The pair that
does exist is remove-from-workspace and assign-to-workspace, so "deactivate"
here means removal with ``admin.users.assign`` as its rollback, and the
contract says that rather than implying a soft deactivation Slack does not
offer.

All three methods are Enterprise Grid only and take a **user** token with
``admin.users:write``; a bot token is refused. The credential resolver asks
for ``slack_admin_token`` rather than reusing the notification webhook, so
nothing silently tries the wrong credential.

The failure mode that matters
-----------------------------
Slack answers HTTP 200 with ``{"ok": false, "error": "..."}``. A client that
only checks the status code reports every refusal as a success — the exact
shape of "we asked" being reported as "it happened". ``_call`` raises on
``ok: false``, which is why every executor here can treat a return value as
an effect.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

_API = "https://slack.com/api"


class SlackAPIError(RuntimeError):
    """Slack answered ``ok: false``. Carries Slack's own error string."""


class SlackAdminClient:
    """Async client over the Slack admin Web API."""

    def __init__(self, admin_token: str, *, team_id: str | None = None, base_url: str | None = None, timeout: float = 30.0) -> None:
        self._token = admin_token
        self._team_id = team_id
        self._base = (base_url or _API).rstrip("/")
        self._timeout = timeout

    async def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._base}/{method}",
                headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json; charset=utf-8"},
                json={k: v for k, v in payload.items() if v is not None},
            )
        if response.status_code >= 400:
            raise SlackAPIError(f"Slack {method} failed with HTTP {response.status_code}: {response.text[:300]}")
        try:
            body = response.json()
        except ValueError as exc:
            raise SlackAPIError(f"Slack {method} returned a non-JSON body") from exc
        if not body.get("ok", False):
            raise SlackAPIError(f"Slack {method} refused: {body.get('error') or 'no error string supplied'}")
        return body

    def _resolve_team(self, team_id: str | None) -> str:
        resolved = team_id or self._team_id
        if not resolved:
            raise ValueError("team_id is required by admin.users.remove and admin.users.assign; set it on the connector or pass it per call")
        return resolved

    async def remove_user(self, user_id: str, *, team_id: str | None = None) -> dict[str, Any]:
        """``admin.users.remove``: take the user out of a workspace."""
        team = self._resolve_team(team_id)
        await self._call("admin.users.remove", {"team_id": team, "user_id": user_id})
        logger.info("slack.remove_user.success", user_id=user_id, team_id=team)
        return {"user_id": user_id, "team_id": team, "removed": True}

    async def assign_user(self, user_id: str, *, team_id: str | None = None, is_restricted: bool | None = None) -> dict[str, Any]:
        """``admin.users.assign``: put the user back. The rollback for removal."""
        team = self._resolve_team(team_id)
        await self._call(
            "admin.users.assign",
            {"team_id": team, "user_id": user_id, "is_restricted": is_restricted},
        )
        logger.info("slack.assign_user.success", user_id=user_id, team_id=team)
        return {"user_id": user_id, "team_id": team, "assigned": True}

    async def reset_sessions(self, user_id: str, *, mobile_only: bool = False, web_only: bool = False) -> dict[str, Any]:
        """``admin.users.session.reset``: wipe every session on every device.

        Self-healing rather than reversible: the user signs in again. There
        is nothing to roll back and nothing to probe — Slack exposes no
        read of a user's live session count — so this verb carries a
        recorded verification gap instead of a claimed probe.
        """
        if mobile_only and web_only:
            raise ValueError("mobile_only and web_only are mutually exclusive; set neither to reset every session")
        await self._call(
            "admin.users.session.reset",
            {"user_id": user_id, "mobile_only": mobile_only or None, "web_only": web_only or None},
        )
        logger.info("slack.reset_sessions.success", user_id=user_id)
        return {"user_id": user_id, "sessions_reset": True, "mobile_only": mobile_only, "web_only": web_only}

    async def get_user(self, user_id: str) -> dict[str, Any]:
        """``users.info``: the read behind the removal probe.

        Slack reports a removed user as ``deleted: true`` rather than
        omitting them, so this answers the probe's question directly.
        """
        body = await self._call("users.info", {"user": user_id})
        user = body.get("user") or {}
        return {
            "id": user.get("id"),
            "name": user.get("name"),
            "deleted": bool(user.get("deleted", False)),
            "is_admin": user.get("is_admin"),
            "is_restricted": user.get("is_restricted"),
            "team_id": user.get("team_id"),
        }
