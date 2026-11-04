"""
Thin wiring helpers for the Teams bot.

We deliberately don't reimplement an HTTP client — the Slack bot already
ships :class:`services.slack-bot.app.services.aisoc_clients.AisocActionsClient`
which is parameterised by env vars and works for any caller. In a real
deployment the Teams bot pulls in ``aisoc-slack-bot`` as a sibling
package and gets the client for free.

For repo-local unit tests, we fall back to a tiny ``httpx``-based stub
so the test suite doesn't need to install both poetry projects.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any, Protocol

import httpx
import structlog

from app.services.approval_audit import StructlogAuditSink

log = structlog.get_logger(__name__)


class _ActionsClient(Protocol):
    # Protocol method bodies use ``pass`` rather than ``...`` to silence
    # CodeQL ``py/ineffectual-statement``. Semantically identical for an
    # unimplemented Protocol contract.
    async def approve_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        pass

    async def reject_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        pass

    async def aclose(self) -> None:
        pass


class _AuditSink(Protocol):
    # See ``_ActionsClient`` — ``pass`` instead of ``...`` for Protocol
    # stubs to avoid CodeQL ``py/ineffectual-statement``.
    async def record(self, event: Any) -> None:
        pass


class _FallbackActionsClient:
    """
    Minimal stand-in used when the Slack bot's client package isn't
    importable at runtime (eg. the Teams bot ships in its own image).
    Hits the same ``services/actions`` REST surface.
    """

    def __init__(self) -> None:
        self._base_url = os.environ.get("AISOC_ACTIONS_BASE_URL", "http://aisoc-actions:8085").rstrip("/")
        self._token = os.environ.get("AISOC_ACTIONS_SERVICE_TOKEN", "") or os.environ.get("AISOC_API_SERVICE_TOKEN", "")
        self._tenant = os.environ.get("AISOC_DEFAULT_TENANT_ID", "00000000-0000-0000-0000-000000000000")
        headers = {"Accept": "application/json", "X-Tenant-Id": self._tenant}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        self._client = httpx.AsyncClient(base_url=self._base_url, headers=headers, timeout=10.0)

    @staticmethod
    def chatops_approver(platform: str, platform_user_id: str | None) -> dict[str, Any] | None:
        """Mirror of the Slack client's helper, so either client works here.

        `build_actions_client` prefers the Slack bot's client when it is on
        the image and falls back to this one, so both have to accept the same
        approver payload — otherwise approvals authorize or don't depending on
        which image the Teams bot happens to be running.
        """
        if not platform_user_id:
            return None
        return {"chatops_approver": {"platform": platform, "platform_user_id": platform_user_id}}

    async def approve_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self._client.post(f"/api/v1/actions/{action_id}/approve", json=approver)
        r.raise_for_status()
        return r.json()

    async def reject_action(self, action_id: str, *, approver: dict[str, Any] | None = None) -> dict[str, Any]:
        r = await self._client.post(f"/api/v1/actions/{action_id}/reject", json=approver)
        r.raise_for_status()
        return r.json()

    async def aclose(self) -> None:
        await self._client.aclose()


def _try_import_slack_bot_client():
    """Best-effort import of the Slack bot's actions client."""
    candidate = Path(__file__).resolve().parents[3] / "slack-bot" / "app" / "services" / "aisoc_clients.py"
    if not candidate.exists():
        return None
    spec = importlib.util.spec_from_file_location("_aisoc_slack_bot_clients", candidate)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - best-effort
        log.warning("teams_bot.slack_client_import_failed", error=str(exc))
        return None
    return module


def build_actions_client() -> _ActionsClient:
    """Pick the Slack bot's client when available, otherwise a fallback."""
    slack_module = _try_import_slack_bot_client()
    if slack_module is not None and hasattr(slack_module, "AisocActionsClient"):
        try:
            return slack_module.AisocActionsClient.from_settings()  # type: ignore[no-any-return]
        except Exception as exc:  # noqa: BLE001
            log.warning("teams_bot.slack_client_from_settings_failed", error=str(exc))
    return _FallbackActionsClient()


def build_audit_sink() -> _AuditSink:
    """The audit sink every Teams approval decision is recorded through.

    GHSA-vf98-8367-45mp, F62. This used to locate the sink by walking
    ``Path(__file__).resolve().parents[3] / "slack-bot" / ...`` and fall back
    to a ``_NullAuditSink`` when the file was not there. In a source checkout
    that path resolves; **inside the built image it is ``/slack-bot/app/...``,
    which does not exist**, because the Dockerfile copies only this service's
    ``app/``. So the shipped container recorded no approval decisions at all,
    silently -- and every developer running from source saw them recorded,
    which is the pairing that keeps a defect alive.

    The sink is now vendored into this service and imported normally. There is
    no fallback, because the only thing a fallback could express here is
    "audit nothing", and an approval surface that cannot write its audit trail
    should fail loudly at startup rather than serve decisions it will not
    record.
    """
    return StructlogAuditSink()
