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

log = structlog.get_logger(__name__)


class _ActionsClient(Protocol):
    # Protocol method bodies use ``pass`` rather than ``...`` to silence
    # CodeQL ``py/ineffectual-statement``. Semantically identical for an
    # unimplemented Protocol contract.
    async def approve_action(self, action_id: str) -> dict[str, Any]:
        pass

    async def reject_action(self, action_id: str) -> dict[str, Any]:
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

    async def approve_action(self, action_id: str) -> dict[str, Any]:
        r = await self._client.post(f"/api/v1/actions/{action_id}/approve")
        r.raise_for_status()
        return r.json()

    async def reject_action(self, action_id: str) -> dict[str, Any]:
        r = await self._client.post(f"/api/v1/actions/{action_id}/reject")
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


class _NullAuditSink:
    async def record(self, event: Any) -> None:
        return None


def build_audit_sink() -> _AuditSink:
    """Construct the shared audit sink if available; null sink otherwise."""
    candidate = Path(__file__).resolve().parents[3] / "slack-bot" / "app" / "services" / "approval_audit.py"
    if not candidate.exists():
        return _NullAuditSink()
    spec = importlib.util.spec_from_file_location("_aisoc_audit", candidate)
    if spec is None or spec.loader is None:
        return _NullAuditSink()
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        log.warning("teams_bot.audit_sink_import_failed", error=str(exc))
        return _NullAuditSink()
    if hasattr(module, "StructlogAuditSink"):
        return module.StructlogAuditSink()  # type: ignore[no-any-return]
    return _NullAuditSink()
