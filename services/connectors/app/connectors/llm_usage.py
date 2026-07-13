"""AI / LLM-usage audit connector (OpenAI + Anthropic org audit logs).

Pulls **organization audit logs** from OpenAI (`GET /v1/organization/audit_logs`)
or Anthropic (admin audit API) and folds each into the common AiSOC alert shape.
This is the governance surface for AI adoption: who created an API key, who was
granted owner, was audit logging or MFA turned off, was a project deleted. It
pairs with the Phase D2 `llm-*` detection rules, which fire on the emitted
`event_type` (e.g. `openai.api_key.created`, `anthropic.member.added`).

A `provider` selector chooses the stream; auth is an admin/audit-scoped API key.
Severity is derived from the event type — key/role/logging/MFA changes are the
high-signal ones a SOC wants surfaced above routine usage.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 100
_OPENAI_BASE = "https://api.openai.com/v1/organization/audit_logs"
_ANTHROPIC_BASE = "https://api.anthropic.com/v1/organizations/audit_logs"

# event_type fragment -> severity floor.
_HIGH = ("api_key.created", "member.added", "invite", "service_account.created")
_CRITICAL = ("logging", "mfa")


class LlmUsageConnector(BaseConnector):
    """OpenAI / Anthropic organization audit logs."""

    connector_id = "llm_usage"
    connector_name = "AI / LLM Usage Audit"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull organization audit logs from OpenAI or Anthropic — API "
                "key creation, role grants, logging/MFA changes, project "
                "deletes. Pairs with the llm-* detection rules. Auth is an "
                "admin/audit-scoped API key."
            ),
            docs_url="/docs/connectors/llm_usage",
            fields=[
                Field(
                    "provider",
                    "select",
                    "Provider",
                    options=[
                        {"value": "openai", "label": "OpenAI"},
                        {"value": "anthropic", "label": "Anthropic"},
                    ],
                ),
                Field("api_key", "secret", "Admin / Audit API Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_AUDIT, Capability.READ_AUDIT_TRAIL)

    def __init__(self, provider: str, api_key: str) -> None:
        provider = (provider or "").lower()
        if provider not in ("openai", "anthropic"):
            raise ValueError(f"llm_usage: unknown provider '{provider}' (need 'openai' or 'anthropic')")
        self._provider = provider
        self._api_key = api_key

    def _endpoint(self) -> str:
        return _OPENAI_BASE if self._provider == "openai" else _ANTHROPIC_BASE

    def _headers(self) -> dict[str, str]:
        if self._provider == "openai":
            return {"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"}
        return {"x-api-key": self._api_key, "anthropic-version": "2023-06-01", "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self._endpoint(), headers=self._headers(), params={"limit": 1})
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id, "provider": self._provider}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            import time  # noqa: PLC0415

            since = int(time.time() - since_seconds)
            params = {"limit": _LIMIT}
            if self._provider == "openai":
                params["effective_at[gte]"] = since
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(self._endpoint(), headers=self._headers(), params=params)
            if resp.status_code != 200:
                logger.warning("llm_usage.fetch_failed", provider=self._provider, status=resp.status_code)
                return out
            body = resp.json() or {}
            for ev in body.get("data") or []:
                out.append(self.normalize(ev))
        except Exception as exc:  # noqa: BLE001
            logger.warning("llm_usage.fetch_error", error=str(exc))
        return out

    def _event_type(self, raw: dict[str, Any]) -> str:
        # OpenAI: raw["type"] e.g. "api_key.created"; Anthropic: raw["action"].
        vendor_type = str(raw.get("type") or raw.get("action") or raw.get("event_type") or "event")
        return f"{self._provider}.{vendor_type}"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        event_type = self._event_type(raw)
        low = event_type.lower()
        severity = "info"
        if any(h in low for h in _HIGH):
            severity = "high"
        if any(c in low for c in _CRITICAL):
            severity = "critical"
        actor = raw.get("actor") or {}
        actor_email = (actor.get("email") if isinstance(actor, dict) else None) or raw.get("actor_email")
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": severity,
            "title": f"{self._provider.capitalize()} audit: {event_type.split('.', 1)[-1]}",
            "description": f"provider={self._provider}; event_type={event_type}; actor={actor_email}",
            "external_id": str(raw.get("id") or ""),
            # Emit the dotted event_type at the TOP LEVEL so the llm-* detection
            # rules (which match on `event_type`) fire against raw_data.
            "event_type": event_type,
            "actor": actor_email,
            "actor_email": actor_email,
            "created_at": raw.get("effective_at") or raw.get("occurred_at") or raw.get("timestamp"),
            "raw": raw,
        }
