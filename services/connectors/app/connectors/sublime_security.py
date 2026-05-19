"""
Sublime Security email-security connector.

Sublime is an email-security platform that auto-triages inbound mail
against a marketplace of detection rules. We poll its public REST API
for **messages** that match high-confidence detection rules — these
flow into AiSOC as alerts so the email-incident playbook has the same
shape regardless of which email-security vendor produced the verdict.

API: ``GET /v1/messages?reviewed=false&query=...`` returns paginated
message records. Auth is a tenant API key (Bearer). Pagination uses
opaque ``cursor`` tokens.

Severity collapse:
  * verdict ``malicious`` → high
  * verdict ``suspicious`` / ``spam`` → medium
  * verdict ``graymail`` / ``commercial`` → low
  * everything else → info
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_DEFAULT_BASE = "https://api.platform.sublimesecurity.com"
_PER_PAGE = 100
_MAX_PAGES = 25


class SublimeSecurityConnector(BaseConnector):
    """Sublime Security email events."""

    connector_id = "sublime_security"
    connector_name = "Sublime Security"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Sublime Security inbound-email detections. Polls "
                "/v1/messages for malicious + suspicious verdicts and "
                "links them to the originating mailbox + sender."
            ),
            docs_url="/docs/connectors/sublime_security",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "API base URL",
                    default=_DEFAULT_BASE,
                    required=False,
                    help_text="Override only for self-hosted / regional Sublime tenants.",
                ),
                Field(
                    "api_key",
                    "secret",
                    "API key",
                    help_text="Sublime → Settings → API → Create token.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PIVOT_USER,
            Capability.QUARANTINE_FILE,
        )

    def __init__(self, api_key: str, base_url: str | None = None):
        self._api_key = api_key
        self._base = (base_url or _DEFAULT_BASE).rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{self._base}/v1/me", headers=self._headers())
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "tenant": (resp.json() or {}).get("organization", {}).get("name"),
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                params: dict[str, Any] = {
                    "limit": _PER_PAGE,
                    "created_at__gte": since,
                }
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(f"{self._base}/v1/messages", headers=self._headers(), params=params)
                if resp.status_code != 200:
                    logger.warning(
                        "sublime_security.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                payload = resp.json() or {}
                messages = payload.get("messages") or payload.get("results") or []
                for msg in messages:
                    out.append(self.normalize(msg))
                cursor = payload.get("next_cursor") or payload.get("next")
                if not cursor or len(messages) < _PER_PAGE:
                    break
        return out

    _SEVERITY_BY_VERDICT = {
        "malicious": "high",
        "suspicious": "medium",
        "spam": "medium",
        "graymail": "low",
        "commercial": "low",
        "benign": "info",
        "trusted": "info",
        "safe": "info",
    }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        verdict = (raw.get("classification") or raw.get("verdict") or "").lower()
        # Sublime sometimes reports verdict as nested ``review.classification``.
        if not verdict:
            verdict = (raw.get("review") or {}).get("classification", "").lower()
        severity = self._SEVERITY_BY_VERDICT.get(verdict, "info")
        # Detection-rule names with attack-shaped substrings escalate.
        rule_name = ""
        rules = raw.get("triggered_rules") or raw.get("matched_rules") or []
        if rules:
            first = rules[0] if isinstance(rules[0], dict) else {"name": rules[0]}
            rule_name = first.get("name", "")
            if any(t in rule_name.lower() for t in ("bec", "credential", "phishing", "impersonation")):
                severity = "high"
        sender = raw.get("from", {}) if isinstance(raw.get("from"), dict) else {"email": raw.get("from_email")}
        recipient = raw.get("to") or raw.get("recipient")
        return {
            "source": self.connector_id,
            "external_id": raw.get("id") or raw.get("message_id") or "",
            "title": raw.get("subject") or rule_name or "Sublime Security message",
            "description": (f"verdict={verdict}; rule={rule_name}; " f"from={sender.get('email')}; to={recipient}"),
            "severity": severity,
            "actor": sender.get("email"),
            "actor_email": sender.get("email"),
            "target": recipient if isinstance(recipient, str) else None,
            "event_type": f"sublime_security.{verdict or 'message'}",
            "raw_event": raw,
            "created_at": raw.get("created_at") or raw.get("received_at"),
        }
