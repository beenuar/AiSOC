"""
PagerDuty connector.

Pulls two streams from the PagerDuty REST API:

1. **Incidents** — ``GET /incidents`` returns the full incident
   timeline. We page through incidents updated in the poll window and
   normalise their ``urgency`` / ``status`` into AiSOC severity.
2. **Audit records** — ``GET /audit/records`` returns the tenant audit
   trail (user role changes, service config edits, API key issuance,
   webhook subscriptions). This is the on-call security surface we
   care about most: an attacker who pwns a PagerDuty admin can silence
   pages globally.

Auth: a REST API key (``Authorization: Token token=<key>``). The
operator generates a *user-level* or *general access* key under
**Integrations → API Access Keys**. Read-only is sufficient.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_BASE = "https://api.pagerduty.com"
_MAX_PAGES = 20
_PAGE_SIZE = 100


class PagerDutyConnector(BaseConnector):
    """PagerDuty incidents + audit records."""

    connector_id = "pagerduty"
    connector_name = "PagerDuty"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "PagerDuty on-call platform. Pulls incident lifecycle events and "
                "tenant audit records (role changes, integration edits, API key "
                "issuance) via the REST API. Requires a read-only REST API key."
            ),
            docs_url="/docs/connectors/pagerduty",
            fields=[
                Field(
                    "api_key",
                    "secret",
                    "REST API Key",
                    help_text=("Generate under Integrations → API Access Keys. Read-only access is sufficient."),
                ),
                Field(
                    "subdomain",
                    "string",
                    "Subdomain (optional)",
                    required=False,
                    placeholder="acme",
                    help_text=(
                        "Your acme.pagerduty.com subdomain. Used to build clickable links in normalised events; not required for ingestion."
                    ),  # noqa: E501
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://app.pagerduty.com/oauth/authorize",
                token_url="https://identity.pagerduty.com/oauth/token",
                scopes=["read"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_AUDIT,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, api_key: str, subdomain: str | None = None):
        self._api_key = api_key
        self._subdomain = (subdomain or "").strip() or None

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        return {
            # PagerDuty's classic API uses the ``Token token=...`` scheme;
            # ``Bearer`` only works for OAuth-issued tokens.
            "Authorization": f"Token token={self._api_key}",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Content-Type": "application/json",
            "User-Agent": "AiSOC-Connector/1.0",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_BASE}/users/me",
                    headers=self._headers(),
                )
                # ``/users/me`` is only valid for *user-level* keys.
                # General-access keys return 401 here but still work for
                # ``/incidents`` so we fall back to probing that.
                if resp.status_code == 200:
                    me = resp.json().get("user", {})
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "user_email": me.get("email"),
                        "auth_type": "user_key",
                    }
                if resp.status_code == 401:
                    probe = await client.get(
                        f"{_BASE}/incidents",
                        headers=self._headers(),
                        params={"limit": 1},
                    )
                    if probe.status_code == 200:
                        return {
                            "success": True,
                            "connector": self.connector_id,
                            "auth_type": "general_access_key",
                        }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(seconds=since_seconds)
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            incidents = await self._paginate_offset(
                client=client,
                path="/incidents",
                params={
                    "limit": _PAGE_SIZE,
                    "since": since_iso,
                    "sort_by": "incident_number:desc",
                    "statuses[]": ["triggered", "acknowledged", "resolved"],
                },
                stream="incident",
                items_key="incidents",
            )
            events.extend(incidents)

            audit = await self._paginate_cursor(
                client=client,
                path="/audit/records",
                params={"limit": _PAGE_SIZE, "since": since_iso},
                stream="audit_record",
                items_key="records",
            )
            events.extend(audit)

        return [self.normalize(e) for e in events]

    async def _paginate_offset(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any],
        stream: str,
        items_key: str,
    ) -> list[dict[str, Any]]:
        """Classic PagerDuty pagination: ``offset`` / ``limit`` / ``more``."""
        out: list[dict[str, Any]] = []
        offset = 0
        for _ in range(_MAX_PAGES):
            call_params = dict(params, offset=offset)
            resp = await client.get(f"{_BASE}{path}", headers=self._headers(), params=call_params)
            if resp.status_code != 200:
                logger.warning("pagerduty.fetch_failed", path=path, status=resp.status_code, body=resp.text[:200])
                break
            body = resp.json() or {}
            items = body.get(items_key) or []
            if not items:
                break
            for item in items:
                item["_aisoc_stream"] = stream
                out.append(item)
            if not body.get("more"):
                break
            offset += len(items)
        return out

    async def _paginate_cursor(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any],
        stream: str,
        items_key: str,
    ) -> list[dict[str, Any]]:
        """Newer audit endpoint uses opaque ``cursor`` pagination."""
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(_MAX_PAGES):
            call_params = dict(params)
            if cursor:
                call_params["cursor"] = cursor
            resp = await client.get(f"{_BASE}{path}", headers=self._headers(), params=call_params)
            if resp.status_code != 200:
                logger.warning("pagerduty.audit_fetch_failed", path=path, status=resp.status_code, body=resp.text[:200])
                break
            body = resp.json() or {}
            items = body.get(items_key) or []
            if not items:
                break
            for item in items:
                item["_aisoc_stream"] = stream
                out.append(item)
            cursor = body.get("next_cursor")
            if not cursor:
                break
        return out

    # ----------------------- normalize --------------------------

    # PagerDuty incident urgency × status → AiSOC severity. Severity
    # follows the urgency primarily; resolved incidents collapse to
    # ``info`` so closed pages aren't re-surfaced as live alerts.
    _URGENCY_SEVERITY = {"high": "high", "low": "low"}

    # Vendor priority labels map per the wave-1 PagerDuty rule
    # (``info → info, warning → low, error → medium, critical → high``).
    _PRIORITY_SEVERITY = {
        "info": "info",
        "warning": "low",
        "warn": "low",
        "error": "medium",
        "critical": "high",
        "p1": "high",
        "p2": "medium",
        "p3": "low",
        "p4": "low",
        "p5": "info",
    }

    _HIGH_RISK_AUDIT_ACTIONS = (
        "user.role_changed",
        "user.delete",
        "user.create",
        "api_key.create",
        "api_key.delete",
        "extension.create",
        "extension.delete",
        "webhook_subscription.create",
        "webhook_subscription.delete",
        "service.delete",
        "escalation_policy.delete",
    )

    def _normalize_incident(self, raw: dict[str, Any]) -> dict[str, Any]:
        status = (raw.get("status") or "").lower()
        urgency = (raw.get("urgency") or "low").lower()
        priority_obj = raw.get("priority") or {}
        priority_name = (priority_obj.get("name") or "").lower() if isinstance(priority_obj, dict) else ""

        if priority_name and priority_name in self._PRIORITY_SEVERITY:
            severity = self._PRIORITY_SEVERITY[priority_name]
        else:
            severity = self._URGENCY_SEVERITY.get(urgency, "low")

        if status == "resolved":
            severity = "info"

        service = (raw.get("service") or {}).get("summary") if isinstance(raw.get("service"), dict) else None
        assignees = raw.get("assignments") or []
        assignee_email = None
        if assignees and isinstance(assignees[0], dict):
            assignee_email = (
                ((assignees[0].get("assignee") or {}).get("summary")) if isinstance(assignees[0].get("assignee"), dict) else None
            )  # noqa: E501

        link = raw.get("html_url") or (
            f"https://{self._subdomain}.pagerduty.com/incidents/{raw.get('id')}" if self._subdomain and raw.get("id") else None
        )  # noqa: E501

        return {
            "source": self.connector_id,
            "external_id": f"pagerduty-incident-{raw.get('id', raw.get('incident_number', ''))}",
            "title": raw.get("title") or raw.get("description") or "PagerDuty incident",
            "description": (
                f"service={service or 'unknown'}; status={status}; urgency={urgency}; priority={priority_name or 'none'}; url={link or 'n/a'}"  # noqa: E501
            ),  # noqa: E501
            "severity": severity,
            "actor": assignee_email,
            "actor_email": assignee_email,
            "src_ip": None,
            "event_type": f"pagerduty.incident.{status or 'updated'}",
            "raw_event": raw,
            "created_at": raw.get("created_at") or raw.get("last_status_change_at"),
        }

    def _normalize_audit(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = raw.get("action") or raw.get("event_type") or "pagerduty.audit"
        actor = raw.get("actor") or {}
        actor_email = actor.get("email") if isinstance(actor, dict) else None

        if any(action == h for h in self._HIGH_RISK_AUDIT_ACTIONS):
            severity = "high"
        elif action.endswith(".delete") or action.endswith(".destroyed"):
            severity = "medium"
        else:
            severity = "info"

        return {
            "source": self.connector_id,
            "external_id": f"pagerduty-audit-{raw.get('id', '')}",
            "title": f"PagerDuty audit: {action}",
            "description": (
                f"actor={actor_email or 'unknown'}; action={action}; method={raw.get('method', {}).get('type', '') if isinstance(raw.get('method'), dict) else ''}"  # noqa: E501
            ),  # noqa: E501
            "severity": severity,
            "actor": actor_email,
            "actor_email": actor_email,
            "src_ip": (raw.get("method") or {}).get("source_ip") if isinstance(raw.get("method"), dict) else None,
            "event_type": f"pagerduty.{action}",
            "raw_event": raw,
            "created_at": raw.get("execution_time") or raw.get("created_at"),
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "incident")
        if stream == "audit_record":
            return self._normalize_audit(raw)
        return self._normalize_incident(raw)
