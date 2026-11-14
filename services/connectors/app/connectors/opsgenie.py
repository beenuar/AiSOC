"""
Opsgenie connector.

Pulls Opsgenie alerts and audit logs via the REST API.

1. **Alerts** — ``GET /v2/alerts`` lists active and recently closed
   alerts. We filter by ``createdAt`` to scope the window and read the
   vendor priority (P1..P5) as the AiSOC severity input.
2. **Audit logs** — ``GET /v2/audit-logs?type=customer`` exposes the
   tenant audit trail: API key issuance, role changes, integration
   create/delete, escalation policy edits. This is the on-call security
   surface we want — an attacker who pwns Opsgenie admin can silence
   alarms across the org.

Auth: an API key issued under **Settings → Integration List → API**.
The key is a UUID; the connector sends it with the ``GenieKey`` scheme.
Opsgenie supports both EU and US data residencies; the operator picks
the matching base URL.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_DEFAULT_BASE = "https://api.opsgenie.com"
_EU_BASE = "https://api.eu.opsgenie.com"
_MAX_PAGES = 20
_PAGE_SIZE = 100


class OpsgenieConnector(BaseConnector):
    """Opsgenie alerts + tenant audit log."""

    connector_id = "opsgenie"
    connector_name = "Opsgenie"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Opsgenie on-call platform. Pulls alerts and tenant audit log "
                "events (API key issuance, role changes, integration edits) via "
                "the REST API. Choose the region matching your Opsgenie account."
            ),
            docs_url="/docs/connectors/opsgenie",
            fields=[
                Field("api_key", "secret", "API Key"),
                Field(
                    "region",
                    "select",
                    "Region",
                    default="us",
                    options=[
                        {"value": "us", "label": "US (api.opsgenie.com)"},
                        {"value": "eu", "label": "EU (api.eu.opsgenie.com)"},
                    ],
                ),
            ],
            oauth=OAuthHints(supported_in_hosted=False),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_AUDIT,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, api_key: str, region: str = "us"):
        self._api_key = api_key
        self._base = _EU_BASE if (region or "us").lower() == "eu" else _DEFAULT_BASE

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"GenieKey {self._api_key}",
            "Accept": "application/json",
            "User-Agent": "AiSOC-Connector/1.0",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/v2/account",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                    }
                data = (resp.json() or {}).get("data") or {}
            return {
                "success": True,
                "connector": self.connector_id,
                "account": data.get("name"),
                "plan": (data.get("plan") or {}).get("name") if isinstance(data.get("plan"), dict) else None,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(seconds=since_seconds)
        since_ms = int(since.timestamp() * 1000)
        # Opsgenie alert query uses a Lucene-style DSL on the createdAt
        # epoch (ms). We pull anything updated in the window.
        alerts_query = f"createdAt > {since_ms} OR updatedAt > {since_ms}"

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            alerts = await self._paginate(
                client=client,
                path="/v2/alerts",
                params={"limit": _PAGE_SIZE, "query": alerts_query, "order": "desc", "sort": "createdAt"},
                stream="alert",
            )
            events.extend(alerts)

            # Audit log: paginated with ``offset`` / ``limit`` and a
            # ``createdAtStart`` (RFC3339) filter.
            since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            audit = await self._paginate(
                client=client,
                path="/v2/audit-logs",
                params={"limit": _PAGE_SIZE, "createdAtStart": since_iso, "type": "customer"},
                stream="audit_log",
            )
            events.extend(audit)

        return [self.normalize(e) for e in events]

    async def _paginate(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any],
        stream: str,
    ) -> list[dict[str, Any]]:
        """Opsgenie pagination: response includes a ``paging.next`` URL.

        We follow ``paging.next`` up to ``_MAX_PAGES`` because that URL
        already contains the cursor / offset query string Opsgenie wants.
        """
        out: list[dict[str, Any]] = []
        url: str | None = f"{self._base}{path}"
        call_params: dict[str, Any] | None = params
        for _ in range(_MAX_PAGES):
            resp = await client.get(url, headers=self._headers(), params=call_params)
            if resp.status_code != 200:
                logger.warning("opsgenie.fetch_failed", path=path, status=resp.status_code, body=resp.text[:200])
                break
            body = resp.json() or {}
            items = body.get("data") or []
            if not items:
                break
            for item in items:
                item["_aisoc_stream"] = stream
                out.append(item)
            paging = body.get("paging") or {}
            next_url = paging.get("next")
            if not next_url:
                break
            url = next_url
            call_params = None  # next URL already carries the params
        return out

    # ----------------------- normalize --------------------------

    # Opsgenie alert ``priority`` (P1..P5) → AiSOC severity. P1/P2 are
    # operational pages that map to high/medium; P3 lands at low and
    # P4/P5 are informational.
    _PRIORITY_SEVERITY = {
        "p1": "high",
        "p2": "medium",
        "p3": "low",
        "p4": "low",
        "p5": "info",
    }

    # Audit operations always considered high-risk.
    _HIGH_RISK_AUDIT_ACTIONS = (
        "ApiIntegrationCreated",
        "ApiIntegrationDeleted",
        "ApiKeyCreated",
        "ApiKeyDeleted",
        "UserRoleChanged",
        "UserAdded",
        "UserDeleted",
        "EscalationPolicyDeleted",
        "TeamDeleted",
        "IntegrationDisabled",
        "WebhookCreated",
        "WebhookDeleted",
    )

    def _normalize_alert(self, raw: dict[str, Any]) -> dict[str, Any]:
        priority = (raw.get("priority") or "P3").lower()
        severity = self._PRIORITY_SEVERITY.get(priority, "low")
        status = (raw.get("status") or "").lower()
        if status == "closed":
            severity = "info"

        # Source: who/what created the alert. ``source`` is the
        # short-form (often an integration name); ``owner`` is the
        # current responder.
        source_name = raw.get("source") or "opsgenie"
        owner = raw.get("owner")

        return {
            "source": self.connector_id,
            "external_id": f"opsgenie-alert-{raw.get('id', raw.get('tinyId', ''))}",
            "title": raw.get("message") or "Opsgenie alert",
            "description": (
                f"priority={priority.upper()}; "
                f"status={status}; "
                f"source={source_name}; "
                f"owner={owner or 'unassigned'}; "
                f"alias={raw.get('alias', '')}"
            ),
            "severity": severity,
            "actor": owner,
            "actor_email": owner if isinstance(owner, str) and "@" in owner else None,
            "src_ip": None,
            "event_type": f"opsgenie.alert.{status or 'updated'}",
            "raw_event": raw,
            "created_at": raw.get("createdAt") or raw.get("updatedAt"),
        }

    def _normalize_audit(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = raw.get("action") or "OpsgenieAudit"
        actor = raw.get("user") or raw.get("userName") or "unknown"
        actor_email = raw.get("email")

        if any(action == h for h in self._HIGH_RISK_AUDIT_ACTIONS):
            severity = "high"
        elif action.endswith("Deleted") or action.endswith("Disabled"):
            severity = "medium"
        else:
            severity = "info"

        return {
            "source": self.connector_id,
            "external_id": f"opsgenie-audit-{raw.get('id', '')}",
            "title": f"Opsgenie audit: {action}",
            "description": f"actor={actor}; action={action}; ip={raw.get('ipAddress', '')}",
            "severity": severity,
            "actor": actor,
            "actor_email": actor_email,
            "src_ip": raw.get("ipAddress"),
            "event_type": f"opsgenie.{action}",
            "raw_event": raw,
            "created_at": raw.get("createdAt"),
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "alert")
        if stream == "audit_log":
            return self._normalize_audit(raw)
        return self._normalize_alert(raw)
