"""
Datadog observability connector — Logs + APM events.

Sister of ``datadog_cloud_siem``: where that one pulls Cloud SIEM
*Security Signals*, this one pulls the broader observability spine
(logs from the Logs Search API, APM error spans / monitor-alert events
from the Events API). The split keeps the SIEM module's schema
single-purpose; this module is the "everything else security cares
about" surface for Datadog.

Two streams under one connector with a ``mode`` field:

  * **logs** — ``POST /api/v2/logs/events/search``. Pulls service
    logs filtered by a saved query (default: ``status:error OR
    status:critical``). Pagination via opaque ``after`` cursor.
  * **events** — ``GET /api/v1/events``. Pulls APM monitor alerts +
    custom emitted events; filterable by tags. Pagination by
    ``start``/``end`` epoch windows.

Auth is API key + Application key, region-aware base URL (same six
sites as Cloud SIEM).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_REGION_HOSTS: dict[str, str] = {
    "us1": "https://api.datadoghq.com",
    "us3": "https://api.us3.datadoghq.com",
    "us5": "https://api.us5.datadoghq.com",
    "eu1": "https://api.datadoghq.eu",
    "ap1": "https://api.ap1.datadoghq.com",
    "us1-fed": "https://api.ddog-gov.com",
}

_LOGS_PER_PAGE = 100
_MAX_PAGES = 25


class DatadogConnector(BaseConnector):
    """Datadog Logs + APM events."""

    connector_id = "datadog"
    connector_name = "Datadog (Logs + APM)"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Datadog observability events: log search across the "
                "logs platform AND APM monitor / event-stream entries. "
                "For Cloud SIEM Security Signals use the "
                "``datadog_cloud_siem`` connector."
            ),
            docs_url="/docs/connectors/datadog",
            fields=[
                Field(
                    "site",
                    "select",
                    "Datadog site",
                    options=[
                        {"value": "us1", "label": "US1 (datadoghq.com)"},
                        {"value": "us3", "label": "US3 (us3.datadoghq.com)"},
                        {"value": "us5", "label": "US5 (us5.datadoghq.com)"},
                        {"value": "eu1", "label": "EU1 (datadoghq.eu)"},
                        {"value": "ap1", "label": "AP1 (ap1.datadoghq.com)"},
                        {"value": "us1-fed", "label": "US1-FED (ddog-gov.com)"},
                    ],
                ),
                Field(
                    "mode",
                    "select",
                    "Stream",
                    options=[
                        {"value": "logs", "label": "Logs Search API"},
                        {"value": "events", "label": "Events / APM monitors"},
                    ],
                ),
                Field(
                    "query",
                    "string",
                    "Filter query",
                    required=False,
                    default="status:error OR status:critical",
                    help_text=(
                        "Logs Search query (logs mode) or tag filter "
                        "(events mode, e.g. 'priority:all')."
                    ),
                ),
                Field("api_key", "secret", "API Key"),
                Field("application_key", "secret", "Application Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_LOGS,
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.PIVOT_HOST,
        )

    def __init__(
        self,
        site: str,
        mode: str,
        api_key: str,
        application_key: str,
        query: str | None = None,
    ):
        if site not in _REGION_HOSTS:
            raise ValueError(f"datadog: unknown site '{site}'")
        if mode not in ("logs", "events"):
            raise ValueError(f"datadog: unknown mode '{mode}'")
        self._site = site
        self._base = _REGION_HOSTS[site]
        self._mode = mode
        self._query = query or "status:error OR status:critical"
        self._api_key = api_key
        self._app_key = application_key

    def _headers(self) -> dict[str, str]:
        return {
            "DD-API-KEY": self._api_key,
            "DD-APPLICATION-KEY": self._app_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/api/v1/validate",
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return {"success": True, "connector": self.connector_id, "site": self._site, "mode": self._mode}
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if self._mode == "logs":
            return await self._fetch_logs(since_seconds)
        return await self._fetch_events(since_seconds)

    async def _fetch_logs(self, since_seconds: int) -> list[dict[str, Any]]:
        end = datetime.now(UTC)
        start = end - timedelta(seconds=since_seconds)
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                body: dict[str, Any] = {
                    "filter": {
                        "from": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "to": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "query": self._query,
                    },
                    "page": {"limit": _LOGS_PER_PAGE},
                    "sort": "-timestamp",
                }
                if cursor:
                    body["page"]["cursor"] = cursor
                resp = await client.post(
                    f"{self._base}/api/v2/logs/events/search",
                    headers=self._headers(),
                    json=body,
                )
                if resp.status_code != 200:
                    logger.warning(
                        "datadog.logs_fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                payload = resp.json() or {}
                events = payload.get("data") or []
                for ev in events:
                    out.append(self.normalize({"_kind": "log", **ev}))
                cursor = ((payload.get("meta") or {}).get("page") or {}).get("after")
                if not cursor or len(events) < _LOGS_PER_PAGE:
                    break
        return out

    async def _fetch_events(self, since_seconds: int) -> list[dict[str, Any]]:
        end = int(datetime.now(UTC).timestamp())
        start = int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp())
        async with httpx.AsyncClient(timeout=30.0) as client:
            params: dict[str, Any] = {
                "start": start,
                "end": end,
                "tags": self._query if self._query and not self._query.startswith("status:") else None,
            }
            params = {k: v for k, v in params.items() if v is not None}
            resp = await client.get(
                f"{self._base}/api/v1/events",
                headers=self._headers(),
                params=params,
            )
            if resp.status_code != 200:
                logger.warning(
                    "datadog.events_fetch_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return []
            payload = resp.json() or {}
            events = payload.get("events") or []
            return [self.normalize({"_kind": "event", **ev}) for ev in events]

    _LOG_LEVEL_SEVERITY = {
        "emergency": "high",
        "alert": "high",
        "critical": "high",
        "error": "medium",
        "warn": "low",
        "warning": "low",
        "notice": "info",
        "info": "info",
        "debug": "info",
    }
    _EVENT_PRIORITY_SEVERITY = {
        "normal": "info",
        "low": "low",
    }
    _EVENT_ALERT_TYPE_SEVERITY = {
        "error": "high",
        "warning": "medium",
        "info": "info",
        "success": "info",
    }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        kind = raw.get("_kind", "log")
        if kind == "log":
            return self._normalize_log(raw)
        return self._normalize_event(raw)

    def _normalize_log(self, raw: dict[str, Any]) -> dict[str, Any]:
        attrs = raw.get("attributes") or {}
        status = (attrs.get("status") or attrs.get("level") or "").lower()
        severity = self._LOG_LEVEL_SEVERITY.get(status, "info")
        message = attrs.get("message") or attrs.get("@message") or ""
        host = attrs.get("host")
        service = attrs.get("service")
        return {
            "source": self.connector_id,
            "stream": "logs",
            "external_id": raw.get("id") or "",
            "title": (message[:120] or f"Datadog {service or 'log'}"),
            "description": message,
            "severity": severity,
            "host": host,
            "service": service,
            "event_type": f"datadog.log.{status or 'event'}",
            "raw_event": raw,
            "created_at": attrs.get("timestamp") or raw.get("timestamp"),
        }

    def _normalize_event(self, raw: dict[str, Any]) -> dict[str, Any]:
        alert_type = (raw.get("alert_type") or "").lower()
        priority = (raw.get("priority") or "").lower()
        severity = self._EVENT_ALERT_TYPE_SEVERITY.get(alert_type, "info")
        # priority normal but alert_type=error → still high; priority low never
        # *raises* severity, only floors it.
        if priority in self._EVENT_PRIORITY_SEVERITY and severity == "info":
            severity = self._EVENT_PRIORITY_SEVERITY[priority]
        return {
            "source": self.connector_id,
            "stream": "events",
            "external_id": str(raw.get("id") or ""),
            "title": raw.get("title") or "Datadog event",
            "description": raw.get("text") or raw.get("alert_type"),
            "severity": severity,
            "host": raw.get("host"),
            "event_type": f"datadog.event.{alert_type or 'event'}",
            "raw_event": raw,
            "created_at": raw.get("date_happened"),
        }
