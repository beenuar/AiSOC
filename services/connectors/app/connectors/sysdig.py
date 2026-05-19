"""
Sysdig Secure runtime / cloud detection connector.

Sysdig Secure exposes a Secure Events API (often referred to as the
"events forwarder" downstream of the same Falco engine that powers the
``falco`` open-source connector). Each event is a runtime policy hit
keyed by rule name, with severity 0..7 on the Falco syslog ladder.

Auth is a per-tenant API token; the base URL is region-prefixed
(`https://secure.sysdig.com`, `https://eu1.app.sysdig.com`, etc.). The
``/api/v1/secureEvents`` endpoint paginates by ``offset`` + ``limit`` or
by ``cursor`` depending on the tenant's API version — we walk both.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_REGION_HOSTS: dict[str, str] = {
    "us1": "https://secure.sysdig.com",
    "us2": "https://us2.app.sysdig.com",
    "us3": "https://app.us3.sysdig.com",
    "us4": "https://app.us4.sysdig.com",
    "eu1": "https://eu1.app.sysdig.com",
    "au1": "https://app.au1.sysdig.com",
    "me2": "https://app.me2.sysdig.com",
}

_PER_PAGE = 100
_MAX_PAGES = 25


class SysdigConnector(BaseConnector):
    """Sysdig Secure runtime events."""

    connector_id = "sysdig"
    connector_name = "Sysdig Secure"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Sysdig Secure runtime / cloud detection events. Polls "
                "the Secure Events API for Falco-style policy hits "
                "across Kubernetes workloads and cloud accounts."
            ),
            docs_url="/docs/connectors/sysdig",
            fields=[
                Field(
                    "region",
                    "select",
                    "Sysdig region",
                    options=[
                        {"value": "us1", "label": "US-East (secure.sysdig.com)"},
                        {"value": "us2", "label": "US-West (us2.app.sysdig.com)"},
                        {"value": "us3", "label": "US3 (app.us3.sysdig.com)"},
                        {"value": "us4", "label": "US4 (app.us4.sysdig.com)"},
                        {"value": "eu1", "label": "EU-Frankfurt (eu1.app.sysdig.com)"},
                        {"value": "au1", "label": "Australia (app.au1.sysdig.com)"},
                        {"value": "me2", "label": "Middle East (app.me2.sysdig.com)"},
                    ],
                ),
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=("Sysdig Secure API token. Settings → API → Tokens. " "Needs read access to Secure Events."),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_LOGS,
            Capability.PIVOT_HOST,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, region: str, api_token: str):
        if region not in _REGION_HOSTS:
            raise ValueError(f"sysdig: unknown region '{region}'")
        self._region = region
        self._base = _REGION_HOSTS[region]
        self._api_token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/api/v1/secureEvents",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "region": self._region,
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        end_ns = int(datetime.now(UTC).timestamp() * 1_000_000_000)
        start_ns = int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp() * 1_000_000_000)
        out: list[dict[str, Any]] = []
        offset = 0
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                params: dict[str, Any] = {
                    "from": start_ns,
                    "to": end_ns,
                    "limit": _PER_PAGE,
                }
                if cursor:
                    params["cursor"] = cursor
                else:
                    params["offset"] = offset
                resp = await client.get(
                    f"{self._base}/api/v1/secureEvents",
                    headers=self._headers(),
                    params=params,
                )
                if resp.status_code != 200:
                    logger.warning(
                        "sysdig.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                body = resp.json() or {}
                events = body.get("data") or body.get("events") or []
                for ev in events:
                    out.append(self.normalize(ev))
                # Newer tenants use ``page.next`` / ``cursor``; older ones
                # use offset arithmetic. Try cursor first, then advance offset.
                page = body.get("page") or {}
                next_cursor = page.get("next") or body.get("next") or body.get("nextCursor")
                if next_cursor:
                    cursor = next_cursor
                    if len(events) < _PER_PAGE:
                        break
                else:
                    if len(events) < _PER_PAGE:
                        break
                    offset += len(events)
        return out

    # Falco syslog ladder (0=Emergency .. 7=Debug). Sysdig surfaces this
    # both as a numeric level and as a name; we accept either.
    _FALCO_NUM_SEVERITY = {
        0: "high",  # emergency
        1: "high",  # alert
        2: "high",  # critical
        3: "medium",  # error
        4: "low",  # warning
        5: "info",  # notice
        6: "info",  # info
        7: "info",  # debug
    }
    _FALCO_NAME_SEVERITY = {
        "emergency": "high",
        "alert": "high",
        "critical": "high",
        "error": "medium",
        "warning": "low",
        "warn": "low",
        "notice": "info",
        "info": "info",
        "informational": "info",
        "debug": "info",
    }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        labels = raw.get("labels") or {}
        sev_raw = raw.get("severity")
        if isinstance(sev_raw, int):
            sev = self._FALCO_NUM_SEVERITY.get(sev_raw, "info")
        else:
            sev = self._FALCO_NAME_SEVERITY.get(str(sev_raw or "").lower(), "info")
        rule = raw.get("ruleName") or raw.get("rule") or labels.get("rule") or "policy"
        # Anomalous-process / drift / interactive-shell policies escalate to
        # high even when the rule's own severity is warning — these are the
        # canonical Falco "you do not want to see this in prod" signals and
        # are never benign once they fire.
        rule_lower = rule.lower()
        if "drift" in rule_lower or "tampering" in rule_lower or "terminal shell" in rule_lower or "shell in container" in rule_lower:
            sev = "high"
        host = labels.get("host.hostname") or labels.get("kubernetes.node.name") or raw.get("hostname")
        ns = labels.get("kubernetes.namespace.name")
        pod = labels.get("kubernetes.pod.name")
        container = labels.get("container.name") or labels.get("kubernetes.container.name")
        user = labels.get("user.name") or labels.get("aws.user.identity") or labels.get("k8s.user.name")
        return {
            "source": self.connector_id,
            "external_id": raw.get("id") or raw.get("eventId") or "",
            "title": rule,
            "description": raw.get("description") or raw.get("output") or rule,
            "severity": sev,
            "host": host,
            "actor": user,
            "namespace": ns,
            "pod": pod,
            "container": container,
            "event_type": f"sysdig.{rule.lower().replace(' ', '_')}",
            "raw_event": raw,
            "created_at": raw.get("timestamp") or raw.get("@timestamp"),
        }
