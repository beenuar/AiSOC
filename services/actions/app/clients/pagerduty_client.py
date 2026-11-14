"""
PagerDuty client for the action layer.

Unlike Jira and ServiceNow which are tracker systems, PagerDuty
is an *on-call* system: the actions service uses it to **page a
human**. We use the Events API v2 (``events.pagerduty.com``)
because it requires only an integration routing key (no global
admin scope) and is the only PagerDuty path that mints incidents
without an existing trigger source.

Verbs covered:

* :meth:`trigger_incident`     — POST events.pagerduty.com/v2/enqueue
                                  with ``event_action=trigger``. AiSOC
                                  case ID is used as ``dedup_key`` so
                                  re-firing the action doesn't open
                                  duplicate pages.
* :meth:`acknowledge_incident` — same endpoint with ``event_action=
                                  acknowledge`` and the dedup_key from
                                  the trigger. PagerDuty resolves the
                                  open incident by dedup key.
* :meth:`resolve_incident`     — ``event_action=resolve``.

Severity → Events-API severity mapping is intentionally narrow
(critical / error / warning / info) because that's the closed set
the Events API accepts. AiSOC's 5-tier severity is folded into
those four buckets.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# AiSOC severity → PagerDuty Events API v2 severity. PagerDuty's
# enum is {critical, error, warning, info}, so "high" and "low"
# fold into the closest neighbour.
_PD_SEVERITY = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "info",
}


class PagerDutyError(RuntimeError):
    """Raised on a 4xx/5xx from the Events API."""


class PagerDutyClient:
    """Async wrapper for the PagerDuty Events API v2."""

    def __init__(self, routing_key: str) -> None:
        # ``routing_key`` is a 32-char integration key bound to a
        # PagerDuty service. It is NOT the REST API token; the
        # Events API v2 deliberately uses a separate auth surface
        # so the actions service never needs global scope.
        self._routing_key = routing_key

    async def _post_event(
        self,
        action: str,
        *,
        dedup_key: str,
        summary: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        custom_details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "routing_key": self._routing_key,
            "event_action": action,
            "dedup_key": dedup_key,
        }
        if action == "trigger":
            payload["payload"] = {
                "summary": summary or "AiSOC alert",
                "severity": severity or "warning",
                "source": source or "aisoc",
            }
            if custom_details:
                payload["payload"]["custom_details"] = custom_details

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(_EVENTS_URL, json=payload)
            if resp.status_code >= 400:
                raise PagerDutyError(f"pagerduty.{action} failed: {resp.status_code} {resp.text[:300]}")
            body = resp.json() or {}

        logger.info("pagerduty.event.success", action=action, dedup_key=dedup_key, status=body.get("status"))
        return {
            "dedup_key": body.get("dedup_key", dedup_key),
            "status": body.get("status"),
            "message": body.get("message"),
            "vendor": "pagerduty",
        }

    async def trigger_incident(
        self,
        *,
        summary: str,
        severity: str = "medium",
        case_id: str,
        source: str = "aisoc",
        custom_details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return await self._post_event(
            "trigger",
            dedup_key=f"aisoc-{case_id}",
            summary=summary,
            severity=_PD_SEVERITY.get(severity.lower(), "warning"),
            source=source,
            custom_details=custom_details,
        )

    async def acknowledge_incident(self, case_id: str) -> dict[str, Any]:
        return await self._post_event("acknowledge", dedup_key=f"aisoc-{case_id}")

    async def resolve_incident(self, case_id: str) -> dict[str, Any]:
        return await self._post_event("resolve", dedup_key=f"aisoc-{case_id}")
