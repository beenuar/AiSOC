"""
ServiceNow Table API client for the action layer.

Mirrors :class:`services.connectors.app.connectors.servicenow.ServiceNowConnector`
wire-shape. The actions service can't import from the connectors
service (separate container, separate package) so the logic lives
here twice — keep both in sync when the Table API surface drifts.

Verbs covered:

* :meth:`create_incident`  — POST ``/api/now/table/{table}``.
* :meth:`add_work_note`    — PATCH the same record with a
                              ``work_notes`` field (ServiceNow
                              treats that as an append-only journal).
* :meth:`set_state`        — PATCH ``state``; if state is 6 or 7
                              (Resolved / Closed) we also fill in
                              ``close_code`` and ``close_notes`` so
                              the UI policy doesn't silently reject
                              the transition.
"""

from __future__ import annotations

from base64 import b64encode
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


# AiSOC severity → ServiceNow impact / urgency.
# ServiceNow's incident table uses three values (1 High, 2 Medium,
# 3 Low) for both. We compress critical+high into "1" because that
# matches the ServiceNow default UX (P1).
_SEVERITY_TO_IMPACT = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}
_SEVERITY_TO_URGENCY = {"critical": "1", "high": "1", "medium": "2", "low": "3", "info": "3"}


class ServiceNowError(RuntimeError):
    """Raised on a 4xx/5xx from ServiceNow."""


class ServiceNowClient:
    """Async wrapper for the ServiceNow Table API."""

    def __init__(self, instance_url: str, username: str, password: str, table: str = "incident") -> None:
        self._base_url = instance_url.rstrip("/")
        self._username = username
        self._password = password
        # 95% of customers use the OOTB ``incident`` table for
        # security work. Enterprises on Security Incident Response
        # (``sn_si_incident``) can override.
        self._table = table

    def _headers(self) -> dict[str, str]:
        creds = b64encode(f"{self._username}:{self._password}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _record_url(self, sys_id: str) -> str:
        return f"{self._base_url}/{self._table}.do?sys_id={sys_id}"

    async def create_incident(
        self,
        *,
        short_description: str,
        description: str,
        severity: str = "medium",
        case_id: str | None = None,
        assignment_group: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "short_description": short_description[:160],
            "description": description,
            "impact": _SEVERITY_TO_IMPACT.get(severity.lower(), "2"),
            "urgency": _SEVERITY_TO_URGENCY.get(severity.lower(), "2"),
        }
        if case_id:
            # The Table API has a built-in ``correlation_id`` /
            # ``correlation_display`` pair we exploit so the inbound
            # webhook can find us without a customer-side custom
            # field. This is the same pattern the connector uses.
            payload["correlation_id"] = f"aisoc:{case_id}"
            payload["correlation_display"] = "AiSOC"
        if assignment_group:
            payload["assignment_group"] = assignment_group

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/now/table/{self._table}",
                headers=self._headers(),
                json=payload,
            )
            if resp.status_code >= 400:
                raise ServiceNowError(f"servicenow.create_incident failed: {resp.status_code} {resp.text[:300]}")
            data = (resp.json() or {}).get("result", {})

        sys_id = data.get("sys_id") or ""
        number = data.get("number")
        logger.info("servicenow.create_incident.success", sys_id=sys_id, number=number)
        return {
            "external_id": sys_id,
            "external_number": number,
            "external_url": self._record_url(sys_id) if sys_id else None,
            "vendor": "servicenow",
            "state": data.get("state") or "1",
        }

    async def add_work_note(self, sys_id: str, note: str) -> dict[str, Any]:
        """Append a journal entry. ``work_notes`` is the
        operator-visible journal; ``comments`` is customer-visible.
        We always use ``work_notes`` because AiSOC is internal.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.patch(
                f"{self._base_url}/api/now/table/{self._table}/{sys_id}",
                headers=self._headers(),
                json={"work_notes": note},
            )
            if resp.status_code >= 400:
                raise ServiceNowError(f"servicenow.add_work_note failed: {resp.status_code} {resp.text[:300]}")
        logger.info("servicenow.add_work_note.success", sys_id=sys_id)
        return {"sys_id": sys_id, "noted": True}

    async def set_state(self, sys_id: str, state: str, *, case_id: str | None = None) -> dict[str, Any]:
        """Change incident state. For Resolved (6) / Closed (7) we
        also stuff in close_code + close_notes since stock SN UI
        policies require them or the API silently drops the
        transition.
        """
        payload: dict[str, Any] = {"state": str(state)}
        if str(state) in {"6", "7"}:
            payload["close_code"] = "Closed/Resolved by Caller"
            payload["close_notes"] = f"Closed by AiSOC (case {case_id or 'n/a'})"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.patch(
                f"{self._base_url}/api/now/table/{self._table}/{sys_id}",
                headers=self._headers(),
                json=payload,
            )
            if resp.status_code >= 400:
                raise ServiceNowError(f"servicenow.set_state failed: {resp.status_code} {resp.text[:300]}")
        logger.info("servicenow.set_state.success", sys_id=sys_id, state=state)
        return {"sys_id": sys_id, "state": str(state)}
