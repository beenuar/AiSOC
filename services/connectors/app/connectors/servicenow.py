"""
ServiceNow connector.

Fetches security-relevant incidents from the ServiceNow Table API and,
under Workstream 8, projects AiSOC cases / status changes back into
ServiceNow as ``incident`` records.
"""

from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# ServiceNow's OOTB incident table exposes a 3-tier ``impact`` field
# (1=High, 2=Medium, 3=Low) but a 5-tier *computed* ``priority`` field
# (1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning). We prefer
# ``priority`` for inbound normalisation because it round-trips AiSOC's
# 5-tier ladder (info | low | medium | high | critical) losslessly; we
# fall back to ``impact`` only when ``priority`` is missing.
_PRIORITY_SEVERITY = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "info",
}

_IMPACT_SEVERITY = {
    "1": "high",
    "2": "medium",
    "3": "low",
}

# WS8: AiSOC severity → ServiceNow ``impact`` numeric code. ServiceNow's
# ``impact`` field is 3-tier (1=High / 2=Medium / 3=Low), so we set
# impact=1 + urgency=1 together — ServiceNow's calculated ``priority``
# matrix turns ``impact=1 + urgency=1`` into priority 1 ("Critical"),
# which preserves the P1 signal even though ``impact`` itself has no
# separate critical band. ``info`` collapses to impact=3 / urgency=3,
# which yields priority 5 ("Planning") — the closest analog ServiceNow
# ships out of the box.
_SEVERITY_TO_IMPACT = {
    "critical": "1",
    "high": "1",
    "medium": "2",
    "low": "3",
    "info": "3",
}

# Urgency mirrors impact but pushes ``critical`` to 1 and ``high`` to 2
# so the resulting priority matrix differentiates them:
#   critical: impact=1 + urgency=1 → priority 1 (Critical)
#   high    : impact=1 + urgency=2 → priority 2 (High)
_SEVERITY_TO_URGENCY = {
    "critical": "1",
    "high": "2",
    "medium": "2",
    "low": "3",
    "info": "3",
}

# WS8: AiSOC status → ServiceNow ``state`` numeric code. The default
# ServiceNow incident state field is a numeric choice list:
#   1=New, 2=In Progress, 3=On Hold, 6=Resolved, 7=Closed, 8=Canceled.
# We map AiSOC's lifecycle onto that vocabulary. Customers with custom
# state lists can override via ``connector_config.state_map`` in a
# future iteration; the defaults below cover the OOTB table.
_STATUS_MAP_SNOW = {
    "new": "1",
    "triaged": "2",
    "investigating": "2",
    "contained": "2",
    "resolved": "6",
    "closed": "7",
}


class ServiceNowConnector(BaseConnector):
    connector_id = "servicenow"
    connector_name = "ServiceNow"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="ServiceNow incidents via the Table API.",
            docs_url="/docs/connectors/servicenow",
            fields=[
                Field(
                    "instance_url",
                    "string",
                    "Instance URL",
                    placeholder="https://yourinstance.service-now.com",
                ),
                Field("username", "string", "Username"),
                Field("password", "secret", "Password"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # WS8: bidirectional ticketing landed; ServiceNow can now mint
        # incidents from AiSOC cases (PUSH_CASE) and project status
        # transitions onto them (PUSH_STATUS) in addition to pulling
        # incidents.
        return (Capability.PULL_ALERTS, Capability.PUSH_CASE, Capability.PUSH_STATUS)

    def __init__(self, instance_url: str, username: str, password: str):
        self._base_url = instance_url.rstrip("/")
        self._username = username
        self._password = password

    def _auth_header(self) -> dict[str, str]:
        creds = b64encode(f"{self._username}:{self._password}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/api/now/table/incident",
                    headers=self._auth_header(),
                    params={"sysparm_limit": 1},
                )
                resp.raise_for_status()
            return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("servicenow.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%d %H:%M:%S")

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self._base_url}/api/now/table/incident",
                headers=self._auth_header(),
                params={
                    "sysparm_query": f"sys_created_on>={since}^ORsys_updated_on>={since}",
                    "sysparm_limit": 100,
                    "sysparm_display_value": "true",
                },
            )
            resp.raise_for_status()
            incidents = resp.json().get("result", [])

        return [self.normalize(i) for i in incidents]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # ServiceNow returns these fields as strings under
        # ``sysparm_display_value=true``, but as nested dicts
        # (``{"value": "1", "display_value": "Critical"}``) under
        # ``sysparm_display_value=all``. Defend against both.
        def _coerce(field: Any) -> str | None:
            if isinstance(field, dict):
                return str(field.get("value")) if field.get("value") is not None else None
            return str(field) if field not in (None, "") else None

        priority = _coerce(raw.get("priority"))
        impact = _coerce(raw.get("impact")) or "3"

        severity = _PRIORITY_SEVERITY.get(priority) if priority else None
        if severity is None:
            severity = _IMPACT_SEVERITY.get(impact, "low")

        return {
            "source": self.connector_id,
            "external_id": raw.get("sys_id", ""),
            "title": raw.get("short_description", "ServiceNow Incident"),
            "description": raw.get("description", "")[:500],
            "severity": severity,
            "src_ip": None,
            "hostname": raw.get("cmdb_ci", {}).get("display_value") if isinstance(raw.get("cmdb_ci"), dict) else raw.get("cmdb_ci"),
            "actor": raw.get("opened_by", {}).get("display_value") if isinstance(raw.get("opened_by"), dict) else raw.get("opened_by"),
            "raw_event": raw,
            "created_at": raw.get("sys_created_on"),
        }

    # ------------------------------------------------------------------
    # WS8: bidirectional ticket sync.
    # ------------------------------------------------------------------
    #
    # ServiceNow's Table API is uniform across record types — POST to
    # ``/api/now/table/incident`` to create, PATCH to
    # ``/api/now/table/incident/{sys_id}`` to update. The implementation
    # below intentionally targets the OOTB ``incident`` table because
    # that's what 95% of customers use for security work; an enterprise
    # using ``sn_si_incident`` (Security Incident Response) can override
    # ``_table`` once we expose it as a config field.
    #
    # Two ServiceNow-specific gotchas the code defends against:
    #
    #   1. Records are identified by ``sys_id`` (a 32-char hex GUID),
    #      NOT by ``number`` (e.g. ``INC0010023``). We persist
    #      ``sys_id`` as the external_id and surface ``number`` only
    #      in the URL the operator clicks.
    #   2. State transitions can fail silently if the customer's UI
    #      policy requires a ``close_code`` / ``close_notes`` for
    #      Resolved/Closed states. We send minimal close metadata when
    #      transitioning to those states so the API call doesn't bounce.

    _table = "incident"

    def _record_url(self, sys_id: str, number: str | None = None) -> str:
        """Best-effort browser URL for a ServiceNow incident."""
        if number:
            return f"{self._base_url}/nav_to.do?uri=incident.do?sys_id={sys_id}"
        return f"{self._base_url}/{self._table}.do?sys_id={sys_id}"

    async def push_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Mint a ServiceNow incident from an AiSOC case."""
        severity = (case.get("severity") or "medium").lower()
        title = case.get("title") or f"AiSOC case {case.get('case_number') or case.get('id')}"
        description = case.get("description") or ""
        case_id = case.get("id") or case.get("case_number")

        payload: dict[str, Any] = {
            "short_description": title[:160],  # ServiceNow short_description cap.
            "description": description,
            "impact": _SEVERITY_TO_IMPACT.get(severity, "2"),
            "urgency": _SEVERITY_TO_URGENCY.get(severity, "2"),
            # Round-trip the AiSOC case identifier in ``correlation_id``
            # so the inbound webhook can find us without a custom field.
            "correlation_id": f"aisoc:{case_id}",
            "correlation_display": "AiSOC",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/now/table/{self._table}",
                headers={
                    **self._auth_header(),
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code >= 400:
                raise httpx.HTTPStatusError(
                    f"servicenow.push_case failed: {resp.status_code} {resp.text[:300]}",
                    request=resp.request,
                    response=resp,
                )
            data = (resp.json() or {}).get("result", {})

        sys_id = data.get("sys_id") or ""
        number = data.get("number")
        return {
            "external_id": sys_id,
            "external_url": self._record_url(sys_id, number) if sys_id else None,
            "vendor": self.connector_id,
            "external_status": data.get("state") or "1",
        }

    async def push_status_change(
        self,
        case: dict[str, Any],
        old_status: str,
        new_status: str,
        external_ref: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Project an AiSOC status transition onto a ServiceNow incident."""
        if external_ref is None:
            return await self.push_case(case)

        sys_id = (external_ref or {}).get("external_id")
        if not sys_id:
            raise ValueError("servicenow.push_status_change: external_ref missing external_id")

        target_state = _STATUS_MAP_SNOW.get(new_status)
        if not target_state:
            logger.info(
                "servicenow.push_status_change.no_mapping",
                external_id=sys_id,
                old=old_status,
                new=new_status,
            )
            return {
                "external_id": sys_id,
                "external_url": self._record_url(sys_id),
                "vendor": self.connector_id,
                "external_status": (external_ref or {}).get("external_status"),
            }

        payload: dict[str, Any] = {"state": target_state}
        # Resolved/Closed states require close_code + close_notes on
        # most stock ServiceNow instances or the API silently ignores
        # the state change. Send a benign default so the transition
        # actually applies.
        if target_state in {"6", "7"}:
            payload["close_code"] = "Closed/Resolved by Caller"
            payload["close_notes"] = f"Closed by AiSOC (case {case.get('case_number') or case.get('id')})"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.patch(
                f"{self._base_url}/api/now/table/{self._table}/{sys_id}",
                headers={
                    **self._auth_header(),
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            if resp.status_code >= 400:
                raise httpx.HTTPStatusError(
                    f"servicenow.push_status_change failed: {resp.status_code} {resp.text[:300]}",
                    request=resp.request,
                    response=resp,
                )

        return {
            "external_id": sys_id,
            "external_url": self._record_url(sys_id),
            "vendor": self.connector_id,
            "external_status": target_state,
        }
