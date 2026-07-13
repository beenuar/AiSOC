"""Windows Event Log / Sysmon connector (WEF collector pull).

Pulls Windows security + Sysmon events that a Windows Event Forwarding (WEF)
collector — or a lightweight agent — has exported as JSON to an HTTP spool
endpoint, and folds each into the common AiSOC alert shape. Severity is derived
from the event's channel + Event ID: known high-signal Security/Sysmon IDs
(process injection, credential dumping surfaces, log clears, new services) are
floored appropriately rather than defaulting to noise.

This is the poll half of the Windows story; the push/agent half arrives via the
universal-capture inbox. The collector endpoint + shared token are
operator-supplied.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 500

# Event IDs that a SOC almost always wants surfaced, with a severity floor.
# Security channel + Sysmon (Microsoft-Windows-Sysmon/Operational).
_HIGH_EVENT_IDS = {
    "1102": "high",  # Security log cleared
    "4720": "medium",  # user account created
    "4728": "medium",  # member added to security-enabled global group
    "4732": "medium",  # member added to security-enabled local group
    "4672": "low",  # special privileges assigned to new logon
    "7045": "high",  # new service installed
    "4688": "low",  # process creation
    # Sysmon
    "1": "low",  # process create
    "8": "high",  # CreateRemoteThread (injection)
    "10": "high",  # ProcessAccess (LSASS access surface)
    "11": "low",  # FileCreate
    "13": "low",  # RegistryValueSet
    "22": "low",  # DNS query
}


class WindowsEventConnector(BaseConnector):
    """Windows Event Log / Sysmon via a WEF collector spool."""

    connector_id = "windows_event"
    connector_name = "Windows Event / Sysmon"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull Windows Security + Sysmon events from a Windows Event "
                "Forwarding (WEF) collector's JSON spool endpoint. Severity is "
                "derived from channel + Event ID (log clears, service installs, "
                "process injection floored appropriately)."
            ),
            docs_url="/docs/connectors/windows_event",
            fields=[
                Field("collector_url", "string", "Collector spool URL", placeholder="https://wef-collector.internal/spool"),
                Field("api_token", "secret", "Spool token"),
                Field("verify_tls", "boolean", "Verify TLS certificate", required=False, default=True),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PULL_LOGS, Capability.PIVOT_HOST)

    def __init__(self, collector_url: str, api_token: str, verify_tls: bool = True) -> None:
        self._base = collector_url.rstrip("/")
        self._token = api_token
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(self._base, headers=self._headers(), params={"limit": 1})
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify) as client:
                resp = await client.get(self._base, headers=self._headers(), params={"limit": _LIMIT, "since": since_seconds})
            if resp.status_code != 200:
                logger.warning("windows_event.fetch_failed", status=resp.status_code)
                return out
            body = resp.json() or {}
            events = body.get("events") if isinstance(body, dict) else body
            for ev in events or []:
                out.append(self.normalize(ev))
        except Exception as exc:  # noqa: BLE001
            logger.warning("windows_event.fetch_error", error=str(exc))
        return out

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Accept both flat and nested (WEF `Event.System`) shapes.
        system = raw.get("System") or raw.get("system") or {}
        event_id = str(raw.get("EventID") or raw.get("event_id") or system.get("EventID") or "")
        channel = raw.get("Channel") or raw.get("channel") or system.get("Channel") or ""
        computer = raw.get("Computer") or raw.get("computer") or system.get("Computer")
        data = raw.get("EventData") or raw.get("event_data") or {}
        severity = _HIGH_EVENT_IDS.get(event_id, "info")
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": severity,
            "title": f"Windows {channel or 'event'} EventID {event_id}",
            "description": (f"channel={channel}; event_id={event_id}; computer={computer}"),
            "external_id": str(raw.get("RecordId") or raw.get("record_id") or system.get("EventRecordID") or ""),
            "hostname": computer,
            "username": data.get("TargetUserName") or data.get("SubjectUserName") or data.get("User"),
            "process_name": data.get("Image") or data.get("NewProcessName"),
            "event_type": f"windows.{(channel or 'event').lower()}.{event_id}",
            "created_at": raw.get("TimeCreated") or system.get("TimeCreated"),
            "raw": raw,
        }
