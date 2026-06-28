"""
Microsoft Defender for Endpoint client via Microsoft Graph Security API.

Supports: isolate device, lift isolation, block IoC, remove IoC, trigger AV scan.

Credentials expected in ActionRequest.parameters:
    mde_tenant_id: str
    mde_client_id: str
    mde_client_secret: str
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_AUTHORITY = "https://login.microsoftonline.com"
_MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"
_MDE_BASE = "https://api.securitycenter.microsoft.com/api"


class DefenderClient:
    """Async client for Microsoft Defender for Endpoint management actions."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            f"{_AUTHORITY}/{self._tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": _MDE_SCOPE,
            },
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _ensure_token(self, client: httpx.AsyncClient) -> None:
        if not self._token:
            await self._authenticate(client)

    async def find_machine(self, hostname: str) -> dict[str, Any] | None:
        """Look up a machine by hostname in Defender for Endpoint."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_MDE_BASE}/machines",
                headers=self._headers(),
                params={"$filter": f"computerDnsName eq '{hostname}'", "$top": 1},
            )
            resp.raise_for_status()
            machines = resp.json().get("value", [])
            return machines[0] if machines else None

    async def isolate_machine(self, hostname: str, comment: str = "AiSOC automated isolation") -> dict[str, Any]:
        """Isolate a machine from the network via MDE."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            machine = await self._resolve_machine(client, hostname)
            machine_id = machine["id"]

            resp = await client.post(
                f"{_MDE_BASE}/machines/{machine_id}/isolate",
                headers=self._headers(),
                json={"Comment": comment, "IsolationType": "Full"},
            )
            resp.raise_for_status()
            action = resp.json()
            logger.info("mde.isolate_machine.success", machine_id=machine_id, hostname=hostname)
            return {
                "success": True,
                "action": "isolate_machine",
                "machine_id": machine_id,
                "hostname": hostname,
                "mde_action_id": action.get("id"),
            }

    async def unisolate_machine(self, hostname: str, comment: str = "AiSOC automated lift") -> dict[str, Any]:
        """Remove a machine from isolation."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            machine = await self._resolve_machine(client, hostname)
            machine_id = machine["id"]

            resp = await client.post(
                f"{_MDE_BASE}/machines/{machine_id}/unisolate",
                headers=self._headers(),
                json={"Comment": comment},
            )
            resp.raise_for_status()
            logger.info("mde.unisolate_machine.success", machine_id=machine_id)
            return {"success": True, "action": "unisolate_machine", "machine_id": machine_id, "hostname": hostname}

    async def block_ioc(
        self,
        indicator_type: str,
        indicator_value: str,
        title: str = "AiSOC block",
        severity: str = "High",
    ) -> dict[str, Any]:
        """Add a block indicator (IP, URL, domain, file hash) to MDE.

        indicator_type: FileSha1 | FileSha256 | FileMd5 | IpAddress | Url | DomainName
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_MDE_BASE}/indicators",
                headers=self._headers(),
                json={
                    "indicatorValue": indicator_value,
                    "indicatorType": indicator_type,
                    "action": "Block",
                    "title": title,
                    "severity": severity,
                    "generateAlert": True,
                },
            )
            resp.raise_for_status()
            indicator = resp.json()
            logger.info("mde.block_ioc.success", type=indicator_type, value=indicator_value)
            return {
                "success": True,
                "action": "block_ioc",
                "indicator_id": indicator.get("id"),
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
            }

    async def remove_ioc(self, indicator_id: str) -> dict[str, Any]:
        """Remove a block indicator from MDE."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.delete(
                f"{_MDE_BASE}/indicators/{indicator_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            logger.info("mde.remove_ioc.success", indicator_id=indicator_id)
            return {"success": True, "action": "remove_ioc", "indicator_id": indicator_id}

    async def run_av_scan(self, hostname: str, scan_type: str = "Full") -> dict[str, Any]:
        """Trigger an antivirus scan on a machine (Quick or Full)."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            machine = await self._resolve_machine(client, hostname)
            machine_id = machine["id"]

            resp = await client.post(
                f"{_MDE_BASE}/machines/{machine_id}/runAntiVirusScan",
                headers=self._headers(),
                json={"Comment": "AiSOC automated AV scan", "ScanType": scan_type},
            )
            resp.raise_for_status()
            action = resp.json()
            logger.info("mde.run_av_scan.success", machine_id=machine_id, scan_type=scan_type)
            return {
                "success": True,
                "action": "run_av_scan",
                "machine_id": machine_id,
                "hostname": hostname,
                "scan_type": scan_type,
                "mde_action_id": action.get("id"),
            }

    async def _resolve_machine(self, client: httpx.AsyncClient, hostname: str) -> dict[str, Any]:
        """Resolve hostname to MDE machine object (with auth already ensured)."""
        resp = await client.get(
            f"{_MDE_BASE}/machines",
            headers=self._headers(),
            params={"$filter": f"computerDnsName eq '{hostname}'", "$top": 1},
        )
        resp.raise_for_status()
        machines = resp.json().get("value", [])
        if not machines:
            raise ValueError(f"No MDE machine found for hostname: {hostname}")
        return machines[0]

    # ──────────────────────────────────────────────────────────────
    # Phase 3.3 — alert lifecycle (ack + suppress)
    # ──────────────────────────────────────────────────────────────

    async def acknowledge_alert(
        self,
        alert_id: str,
        comment: str = "Acknowledged by AiSOC",
        assigned_to: str | None = None,
    ) -> dict[str, Any]:
        """Mark a Defender alert as ``InProgress``.

        MDE alert states are ``New`` / ``InProgress`` / ``Resolved``.
        Acknowledgement maps to InProgress because the alert is now
        being worked but not yet closed.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            body: dict[str, Any] = {
                "status": "InProgress",
                "comments": [{"comment": comment}],
            }
            if assigned_to:
                body["assignedTo"] = assigned_to
            resp = await client.patch(
                f"{_MDE_BASE}/alerts/{alert_id}",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            logger.info("mde.alert.acknowledged", alert_id=alert_id)
            return {
                "success": True,
                "action": "acknowledge_alert",
                "alert_id": alert_id,
                "response": resp.json() if resp.content else {},
            }

    async def suppress_alert(
        self,
        alert_id: str,
        *,
        classification: str = "FalsePositive",
        determination: str = "NotAvailable",
        comment: str = "Suppressed by AiSOC",
    ) -> dict[str, Any]:
        """Resolve + classify a Defender alert.

        MDE requires a classification ("TruePositive" / "Informational" /
        "FalsePositive") when moving an alert to ``Resolved``. We
        default to FalsePositive because that's the operationally
        useful suppression case — AiSOC has decided the signal isn't
        actionable. Operators driving a TruePositive close from a
        playbook should override the argument.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            body = {
                "status": "Resolved",
                "classification": classification,
                "determination": determination,
                "comments": [{"comment": comment}],
            }
            resp = await client.patch(
                f"{_MDE_BASE}/alerts/{alert_id}",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            logger.info("mde.alert.suppressed", alert_id=alert_id, classification=classification)
            return {
                "success": True,
                "action": "suppress_alert",
                "alert_id": alert_id,
                "classification": classification,
                "response": resp.json() if resp.content else {},
            }
