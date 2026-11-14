"""
Microsoft Defender for Endpoint client via Microsoft Graph Security API.

Supports: isolate device, lift isolation, block IoC, remove IoC, trigger AV scan.

Credentials expected in ActionRequest.parameters:
    mde_tenant_id: str
    mde_client_id: str
    mde_client_secret: str
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import quote

import httpx
import structlog

logger = structlog.get_logger()

_AUTHORITY = "https://login.microsoftonline.com"
_MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"
_MDE_BASE = "https://api.securitycenter.microsoft.com/api"


def _kql_escape(value: str) -> str:
    """Escape a value for a double-quoted KQL string literal.

    KQL escapes backslash and double quote inside a quoted string, and that
    is the whole grammar. Control characters are dropped rather than escaped:
    a newline in an indicator is not an indicator, and preserving it buys
    nothing while giving a crafted value somewhere to hide.

    The value is also length-capped. A multi-kilobyte "indicator" is not one,
    and an unbounded literal is a cheap way to make a query the service
    refuses, which reads to a caller as the telemetry being unavailable.
    """
    cleaned = "".join(ch for ch in str(value)[:512] if ch.isprintable())
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


#: The only advanced-hunting queries this client will run.
#:
#: A closed set, because the caller is reachable from an investigation agent
#: and the plan forbids a model composing query text against a customer's
#: estate. Each template reads `target` and `window`, which `hunt_indicator`
#: binds as KQL `let` statements, and compares by equality only, so a value
#: has no way to become an operator. Adding a template is a reviewable change
#: to this dict rather than a string built at call time.
_HUNT_TEMPLATES: dict[str, str] = {
    "file_hash_sightings": (
        "DeviceFileEvents\n"
        "| where Timestamp > ago(window)\n"
        "| where SHA256 =~ target or SHA1 =~ target or MD5 =~ target\n"
        "| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, ActionType"
    ),
    "process_sightings": (
        "DeviceProcessEvents\n"
        "| where Timestamp > ago(window)\n"
        "| where FileName =~ target or SHA256 =~ target\n"
        "| project Timestamp, DeviceName, FileName, AccountName, InitiatingProcessFileName, ProcessCommandLine"
    ),
    "network_sightings": (
        "DeviceNetworkEvents\n"
        "| where Timestamp > ago(window)\n"
        "| where RemoteIP =~ target or RemoteUrl =~ target\n"
        "| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, ActionType"
    ),
    "logon_sightings": (
        "DeviceLogonEvents\n"
        "| where Timestamp > ago(window)\n"
        "| where AccountName =~ target or AccountUpn =~ target\n"
        "| project Timestamp, DeviceName, AccountName, AccountDomain, LogonType, RemoteIP, ActionType"
    ),
}


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

    async def list_resolved_alerts(
        self,
        since: datetime,
        until: datetime,
        *,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """List alerts an analyst resolved in the window, with their classification.

        Gap-closure Phase 1.1.

        Defender XDR separates two fields an evaluation must not conflate:
        ``classification`` is the verdict (TruePositive,
        InformationalExpectedActivity, FalsePositive, Unknown) and
        ``determination`` is the reason (Malware, SecurityTesting, Phishing and
        so on). Only the first maps to a disposition; the second is carried as
        the analyst's reason. ``Unknown`` is a real choice in the product and
        stays unlabeled.

        ``@odata.nextLink`` is followed so a window larger than one page is
        read whole rather than truncated to whatever sorted first.
        """
        results: list[dict[str, Any]] = []
        url: str | None = f"{_MDE_BASE}/alerts"
        params: dict[str, Any] | None = {
            "$filter": (
                f"status eq 'Resolved' and "
                f"lastUpdateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')} and "
                f"lastUpdateTime le {until.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            ),
            "$orderby": "lastUpdateTime asc",
            "$top": min(limit, 100),
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            while url and len(results) < limit:
                resp = await client.get(url, headers=self._headers(), params=params)
                resp.raise_for_status()
                body = resp.json() if resp.content else {}
                results.extend(body.get("value") or [])
                # nextLink already carries the filter and the skip token.
                url = body.get("@odata.nextLink")
                params = None
        logger.info("defender.resolved_alerts", count=len(results))
        return results[:limit]

    async def list_alerts_for_host(self, hostname: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Recent Defender alerts on one machine, whatever their status.

        Gap-closure Phase 4.2. Read-only.

        Resolved alerts are included on purpose. "This host raised the same
        alert three times last month and an analyst closed each as benign" is
        one of the few pieces of evidence that reliably settles a repeat
        finding, and a filter on open alerts throws it away.
        """
        machine = await self.find_machine(hostname)
        if machine is None:
            return []
        machine_id = str(machine.get("id") or "")
        if not machine_id:
            return []
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_MDE_BASE}/machines/{quote(machine_id, safe='')}/alerts",
                headers=self._headers(),
                params={"$top": min(limit, 100), "$orderby": "alertCreationTime desc"},
            )
            resp.raise_for_status()
            raw = resp.json().get("value", []) or []
        return [self._project_alert(entry) for entry in raw if isinstance(entry, dict)]

    @staticmethod
    def _project_alert(entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "alert_id": entry.get("id"),
            "title": entry.get("title"),
            "severity": entry.get("severity"),
            "category": entry.get("category"),
            "status": entry.get("status"),
            "classification": entry.get("classification"),
            "determination": entry.get("determination"),
            "detection_source": entry.get("detectionSource"),
            "threat_family": entry.get("threatFamilyName"),
            "created_at": entry.get("alertCreationTime"),
            "resolved_at": entry.get("resolvedTime"),
        }

    async def hunt_indicator(
        self,
        template: str,
        indicator: str,
        *,
        hours: int = 24,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Run one of a fixed set of advanced-hunting queries for an indicator.

        Gap-closure Phase 4.2, and the constraint is the whole design.

        Defender's advanced hunting takes KQL. The plan is explicit that a
        model must never compose query text against a customer's estate, and
        that is a security boundary rather than a style preference: the
        indicator reaching this method was lifted out of a process command
        line or a file name, which is attacker-influenced, so a model relaying
        it into a query is one injected instruction away from an arbitrary
        query over the tenant's telemetry.

        So the KQL lives **here**, as a closed set of named templates, and the
        caller supplies a template name, one indicator and a window. An
        unknown template name is a ``ValueError``, not a fallback: falling
        back to a default query would answer a question nobody asked and the
        answer would look like evidence.

        The indicator is bound through a KQL ``let`` statement with a quoted
        string literal, and the quoting escapes backslash and double quote,
        which is the whole of KQL's string escape grammar. The templates
        compare against it by equality only, so there is no place for a
        value to become an operator.
        """
        query = _HUNT_TEMPLATES.get(template)
        if query is None:
            raise ValueError(f"unknown hunting template {template!r}; known templates are {', '.join(sorted(_HUNT_TEMPLATES))}")
        window = max(1, min(hours, 720))
        kql = f'let target = "{_kql_escape(indicator)}";\nlet window = {window}h;\n{query}\n| limit {min(limit, 200)}'
        async with httpx.AsyncClient(timeout=60.0) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{_MDE_BASE}/advancedqueries/run",
                headers=self._headers(),
                json={"Query": kql},
            )
            resp.raise_for_status()
            body = resp.json() if resp.content else {}
        rows = body.get("Results") or []
        return [row for row in rows if isinstance(row, dict)]

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

    async def collect_investigation_package(
        self,
        hostname: str,
        comment: str = "AiSOC forensic acquisition",
    ) -> dict[str, Any]:
        """Start an investigation-package collection on a machine.

        MDE's investigation package is the one broad forensic acquisition in
        this client's vendor set: the agent bundles running processes, network
        connections, registry hives, prefetch, scheduled tasks and event logs
        and uploads them for download.

        Collection is **asynchronous**. This returns as soon as Defender has
        queued the machine action, with ``status`` at ``Pending`` — the package
        does not exist yet. ``get_machine_action`` is how a caller finds out
        whether it ever did.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            machine = await self._resolve_machine(client, hostname)
            machine_id = machine["id"]

            resp = await client.post(
                f"{_MDE_BASE}/machines/{machine_id}/collectInvestigationPackage",
                headers=self._headers(),
                json={"Comment": comment},
            )
            resp.raise_for_status()
            action = resp.json()
            logger.info("mde.collect_investigation_package.queued", machine_id=machine_id, hostname=hostname)
            return {
                "success": True,
                "action": "collect_investigation_package",
                "machine_id": machine_id,
                "hostname": hostname,
                "mde_action_id": action.get("id"),
                "status": action.get("status"),
            }

    async def get_machine_action(self, action_id: str) -> dict[str, Any] | None:
        """Read a machine action's current state.

        The read-back half of every asynchronous MDE action. ``status`` is one
        of ``Pending`` / ``InProgress`` / ``Succeeded`` / ``Failed`` /
        ``TimeOut`` / ``Cancelled``; only the third means the work finished.

        Returns ``None`` when the action cannot be read, so a verifier can tell
        "I could not check" apart from "it failed" — which are different facts
        and are acted on differently.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_MDE_BASE}/machineactions/{action_id}",
                headers=self._headers(),
            )
            if resp.status_code != 200:
                logger.warning("mde.get_machine_action.failed", action_id=action_id, status=resp.status_code)
                return None
            return resp.json()

    async def list_machine_actions(
        self,
        machine_id: str,
        action_type: str,
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Machine actions of one type against one machine, newest first.

        Sorted here rather than with ``$orderby`` because the ordering is the
        part a verifier depends on, and a server-side sort that silently is not
        applied would hand back the oldest action as if it were the newest.

        Returns an empty list both when there are none and when the read
        fails — the caller treats "nothing to read back" as indeterminate
        either way, and the failure is logged so it is not silent.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_MDE_BASE}/machineactions",
                headers=self._headers(),
                params={
                    "$filter": f"machineId eq '{machine_id}' and type eq '{action_type}'",
                    "$top": max(1, min(limit, 100)),
                },
            )
            if resp.status_code != 200:
                logger.warning(
                    "mde.list_machine_actions.failed",
                    machine_id=machine_id,
                    type=action_type,
                    status=resp.status_code,
                )
                return []
            actions = resp.json().get("value", [])
            return sorted(actions, key=lambda a: str(a.get("creationDateTimeUtc") or ""), reverse=True)

    async def get_investigation_package_uri(self, action_id: str) -> str | None:
        """The download URI for a completed investigation package.

        Defender only issues one once the collection succeeded, which is what
        makes it usable as evidence that a package exists rather than that a
        request was accepted. Returns ``None`` while the action is still
        running or if it never produced a package.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{_MDE_BASE}/machineactions/{action_id}/getPackageUri",
                headers=self._headers(),
            )
            if resp.status_code != 200:
                logger.warning("mde.get_package_uri.unavailable", action_id=action_id, status=resp.status_code)
                return None
            uri = resp.json().get("value")
            return str(uri) if uri else None

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
