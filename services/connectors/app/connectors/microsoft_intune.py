"""Microsoft Intune device context.

Depth plan wave 2, item 1.3.

Vendor reference, verified 2026-11-01 at
learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list:

* `GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices`
* Application permission `DeviceManagementManagedDevices.Read.All`
  (the read-only half of the pair; the ReadWrite variant is never requested
  because nothing here changes vendor state).
* Token from `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`
  with scope `https://graph.microsoft.com/.default`.
* Paging follows `@odata.nextLink`.

The fields the plan's list maps onto, by their documented names:

| Plan field | Graph property |
|---|---|
| device owner | `userPrincipalName`, `userId` |
| compliance state | `complianceState` |
| OS version | `operatingSystem`, `osVersion` |
| encryption | `isEncrypted` |
| EDR agent health | `partnerReportedThreatState` |

`partnerReportedThreatState` is the mobile-threat-defence partner's own
verdict on the device, and it is the closest thing Graph's managedDevice
publishes to EDR agent health. It is carried through under its own name
rather than flattened into a boolean, because its vocabulary
(`unknown`, `activated`, `deactivated`, `secured`, `lowSeverity`,
`mediumSeverity`, `highSeverity`, `unresponsive`, `compromised`, `misconfigured`)
distinguishes "no agent is talking to us" from "the agent says this device
is fine", and a boolean would merge them.

What is deliberately not read
------------------------------
`managedDevice` returns phone numbers, IMEI, ICCID, subscriber carrier,
notes and a full device-health-attestation block. None of it is stored.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.workforce import DeviceRecord

logger = structlog.get_logger()

_GRAPH = "https://graph.microsoft.com/v1.0"
_LOGIN = "https://login.microsoftonline.com"

#: `$select` rather than the full object. Graph returns roughly sixty
#: properties per device and the plan's list needs nine; asking for nine is
#: the data minimisation, and doing it in the request means a future reader
#: cannot quietly start using a field nobody decided to collect.
_SELECT = ",".join(
    (
        "id",
        "deviceName",
        "userId",
        "userPrincipalName",
        "complianceState",
        "operatingSystem",
        "osVersion",
        "isEncrypted",
        "partnerReportedThreatState",
        "managedDeviceOwnerType",
        "serialNumber",
        "lastSyncDateTime",
    )
)

#: Graph's documented `complianceState` vocabulary. `unknown`,
#: `conflict` and `error` all mean Intune could not reach a verdict, and
#: each maps to `unknown` rather than to compliant: a device nobody
#: evaluated must never read as one that passed.
_COMPLIANCE_MAP = {
    "compliant": "compliant",
    "noncompliant": "noncompliant",
    "ingraceperiod": "in_grace_period",
    "configmanager": "unknown",
    "conflict": "unknown",
    "error": "unknown",
    "unknown": "unknown",
}

_MAX_PAGES = 200


class MicrosoftIntuneConnector(BaseConnector):
    connector_id = "microsoft_intune"
    connector_name = "Microsoft Intune"
    connector_category = "mdm"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Device owner, compliance state, OS version, encryption and threat-defence agent state "
                "from Microsoft Intune, as triage context. Read-only."
            ),
            docs_url="/docs/connectors/microsoft-intune",
            fields=[
                Field("tenant_id", "string", "Directory (tenant) ID"),
                Field("client_id", "string", "Application (client) ID"),
                Field(
                    "client_secret",
                    "secret",
                    "Client secret",
                    help_text=(
                        "The app registration needs the application permission "
                        "DeviceManagementManagedDevices.Read.All, granted with admin consent."
                    ),
                ),
            ],
            capabilities=cls.capabilities(),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_DEVICE_INVENTORY,)

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        transport: Any | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._transport = transport
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    async def _access_token(self) -> str:
        # A minute of headroom: a token that expires between the check and
        # the call produces a 401 an operator reads as a bad credential.
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token
        async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
            response = await client.post(
                f"{_LOGIN}/{self._tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            response.raise_for_status()
            body = response.json()
        self._token = str(body["access_token"])
        self._token_expires_at = time.time() + float(body.get("expires_in") or 3600)
        return self._token

    async def test_connection(self) -> dict[str, Any]:
        try:
            token = await self._access_token()
            async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
                response = await client.get(
                    f"{_GRAPH}/deviceManagement/managedDevices",
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    params={"$top": 1, "$select": "id"},
                )
                if response.status_code == 403:
                    return {
                        "ok": False,
                        "error": (
                            "Graph answered 403. The app registration is missing "
                            "DeviceManagementManagedDevices.Read.All, or admin consent has not been granted."
                        ),
                    }
                response.raise_for_status()
            return {"ok": True, "detail": "managedDevices readable"}
        except httpx.HTTPError as exc:
            return {"ok": False, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """No alerts. An MDM reports device state, not security events."""
        return []

    async def fetch_devices(self) -> list[DeviceRecord]:
        token = await self._access_token()
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        records: list[DeviceRecord] = []

        async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
            url: str | None = f"{_GRAPH}/deviceManagement/managedDevices"
            params: dict[str, Any] | None = {"$select": _SELECT, "$top": 100}
            for _ in range(_MAX_PAGES):
                if url is None:
                    break
                response = await client.get(url, headers=headers, params=params)
                response.raise_for_status()
                body = response.json()
                for device in body.get("value") or []:
                    record = self._to_record(device)
                    if record is not None:
                        records.append(record)
                # `@odata.nextLink` already carries `$select` and the skip
                # token; re-sending the first page's params would reset it.
                url = body.get("@odata.nextLink") or None
                params = None
        return records

    @staticmethod
    def _to_record(device: dict[str, Any]) -> DeviceRecord | None:
        external_id = str(device.get("id") or "").strip()
        if not external_id:
            return None

        raw_compliance = str(device.get("complianceState") or "").strip().lower()
        encrypted = device.get("isEncrypted")

        return DeviceRecord(
            external_id=external_id,
            hostname=(device.get("deviceName") or "").strip() or None,
            owner_email=(device.get("userPrincipalName") or "").strip() or None,
            owner_external_id=(str(device.get("userId") or "").strip() or None),
            compliance_state=_COMPLIANCE_MAP.get(raw_compliance, "unknown"),
            os_name=(device.get("operatingSystem") or "").strip() or None,
            os_version=(device.get("osVersion") or "").strip() or None,
            # Tri-state preserved: a device Graph did not report on is None,
            # not False. "Not encrypted" is a finding; "not reported" is not,
            # and merging them would put every unevaluated device in it.
            encrypted=(bool(encrypted) if isinstance(encrypted, bool) else None),
            edr_agent_health=(device.get("partnerReportedThreatState") or "").strip() or None,
            serial_number=(device.get("serialNumber") or "").strip() or None,
            last_seen=(device.get("lastSyncDateTime") or "").strip() or None,
        )
