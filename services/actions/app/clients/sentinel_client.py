"""Microsoft Sentinel REST client — incident lifecycle writeback.

Sentinel incidents live behind Azure Resource Manager, so every call needs the
full workspace path (subscription / resource group / workspace) plus an Entra
application token scoped to ``https://management.azure.com/.default``. The
app registration needs the *Microsoft Sentinel Responder* role on the
workspace; *Reader* is enough to fetch an incident and not enough to update
one, which surfaces as a 403 on the PATCH and nothing earlier.

Credentials expected in ``ActionRequest.parameters``:
    sentinel_tenant_id, sentinel_client_id, sentinel_client_secret
    sentinel_subscription_id, sentinel_resource_group, sentinel_workspace_name
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

#: Pinned: the incident ``properties`` contract differs between versions, and
#: a floating ``api-version`` would change what a PATCH means without a deploy.
API_VERSION = "2023-11-01"

ARM_BASE = "https://management.azure.com"
AUTHORITY = "https://login.microsoftonline.com"
SCOPE = "https://management.azure.com/.default"

#: Sentinel's closed-incident classifications. ``Undetermined`` is deliberately
#: absent from the writeback mapping: it is what a human picks when they gave
#: up, and it is not something the platform should claim on their behalf.
CLASSIFICATION_FALSE_POSITIVE = "FalsePositive"
CLASSIFICATION_BENIGN_POSITIVE = "BenignPositive"
CLASSIFICATION_TRUE_POSITIVE = "TruePositive"


class SentinelClient:
    """Async client for Microsoft Sentinel incident updates."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
        *,
        timeout: float = 30.0,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._workspace_name = workspace_name
        self._timeout = timeout
        self._token: str | None = None

    def _incident_url(self, incident_id: str) -> str:
        return (
            f"{ARM_BASE}/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{self._resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self._workspace_name}"
            f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}"
        )

    async def _access_token(self, client: httpx.AsyncClient) -> str:
        if self._token:
            return self._token
        response = await client.post(
            f"{AUTHORITY}/{self._tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": SCOPE,
            },
        )
        response.raise_for_status()
        self._token = response.json()["access_token"]
        return self._token

    async def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Read one incident. Used as the writeback verification probe."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            token = await self._access_token(client)
            response = await client.get(
                self._incident_url(incident_id),
                headers={"Authorization": f"Bearer {token}"},
                params={"api-version": API_VERSION},
            )
            response.raise_for_status()
            return response.json() if response.content else {}

    async def update_incident(
        self,
        incident_id: str,
        *,
        status: str,
        classification: str | None = None,
        classification_comment: str | None = None,
        owner_upn: str | None = None,
    ) -> dict[str, Any]:
        """PATCH an incident's status and classification.

        Sentinel's incident PATCH replaces ``properties`` wholesale rather than
        merging, so ``title`` and ``severity`` must be echoed back or the call
        fails validation. That means a read is not an optimisation here — it is
        required for correctness, and it is why this method issues two
        requests.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            token = await self._access_token(client)
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            url = self._incident_url(incident_id)
            params = {"api-version": API_VERSION}

            current = await client.get(url, headers=headers, params=params)
            current.raise_for_status()
            existing = (current.json() or {}).get("properties", {}) if current.content else {}

            properties: dict[str, Any] = {
                "title": existing.get("title") or f"AiSOC incident {incident_id}",
                "severity": existing.get("severity") or "Medium",
                "status": status,
            }
            if classification:
                properties["classification"] = classification
            if classification_comment:
                properties["classificationComment"] = classification_comment[:2000]
            if owner_upn:
                properties["owner"] = {"userPrincipalName": owner_upn}

            response = await client.patch(url, headers=headers, params=params, json={"properties": properties})
            response.raise_for_status()
            logger.info(
                "sentinel.incident.updated",
                incident_id=incident_id,
                status=status,
                classification=classification,
            )
            return {
                "success": True,
                "action": "update_incident",
                "incident_id": incident_id,
                "status": status,
                "classification": classification,
                "response": response.json() if response.content else {},
            }

    async def close_incident(
        self,
        incident_id: str,
        *,
        classification: str,
        comment: str,
    ) -> dict[str, Any]:
        """Close an incident with a classification and AiSOC's reasoning."""
        return await self.update_incident(
            incident_id,
            status="Closed",
            classification=classification,
            classification_comment=comment,
        )

    async def escalate_incident(
        self,
        incident_id: str,
        *,
        comment: str,
        owner_upn: str | None = None,
    ) -> dict[str, Any]:
        """Move an incident to Active and record why, leaving it OPEN.

        No classification is set: Sentinel only accepts one on a closed
        incident, and an incident AiSOC confirmed is precisely the one that
        must not be closed.
        """
        return await self.update_incident(
            incident_id,
            status="Active",
            classification_comment=comment,
            owner_upn=owner_upn,
        )
