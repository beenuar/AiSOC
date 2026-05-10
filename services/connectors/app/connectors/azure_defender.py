"""
Microsoft Defender / Microsoft 365 Defender alerts connector.

Pulls alerts from the unified Microsoft Graph Security ``alerts_v2`` endpoint.
This single feed covers Defender for Cloud, Defender for Endpoint, Defender
for Identity, Defender for Office 365, and Defender for Cloud Apps — i.e.
the post-Sentinel "XDR" alert surface.

Auth model: Azure AD app registration with the following Microsoft Graph
*application* permissions granted with admin consent:

    SecurityAlert.Read.All

(``SecurityIncident.Read.All`` is needed if you also want incidents, but
we stick to alerts here so the contract matches the other connectors.)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_PAGE_SIZE = 200


class AzureDefenderConnector(BaseConnector):
    """Microsoft 365 Defender / Defender for Cloud alerts via Graph."""

    connector_id = "azure_defender"
    connector_name = "Microsoft Defender"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Microsoft 365 Defender unified alerts feed (Defender for "
                "Cloud, Endpoint, Identity, Office 365, Cloud Apps) via "
                "Microsoft Graph. Requires SecurityAlert.Read.All."
            ),
            docs_url="/docs/connectors/azure-defender",
            fields=[
                Field("tenant_id", "string", "Tenant ID"),
                Field("client_id", "string", "Application (Client) ID"),
                Field("client_secret", "secret", "Client Secret"),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes=["https://graph.microsoft.com/SecurityAlert.Read.All"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Microsoft 365 Defender unified alerts feed.
        # WS-E4: Live Microsoft Defender for Endpoint response actions now wired
        # via services/actions/app/clients/defender_client.py
        return (
            Capability.PULL_ALERTS,
            Capability.ISOLATE_HOST,
            Capability.UNISOLATE_HOST,
            Capability.BLOCK_IOC,
            Capability.RUN_AV_SCAN,
        )

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None

    # --------------------------- auth ---------------------------

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                _TOKEN_URL.format(tenant_id=self._tenant_id),
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            await self._authenticate()
            # Pull a single alert just to confirm scope/token combo works.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_GRAPH_BASE}/security/alerts_v2",
                    headers=self._headers(),
                    params={"$top": 1},
                )
                resp.raise_for_status()
            return {
                "success": True,
                "connector": self.connector_id,
                "tenant_id": self._tenant_id,
            }
        except httpx.HTTPStatusError as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}",
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        params = {
            "$filter": f"createdDateTime ge {since}",
            "$top": _PAGE_SIZE,
            "$orderby": "createdDateTime desc",
        }

        alerts: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{_GRAPH_BASE}/security/alerts_v2",
                headers=self._headers(),
                params=params,
            )
            if resp.status_code == 401:
                await self._authenticate()
                resp = await client.get(
                    f"{_GRAPH_BASE}/security/alerts_v2",
                    headers=self._headers(),
                    params=params,
                )
            if resp.status_code != 200:
                logger.warning(
                    "azure_defender.fetch_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return []
            alerts = resp.json().get("value", [])

        return [self.normalize(a) for a in alerts]

    # ----------------------- normalize --------------------------

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Graph alerts_v2 uses {low, medium, high, informational}; map
        # informational → info to match the AiSOC scale.
        sev_in = (raw.get("severity") or "medium").lower()
        severity = {"informational": "info"}.get(sev_in, sev_in)

        # Pull the first user/host evidence so the analyst sees something
        # actionable in the queue without expanding raw_event.
        evidences = raw.get("evidence") or []
        actor = None
        actor_email = None
        host = None
        for ev in evidences:
            odata_type = ev.get("@odata.type", "")
            if "userEvidence" in odata_type and not actor:
                user_account = ev.get("userAccount", {}) or {}
                actor = user_account.get("displayName") or user_account.get("accountName")
                actor_email = user_account.get("userPrincipalName")
            elif "deviceEvidence" in odata_type and not host:
                host = ev.get("deviceDnsName") or ev.get("hostName")

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": raw.get("title", "Defender Alert"),
            "description": raw.get("description", ""),
            "severity": severity,
            "status": raw.get("status"),
            "actor": actor,
            "actor_email": actor_email,
            "host": host,
            "service_source": raw.get("serviceSource"),
            "tactics": raw.get("mitreTechniques", []),
            "category": raw.get("category"),
            "event_type": (f"azure.defender.{(raw.get('serviceSource') or 'unknown').lower()}"),
            "raw_event": raw,
            "created_at": raw.get("createdDateTime"),
        }
