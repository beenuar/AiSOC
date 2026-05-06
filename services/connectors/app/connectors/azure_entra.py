"""
Azure Entra ID (formerly Azure AD) connector.

Pulls directory audit logs and risky sign-in events via Microsoft Graph.
This is the identity-plane counterpart to ``azure_activity`` (control plane)
and ``azure_defender`` (security plane).

Auth model: Azure AD app registration with the following Microsoft Graph
*application* permissions granted with admin consent:

    AuditLog.Read.All
    Directory.Read.All
    IdentityRiskyUser.Read.All  (only if you want risky-user signals)

We use the OAuth2 client-credentials flow, scoped to ``.default`` so the
token reflects exactly the consented permissions — that way the connector
fails closed if an operator forgets to grant a scope.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Microsoft Graph caps `$top` at 1000 for these collections; 200 keeps each
# round-trip fast and rate-limit friendly while still covering normal volume.
_PAGE_SIZE = 200


class AzureEntraConnector(BaseConnector):
    """Microsoft Entra ID directory audits + risky sign-ins."""

    connector_id = "azure_entra"
    connector_name = "Microsoft Entra ID"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Microsoft Entra ID (Azure AD) directory audits and risky "
                "sign-ins via Microsoft Graph. Requires AuditLog.Read.All "
                "and Directory.Read.All application permissions."
            ),
            docs_url="/docs/connectors/azure-entra",
            fields=[
                Field("tenant_id", "string", "Tenant ID", placeholder="00000000-0000-0000-0000-000000000000"),
                Field("client_id", "string", "Application (Client) ID"),
                Field("client_secret", "secret", "Client Secret"),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes=[
                    "https://graph.microsoft.com/AuditLog.Read.All",
                    "https://graph.microsoft.com/Directory.Read.All",
                ],
            ),
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
            # Hit a cheap Graph endpoint to confirm the token can actually
            # reach the directory; the token call alone doesn't verify scopes.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_GRAPH_BASE}/organization?$select=id,displayName",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                orgs = resp.json().get("value", [])
            return {
                "success": True,
                "connector": self.connector_id,
                "tenant_id": self._tenant_id,
                "organization": orgs[0].get("displayName") if orgs else None,
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

        # Graph wants ISO 8601 with milliseconds, e.g. ``2024-01-01T00:00:00.000Z``.
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Directory audits — admin/role/policy/group changes etc.
            audit_params = {
                "$filter": f"activityDateTime ge {since}",
                "$top": _PAGE_SIZE,
                "$orderby": "activityDateTime desc",
            }
            audit_resp = await client.get(
                f"{_GRAPH_BASE}/auditLogs/directoryAudits",
                headers=self._headers(),
                params=audit_params,
            )
            if audit_resp.status_code == 401:
                await self._authenticate()
                audit_resp = await client.get(
                    f"{_GRAPH_BASE}/auditLogs/directoryAudits",
                    headers=self._headers(),
                    params=audit_params,
                )
            if audit_resp.status_code == 200:
                for raw in audit_resp.json().get("value", []):
                    raw["_aisoc_event_kind"] = "directoryAudit"
                    events.append(raw)
            else:
                logger.warning(
                    "azure_entra.directory_audits.fetch_failed",
                    status=audit_resp.status_code,
                    body=audit_resp.text[:300],
                )

            # Risky sign-ins — these are higher-signal than every signIn.
            signin_params = {
                "$filter": (f"createdDateTime ge {since} and riskLevelAggregated ne 'none'"),
                "$top": _PAGE_SIZE,
                "$orderby": "createdDateTime desc",
            }
            signin_resp = await client.get(
                f"{_GRAPH_BASE}/auditLogs/signIns",
                headers=self._headers(),
                params=signin_params,
            )
            if signin_resp.status_code == 200:
                for raw in signin_resp.json().get("value", []):
                    raw["_aisoc_event_kind"] = "riskySignIn"
                    events.append(raw)
            else:
                logger.warning(
                    "azure_entra.risky_signins.fetch_failed",
                    status=signin_resp.status_code,
                    body=signin_resp.text[:300],
                )

        return [self.normalize(e) for e in events]

    # ----------------------- normalize --------------------------

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        kind = raw.get("_aisoc_event_kind", "directoryAudit")

        if kind == "riskySignIn":
            risk = (raw.get("riskLevelAggregated") or "low").lower()
            severity = {
                "none": "info",
                "low": "low",
                "medium": "medium",
                "high": "high",
            }.get(risk, "medium")
            return {
                "source": self.connector_id,
                "external_id": raw.get("id", ""),
                "title": f"Risky sign-in: {raw.get('userPrincipalName', 'unknown user')}",
                "description": (
                    f"riskLevel={risk}; "
                    f"riskState={raw.get('riskState')}; "
                    f"riskEventTypes={raw.get('riskEventTypes_v2', raw.get('riskEventTypes', []))}"
                ),
                "severity": severity,
                "src_ip": raw.get("ipAddress"),
                "actor": raw.get("userDisplayName"),
                "actor_email": raw.get("userPrincipalName"),
                "event_type": "azure.entra.signin.risky",
                "raw_event": raw,
                "created_at": raw.get("createdDateTime"),
            }

        # directoryAudit
        result = (raw.get("result") or "").lower()
        category = raw.get("category", "")
        # Failed admin actions or anything in the AuthenticationMethod /
        # RoleManagement category gets bumped to medium since those are
        # the high-blast-radius levers.
        severity = "info"
        if result == "failure":
            severity = "medium"
        if category in ("RoleManagement", "AuthenticationMethod", "ConditionalAccess"):
            severity = "medium" if severity == "info" else severity
        if category == "RoleManagement" and result == "success":
            # role assignments are always worth surfacing
            severity = "high"

        initiator = raw.get("initiatedBy", {}) or {}
        user_part = initiator.get("user", {}) or {}
        app_part = initiator.get("app", {}) or {}

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": raw.get("activityDisplayName", "Entra Directory Audit"),
            "description": (f"category={category}; result={raw.get('result')}; resultReason={raw.get('resultReason', '')}"),
            "severity": severity,
            "actor": user_part.get("displayName") or app_part.get("displayName"),
            "actor_email": user_part.get("userPrincipalName"),
            "event_type": f"azure.entra.audit.{category.lower() or 'unknown'}",
            "raw_event": raw,
            "created_at": raw.get("activityDateTime"),
        }
