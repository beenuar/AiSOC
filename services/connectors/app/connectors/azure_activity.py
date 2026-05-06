"""
Azure Activity Logs connector.

Pulls subscription-level Azure Activity Log entries — the audit record of
every control-plane operation against Azure resources (creates, deletes,
RBAC changes, policy changes, etc.).

Auth model: Azure AD app registration with the **Reader** role assigned at
the subscription scope (or higher, e.g. management group). We use the
client-credentials flow against the ARM management endpoint.

API: ``/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values``
which is the documented Activity Log read API. Resource Graph would be
faster for very large estates, but the Activity Log API is the canonical
source and avoids needing the Resource Graph SDK.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_ARM_BASE = "https://management.azure.com"
_ACTIVITY_API_VERSION = "2015-04-01"

# Verbs that move the cluster — we boost severity for these so analysts
# actually see them in the queue. Everything else is informational unless
# the operation explicitly failed.
# Substrings (matched against the lower-cased operationName.value) that we
# treat as inherently high blast radius. Azure operation names follow the
# pattern ``Microsoft.<rp>/<resource>/<verb>``, e.g.
# ``Microsoft.Authorization/roleAssignments/write``, so each entry is the
# tail of the path we want to flag.
_HIGH_BLAST_RADIUS_VERBS = (
    "/delete",
    "roleassignments/write",
    "roleassignmentscheduleinstances/write",
    "policyassignments/write",
    "policydefinitions/write",
    "/deallocate",
    "/disable",
    "diagnosticsettings/delete",
)


class AzureActivityConnector(BaseConnector):
    """Azure Resource Manager Activity Logs (control-plane audit)."""

    connector_id = "azure_activity"
    connector_name = "Azure Activity Logs"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Azure subscription Activity Log — every control-plane "
                "operation (resource CRUD, RBAC changes, policy changes). "
                "Requires Reader role on the subscription."
            ),
            docs_url="/docs/connectors/azure-activity",
            fields=[
                Field("tenant_id", "string", "Tenant ID"),
                Field("client_id", "string", "Application (Client) ID"),
                Field("client_secret", "secret", "Client Secret"),
                Field(
                    "subscription_id",
                    "string",
                    "Subscription ID",
                    placeholder="00000000-0000-0000-0000-000000000000",
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes=["https://management.azure.com/user_impersonation"],
            ),
        )

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
    ):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._subscription_id = subscription_id
        self._access_token: str | None = None

    # --------------------------- auth ---------------------------

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                _TOKEN_URL.format(tenant_id=self._tenant_id),
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://management.azure.com/.default",
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
            # Confirm the subscription is actually reachable with this token
            # (catches "wrong tenant" and "no Reader role" mistakes early).
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_ARM_BASE}/subscriptions/{self._subscription_id}",
                    headers=self._headers(),
                    params={"api-version": "2020-01-01"},
                )
                resp.raise_for_status()
                sub = resp.json()
            return {
                "success": True,
                "connector": self.connector_id,
                "subscription_id": self._subscription_id,
                "subscription_name": sub.get("displayName"),
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

        # Activity log filter is OData; quote the literal datetime.
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        until = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        url = f"{_ARM_BASE}/subscriptions/{self._subscription_id}/providers/Microsoft.Insights/eventtypes/management/values"
        params = {
            "api-version": _ACTIVITY_API_VERSION,
            "$filter": (f"eventTimestamp ge '{since}' and eventTimestamp le '{until}'"),
        }

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code == 401:
                await self._authenticate()
                resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code != 200:
                logger.warning(
                    "azure_activity.fetch_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return []
            events = resp.json().get("value", [])

            # Activity log responses are paginated via ``nextLink``; we cap
            # at a few pages per poll so a single noisy subscription can't
            # starve the scheduler.
            for _ in range(4):
                next_link = resp.json().get("nextLink")
                if not next_link:
                    break
                resp = await client.get(next_link, headers=self._headers())
                if resp.status_code != 200:
                    break
                events.extend(resp.json().get("value", []))

        return [self.normalize(e) for e in events]

    # ----------------------- normalize --------------------------

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        op_name = (raw.get("operationName", {}) or {}).get("value") or ""
        status = (raw.get("status", {}) or {}).get("value") or ""
        sub_status = (raw.get("subStatus", {}) or {}).get("value") or ""
        level = (raw.get("level") or "").lower()
        caller = raw.get("caller", "")

        op_lower = op_name.lower()
        severity = "info"
        if level in ("error", "critical"):
            severity = "high"
        elif level == "warning":
            severity = "medium"
        if status.lower() == "failed":
            severity = "medium" if severity == "info" else severity
        if any(verb in op_lower for verb in _HIGH_BLAST_RADIUS_VERBS):
            severity = "high"

        resource_id = raw.get("resourceId") or ""

        return {
            "source": self.connector_id,
            "external_id": raw.get("eventDataId") or raw.get("id", ""),
            "title": op_name or "Azure Activity Log Event",
            "description": (f"status={status}; subStatus={sub_status}; resource={resource_id}"),
            "severity": severity,
            "actor": caller,
            "actor_email": caller if "@" in caller else None,
            "event_type": f"azure.activity.{op_lower or 'unknown'}",
            "resource": resource_id,
            "raw_event": raw,
            "created_at": raw.get("eventTimestamp"),
        }
