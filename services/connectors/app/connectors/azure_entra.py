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

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints
from app.connectors.posture import POSTURE_SNAPSHOT_ID
from app.connectors.posture import azure as azure_posture

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Microsoft Graph caps `$top` at 1000 for these collections; 200 keeps each
# round-trip fast and rate-limit friendly while still covering normal volume.
_PAGE_SIZE = 200


def _target_fields(targets: Any) -> dict[str, Any]:
    """The first target resource of a directory-audit event, flattened.

    Graph puts the object an administrator acted on inside
    `targetResources`, a list, with the property that changed nested one
    level deeper again under `modifiedProperties`. The engine flattens
    `raw_event` exactly one level, so a rule asking "which role was granted,
    and to whom" had nothing to read.

    Only the first target is lifted. Almost every audit event has exactly
    one, and inventing `target_user_2` for the rare multi-target event would
    give rules a field they cannot rely on being present — worse than an
    honest single value, because a rule written against it would pass its
    fixture and miss the real shape.
    """
    if not isinstance(targets, list) or not targets:
        return {}
    first = targets[0]
    if not isinstance(first, dict):
        return {}
    out: dict[str, Any] = {
        "target_type": first.get("type"),
        "target_user": first.get("userPrincipalName"),
        "target_name": first.get("displayName"),
        "target_id": first.get("id"),
    }
    modified = first.get("modifiedProperties")
    if isinstance(modified, list) and modified and isinstance(modified[0], dict):
        change = modified[0]
        out["modified_property"] = change.get("displayName")
        # Graph JSON-encodes these, so `"Global Administrator"` arrives with
        # its quotes. Stripping them is what lets a rule compare against the
        # role name a reader would write.
        out["old_value"] = str(change.get("oldValue") or "").strip('"')
        out["new_value"] = str(change.get("newValue") or "").strip('"')
    return out


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

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Entra ID surfaces both directory audits and risky sign-ins.
        return (Capability.PULL_AUDIT, Capability.PULL_ALERTS)

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

    # ------------------------- posture --------------------------

    async def get_resource_config(self, resource_id: str, at_ts: str | None = None) -> dict[str, Any]:
        """Return the directory posture snapshot for the sentinel id.

        This connector models the identity plane, so the only resource it can
        describe is the directory itself. Any other id raises rather than
        returning ``{}``, because a caller asking for a resource that was
        never collectable should see that, not an empty config that reads as
        "this resource has no settings".
        """
        if resource_id != POSTURE_SNAPSHOT_ID:
            raise NotImplementedError(
                f"{self.connector_id} describes the directory, not individual resources; the only id it answers is {POSTURE_SNAPSHOT_ID!r}"
            )
        await self._authenticate()
        async with httpx.AsyncClient(timeout=30.0) as client:
            collected = await azure_posture.collect(client, self._headers(), tenant_id=self._tenant_id)
        return collected.to_resource_config()

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
            device = raw.get("deviceDetail") or {}
            location = raw.get("location") or {}
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
                # Depth 7.3 — adversary-in-the-middle session reuse. Graph's
                # `signIn` resource carries all of this and `normalize()`
                # emitted none of it, so a rule grouping by session or
                # comparing networks had nothing to read: the engine
                # flattens `raw_event` one level and `deviceDetail` arrives
                # as a dict.
                #
                # `sessionId` is read first and `correlationId` is **not** a
                # fallback for it. They mean different things: a correlation
                # id identifies one sign-in request, a session id identifies
                # the session the sign-in established. Substituting one for
                # the other would make every sign-in its own session and the
                # reuse detection could never fire, while looking like it
                # worked. Both are emitted under their own names and the
                # detection names the one it needs.
                "session_id": raw.get("sessionId"),
                "correlation_id": raw.get("correlationId"),
                "src_asn": raw.get("autonomousSystemNumber"),
                "src_country": location.get("countryOrRegion"),
                "user_agent": raw.get("userAgent"),
                "client_browser": device.get("browser"),
                "client_os": device.get("operatingSystem"),
                "client_app": raw.get("clientAppUsed"),
                "device_id": device.get("deviceId"),
                "device_compliant": device.get("isCompliant"),
                # Graph states this directly, so there is nothing to infer.
                # `None` when the field is absent, which is not the same as
                # single-factor: an older API version that does not return
                # it must not make every sign-in look unchallenged.
                "mfa_satisfied": (
                    None
                    if raw.get("authenticationRequirement") is None
                    else raw.get("authenticationRequirement") == "multiFactorAuthentication"
                ),
                "authentication_requirement": raw.get("authenticationRequirement"),
                "incoming_token_type": raw.get("incomingTokenType"),
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
            "actor": user_part.get("displayName") or app_part.get("displayName") or user_part.get("userPrincipalName"),
            "actor_email": user_part.get("userPrincipalName"),
            "src_ip": user_part.get("ipAddress"),
            "event_type": f"azure.entra.audit.{category.lower() or 'unknown'}",
            # `event_type` carries the *category*, which is far too coarse to
            # clause on: every role grant, removal and eligibility change in
            # the tenant shares `azure.entra.audit.rolemanagement`. The
            # activity is the thing a detection is about, so it is lifted
            # under its own name alongside a normalised form that survives
            # Graph's capitalisation.
            "activity": raw.get("activityDisplayName"),
            "activity_key": str(raw.get("activityDisplayName") or "").strip().lower().replace(" ", "_"),
            "operation_type": raw.get("operationType"),
            "audit_category": category,
            "audit_result": result,
            # `targetResources` is a list, and the engine flattens
            # `raw_event` one level — so the account a role was granted to,
            # and the role itself, were both invisible. A role-grant rule
            # could name the category and nothing about what was granted.
            **_target_fields(raw.get("targetResources")),
            "raw_event": raw,
            "created_at": raw.get("activityDateTime"),
        }
