"""
Microsoft 365 / Office 365 Management Activity API connector.

Pulls unified audit events covering Azure AD, Exchange, SharePoint/OneDrive,
DLP, and other "general" Microsoft 365 audit content. Reuses the same Azure
AD app registration pattern as the ``azure_*`` connectors, but talks to the
Management Activity API instead of Graph.

Auth model: Azure AD app registration with the Office 365 Management API
permission ``ActivityFeed.Read`` granted with admin consent.

Why this is more involved than Graph alerts: the Activity API doesn't have
a simple ``/alerts`` endpoint. Instead Microsoft enforces a publish/poll
pattern where you (1) ensure a subscription is started for each content type
you care about, (2) list content blobs available since a window, and (3)
fetch each blob URL to materialise the events. We cover (1) and (2) in
``test_connection`` / ``fetch_alerts``, and inline the blob fetch so the
connector contract still returns flat events.

Scope: we deliberately limit to Audit.* content types and skip DLP.All by
default. DLP can be re-enabled per-instance later via ``connector_config``
once the analyst opt-in path lands.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_BASE = "https://manage.office.com/api/v1.0/{tenant_id}/activity/feed"

# Content types we pull by default. Audit.General captures Power BI, Teams,
# Dynamics, etc.; the noisy DLP.All stream is left off to keep volumes sane.
_DEFAULT_CONTENT_TYPES = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
)


class M365AuditConnector(BaseConnector):
    """Microsoft 365 unified audit log via Office 365 Management Activity API."""

    connector_id = "m365_audit"
    connector_name = "Microsoft 365 Audit"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Microsoft 365 unified audit log (Azure AD, Exchange, "
                "SharePoint/OneDrive, Teams, Power BI) via the Office 365 "
                "Management Activity API. Requires ActivityFeed.Read on an "
                "Azure AD app registration."
            ),
            docs_url="/docs/connectors/m365-audit",
            fields=[
                Field(
                    "tenant_id",
                    "string",
                    "Tenant ID",
                    placeholder="00000000-0000-0000-0000-000000000000",
                ),
                Field("client_id", "string", "Application (Client) ID"),
                Field("client_secret", "secret", "Client Secret"),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes=["https://manage.office.com/ActivityFeed.Read"],
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
                    # Note: Management API uses a *resource* parameter rather
                    # than a Graph-style scope. Both ``/.default`` and the
                    # explicit ``resource`` form are accepted by v2.0/token,
                    # but ``resource`` is what Microsoft documents for this
                    # API and is the safer choice across tenants.
                    "scope": "https://manage.office.com/.default",
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

    def _base(self) -> str:
        return _BASE.format(tenant_id=self._tenant_id)

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            await self._authenticate()
            # Listing current subscriptions is the canonical "is the auth
            # wired up correctly" probe — it returns 200 + JSON list even
            # when zero subscriptions exist, and 403 if ActivityFeed.Read
            # admin consent is missing.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base()}/subscriptions/list",
                    headers=self._headers(),
                )
                resp.raise_for_status()
            return {
                "success": True,
                "connector": self.connector_id,
                "tenant_id": self._tenant_id,
                "active_subscriptions": [s.get("contentType") for s in resp.json() if s.get("status") == "enabled"],
            }
        except httpx.HTTPStatusError as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"HTTP {exc.response.status_code}: {exc.response.text[:300]}",
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def _ensure_subscriptions(self, client: httpx.AsyncClient) -> None:
        """Idempotently start any of our default content-type subscriptions
        that aren't already running. ``/subscriptions/start`` is a POST that
        returns 200 if the subscription was created, 400 if it was already
        active. We treat both as success.
        """
        for content_type in _DEFAULT_CONTENT_TYPES:
            try:
                resp = await client.post(
                    f"{self._base()}/subscriptions/start",
                    headers=self._headers(),
                    params={"contentType": content_type},
                )
                if resp.status_code not in (200, 400):
                    logger.warning(
                        "m365_audit.subscribe_unexpected_status",
                        content_type=content_type,
                        status=resp.status_code,
                        body=resp.text[:200],
                    )
            except httpx.RequestError as exc:
                # Don't let a transient network blip wedge fetch_alerts;
                # we'll retry on the next poll.
                logger.warning(
                    "m365_audit.subscribe_request_failed",
                    content_type=content_type,
                    error=str(exc),
                )

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        # Management API requires both startTime and endTime, and the spec
        # forbids more than 24h between them. Our default poll window is
        # well under that, but we still clamp to a sane upper bound to
        # protect against operator misconfig.
        end = datetime.now(UTC)
        start = end - timedelta(seconds=min(since_seconds, 24 * 3600))
        fmt = "%Y-%m-%dT%H:%M:%S"
        common_params = {
            "startTime": start.strftime(fmt),
            "endTime": end.strftime(fmt),
        }

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_subscriptions(client)

            # For each content type, list available content blobs in the
            # window then fetch each blob URI. The blob URIs are short-lived
            # (~24h) signed URLs hosted on the same management API.
            for content_type in _DEFAULT_CONTENT_TYPES:
                resp = await client.get(
                    f"{self._base()}/subscriptions/content",
                    headers=self._headers(),
                    params={**common_params, "contentType": content_type},
                )
                if resp.status_code == 401:
                    await self._authenticate()
                    resp = await client.get(
                        f"{self._base()}/subscriptions/content",
                        headers=self._headers(),
                        params={**common_params, "contentType": content_type},
                    )
                if resp.status_code != 200:
                    logger.warning(
                        "m365_audit.list_failed",
                        content_type=content_type,
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    continue

                blobs = resp.json()
                for blob in blobs:
                    blob_uri = blob.get("contentUri")
                    if not blob_uri:
                        continue
                    blob_resp = await client.get(blob_uri, headers=self._headers())
                    if blob_resp.status_code != 200:
                        logger.warning(
                            "m365_audit.blob_fetch_failed",
                            blob_id=blob.get("contentId"),
                            status=blob_resp.status_code,
                        )
                        continue
                    body = blob_resp.json()
                    if isinstance(body, list):
                        events.extend(body)
                    elif isinstance(body, dict):
                        # Some content types wrap the array; tolerate both.
                        events.extend(body.get("value", []))

        return [self.normalize(e) for e in events]

    # ----------------------- normalize --------------------------

    # M365 ``Operation`` names that are inherently sensitive. Matched as a
    # case-insensitive substring.
    _HIGH_RISK_OPERATIONS = (
        "AddRoleScopeMember",  # privileged role grants
        "Add member to role",
        "Add app role assignment",
        "Add service principal",
        "Set company information",
        "Update user",  # specifically catches admin-on-admin elevation
        "Update application",
        "Add owner to",
        "Disable Strong Authentication",
        "Disable account",
        "Reset user password",
        "ResetPassword",
        # SharePoint sharing escalations
        "AnonymousLinkCreated",
        "SharingInvitationCreated",
        # Mailbox forwarding rules are a textbook BEC IOC
        "New-InboxRule",
        "Set-InboxRule",
        "UpdateInboxRules",
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        operation = raw.get("Operation", "")
        result_status = (raw.get("ResultStatus") or "").lower()
        workload = raw.get("Workload", "")

        # Severity heuristic: high-risk ops → high; failed sensitive ops →
        # medium (failed brute force / failed MFA / failed admin op are
        # interesting); failed normal ops → low; everything else → info.
        op_lower = operation.lower()
        is_high_risk = any(h.lower() in op_lower for h in self._HIGH_RISK_OPERATIONS)

        if is_high_risk:
            severity = "high"
        elif result_status in ("failed", "failure") and "login" in op_lower:
            # Brute-force-like patterns warrant low rather than info because
            # downstream detections will multiply low-severity auth failures
            # to flag spray attacks.
            severity = "low"
        elif result_status in ("failed", "failure"):
            severity = "low"
        else:
            severity = "info"

        actor = raw.get("UserId") or raw.get("UserKey") or "unknown"
        user_type_int = raw.get("UserType")
        # UserType: 0=Regular, 1=Reserved, 2=Admin, 3=DcAdmin, 4=System,
        # 5=Application, 6=ServicePrincipal. Admin/DcAdmin actions get a
        # severity bump because privileged operator activity is always
        # higher-stakes than end-user noise.
        if user_type_int in (2, 3) and severity == "info":
            severity = "low"

        return {
            "source": self.connector_id,
            "external_id": raw.get("Id", ""),
            "title": operation or f"M365 {workload} event",
            "description": (f"workload={workload}; operation={operation}; result={result_status or 'success'}"),
            "severity": severity,
            "actor": actor,
            "actor_email": actor if "@" in actor else None,
            "src_ip": raw.get("ClientIP"),
            "workload": workload,
            "event_type": (f"m365.{workload.lower()}.{operation.replace(' ', '').lower()}" if workload and operation else "m365.audit"),
            "raw_event": raw,
            "created_at": raw.get("CreationTime"),
        }
