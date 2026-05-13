"""
Atlassian Confluence audit connector.

Pulls audit-trail events from Confluence Cloud via the REST API.

Two read paths:

1. **Audit records** — ``GET /wiki/rest/api/audit`` returns the legacy
   audit log shape (used by Confluence Cloud Free / Standard plans).
   Each record carries ``creationDate`` (ms), ``summary``,
   ``description``, ``author``, ``remoteAddress``, ``category``, and an
   ``affectedObject``.
2. **Permission / page events** — the same endpoint is filtered by
   ``searchString`` to focus on permission, restriction, and content
   deletion events.

Auth: Atlassian Cloud uses an email + API token pair (HTTP Basic).
The operator generates the token at
``https://id.atlassian.com/manage-profile/security/api-tokens``.

The connector is read-only — it never writes back to Confluence — and
declares ``READ_AUDIT_TRAIL`` capability so the agent layer can pivot
to it for "who deleted this page / who changed these permissions"
investigations.
"""

from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_MAX_PAGES = 20
_PAGE_SIZE = 100


class ConfluenceAuditConnector(BaseConnector):
    """Atlassian Confluence audit events."""

    connector_id = "confluence_audit"
    connector_name = "Confluence Audit"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Atlassian Confluence audit trail. Pulls page, space, and permission "
                "audit events via the Confluence Cloud REST API. Requires an "
                "Atlassian Cloud API token; the calling user needs site-admin "
                "access to read the full audit log."
            ),
            docs_url="/docs/connectors/confluence-audit",
            fields=[
                Field(
                    "site_url",
                    "string",
                    "Confluence site URL",
                    placeholder="https://yourorg.atlassian.net",
                ),
                Field("email", "string", "Account email"),
                Field(
                    "api_token",
                    "secret",
                    "API token",
                    help_text="Generate at https://id.atlassian.com/manage-profile/security/api-tokens",
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://auth.atlassian.com/authorize",
                token_url="https://auth.atlassian.com/oauth/token",
                scopes=[
                    "read:audit-log:confluence",
                    "read:user:confluence",
                    "offline_access",
                ],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_AUDIT, Capability.READ_AUDIT_TRAIL)

    def __init__(self, site_url: str, email: str, api_token: str):
        self._site_url = site_url.rstrip("/")
        self._email = email
        self._api_token = api_token

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        creds = b64encode(f"{self._email}:{self._api_token}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
            "User-Agent": "AiSOC-Connector/1.0",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # ``/wiki/rest/api/user/current`` is a cheap auth probe;
                # returns 200 + the calling user even for non-admin tokens.
                me_resp = await client.get(
                    f"{self._site_url}/wiki/rest/api/user/current",
                    headers=self._headers(),
                )
                if me_resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {me_resp.status_code}: {me_resp.text[:200]}",
                    }
                me = me_resp.json() or {}

                # Audit probe — confirms the token is actually site-admin.
                # ``403`` here means "auth is fine but you can't read the
                # audit log" and we surface that distinct from "bad creds".
                audit_resp = await client.get(
                    f"{self._site_url}/wiki/rest/api/audit",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                audit_available = audit_resp.status_code == 200
                if audit_resp.status_code not in (200, 403):
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": (f"Auth ok but audit probe failed: HTTP {audit_resp.status_code}: {audit_resp.text[:200]}"),
                    }

            return {
                "success": True,
                "connector": self.connector_id,
                "site_url": self._site_url,
                "account_id": me.get("accountId"),
                "audit_available": audit_available,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(seconds=since_seconds)
        since_ms = int(since.timestamp() * 1000)

        events = await self._paginate(since_ms=since_ms)
        return [self.normalize(e) for e in events]

    async def _paginate(self, since_ms: int) -> list[dict[str, Any]]:
        """Walk the Confluence audit endpoint.

        Audit responses look like ``{"results": [...], "start": N,
        "limit": L, "size": S, "_links": {...}}``. We page by ``start``
        offset until ``size < limit`` (the API's signal that we've hit
        the end of the window).
        """
        out: list[dict[str, Any]] = []
        start = 0
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                resp = await client.get(
                    f"{self._site_url}/wiki/rest/api/audit",
                    headers=self._headers(),
                    params={"startDate": since_ms, "limit": _PAGE_SIZE, "start": start},
                )
                if resp.status_code != 200:
                    logger.warning("confluence_audit.fetch_failed", status=resp.status_code, body=resp.text[:200])
                    break
                body = resp.json() or {}
                items = body.get("results") or []
                if not items:
                    break
                out.extend(items)
                size = int(body.get("size") or len(items))
                limit = int(body.get("limit") or _PAGE_SIZE)
                if size < limit:
                    break
                start += size
        return out

    # ----------------------- normalize --------------------------

    # ``summary`` strings that are always high-severity. These are
    # observed text fragments from the Atlassian audit-event catalogue;
    # we use ``in`` matching because Confluence prefixes with locale
    # qualifiers in some tenants ("Removed user from site permissions").
    _HIGH_RISK_SUMMARIES = (
        "Removed user from site",
        "Granted site admin",
        "Site-wide deletion",
        "Removed group from site",
        "Permissions granted to anyone",
        "Anonymous access enabled",
        "Site export started",
        "External share link created",
        "Public link enabled",
        "Bulk delete",
    )

    _MEDIUM_RISK_SUMMARIES = (
        "Restrictions updated",
        "Space permissions updated",
        "Page permissions updated",
        "Page restricted",
        "Permission changed",
        "User added to group",
        "User removed from group",
        "Group created",
        "Group deleted",
        "Space created",
        "Space deleted",
        "Global permissions updated",
    )

    def _classify(self, summary: str, category: str) -> str:
        s = summary or ""
        cat = (category or "").lower()
        # Permission / security category bumps everything to at least medium.
        category_floor = "medium" if cat in ("permissions", "security", "users and groups") else "info"

        for frag in self._HIGH_RISK_SUMMARIES:
            if frag.lower() in s.lower():
                return "high"
        for frag in self._MEDIUM_RISK_SUMMARIES:
            if frag.lower() in s.lower():
                return "medium"
        return category_floor

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        summary = raw.get("summary") or "Confluence audit event"
        category = raw.get("category") or ""
        severity = self._classify(summary, category)

        author = raw.get("author") or {}
        actor_name = author.get("displayName") if isinstance(author, dict) else None
        actor_email = author.get("username") if isinstance(author, dict) else None

        affected = raw.get("affectedObject") or {}
        affected_name = affected.get("name") if isinstance(affected, dict) else None

        # ``creationDate`` is ms-since-epoch in the audit response.
        created_iso: str | None = None
        cd = raw.get("creationDate")
        if isinstance(cd, int | float):
            created_iso = datetime.fromtimestamp(cd / 1000, tz=UTC).isoformat()
        elif isinstance(cd, str):
            created_iso = cd

        return {
            "source": self.connector_id,
            "external_id": f"confluence-audit-{raw.get('id', cd or summary)}",
            "title": f"Confluence: {summary}",
            "description": (
                f"author={actor_name or 'unknown'}; "
                f"category={category}; "
                f"affected={affected_name or 'n/a'}; "
                f"description={raw.get('description', '')}"
            )[:500],
            "severity": severity,
            "actor": actor_name,
            "actor_email": actor_email,
            "src_ip": raw.get("remoteAddress"),
            "event_type": f"confluence.{category.lower().replace(' ', '_')}" if category else "confluence.audit",
            "raw_event": raw,
            "created_at": created_iso,
        }
