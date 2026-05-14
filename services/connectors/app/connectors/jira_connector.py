"""
Jira connector.
Fetches security-relevant issues from Jira Cloud via the REST API and,
under Workstream 8, projects AiSOC cases / status changes back into Jira.
"""

from __future__ import annotations

from base64 import b64encode
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

# Jira ships a 5-tier priority ladder (Highest / High / Medium / Low /
# Lowest). AiSOC's 5-tier severity ladder
# (info | low | medium | high | critical) lines up 1:1 with that, so
# ``Highest`` maps to ``critical`` and round-trips back to ``Highest``
# without any collapse — P1 escalations to Jira stay P1.
_PRIORITY_SEVERITY = {
    "Highest": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Lowest": "info",
}

# WS8: AiSOC severity → Jira priority. We invert ``_PRIORITY_SEVERITY``
# so the round-trip is lossless.
_SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

# WS8: AiSOC status → Jira status name. The values on the right match
# the default Jira workflow ("To Do" / "In Progress" / "Done"). Customers
# with custom workflows can override via ``connector_config.status_map``
# in the future; for now we ship the defaults so the happy path Just Works.
_STATUS_MAP_JIRA = {
    "new": "To Do",
    "triaged": "To Do",
    "investigating": "In Progress",
    "contained": "In Progress",
    "resolved": "Done",
    "closed": "Done",
}


class JiraConnector(BaseConnector):
    connector_id = "jira"
    connector_name = "Jira"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Jira Cloud issues via the REST API v3.",
            docs_url="/docs/connectors/jira",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Jira Base URL",
                    placeholder="https://yourorg.atlassian.net",
                ),
                Field("email", "string", "Email"),
                Field("api_token", "secret", "API Token"),
            ],
            # Hosted OAuth (Workstream 2): Atlassian 3LO. We map a Jira
            # Cloud site to the {site_id} placeholder by hitting the
            # accessible-resources endpoint after the token exchange.
            # Atlassian mandates PKCE + the audience=api.atlassian.com
            # parameter; the /oauth/start handler injects both.
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://auth.atlassian.com/authorize",
                token_url="https://auth.atlassian.com/oauth/token",
                scopes=[
                    "read:jira-work",
                    "read:jira-user",
                    "write:jira-work",
                    "manage:jira-webhook",
                    "offline_access",
                ],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # WS8: bidirectional ticketing landed; Jira can now mint issues
        # from AiSOC cases (PUSH_CASE) and project status transitions
        # onto them (PUSH_STATUS) in addition to pulling alerts.
        return (Capability.PULL_ALERTS, Capability.PUSH_CASE, Capability.PUSH_STATUS)

    def __init__(self, base_url: str, email: str, api_token: str, project_key: str | None = None):
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._api_token = api_token
        # ``project_key`` is required for ``push_case`` (Jira REST won't
        # accept an issue without one) but optional for the read path
        # because pull-alerts works across all projects the user can
        # see. We accept it lazily and only enforce it where it matters.
        self._project_key = (project_key or "").strip() or None

    def _auth_header(self) -> dict[str, str]:
        creds = b64encode(f"{self._email}:{self._api_token}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/rest/api/3/myself",
                    headers=self._auth_header(),
                )
                resp.raise_for_status()
                user = resp.json()
            return {
                "success": True,
                "connector": self.connector_id,
                "user": user.get("displayName"),
            }
        except Exception as exc:
            logger.warning("jira.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        minutes_ago = max(since_seconds // 60, 1)
        jql = f"updated >= -{minutes_ago}m ORDER BY updated DESC"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self._base_url}/rest/api/3/search",
                headers=self._auth_header(),
                params={
                    "jql": jql,
                    "maxResults": 100,
                    "fields": "summary,description,priority,status,creator,created,updated",
                },
            )
            resp.raise_for_status()
            issues = resp.json().get("issues", [])

        return [self.normalize(i) for i in issues]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        fields = raw.get("fields", {})
        priority_name = (fields.get("priority") or {}).get("name", "Medium")
        creator = fields.get("creator") or {}
        description_body = fields.get("description")
        if isinstance(description_body, dict):
            description_body = description_body.get("text", str(description_body))

        return {
            "source": self.connector_id,
            "external_id": raw.get("key", raw.get("id", "")),
            "title": fields.get("summary", "Jira Issue"),
            "description": str(description_body or "")[:500],
            "severity": _PRIORITY_SEVERITY.get(priority_name, "medium"),
            "src_ip": None,
            "hostname": None,
            "actor": creator.get("displayName") or creator.get("emailAddress"),
            "raw_event": raw,
            "created_at": fields.get("created"),
        }

    # ------------------------------------------------------------------
    # WS8: bidirectional ticket sync.
    # ------------------------------------------------------------------
    #
    # Jira's REST API is well-documented but has a few gotchas the
    # implementation defends against:
    #
    #   1. ``description`` MUST be in the Atlassian Document Format
    #      (ADF) on issue create — passing a raw string returns 400.
    #      We wrap whatever the case has in a minimal ADF doc.
    #   2. Transitions (status changes) are NOT field writes. You have
    #      to ask Jira ``GET /issue/{key}/transitions`` to discover the
    #      transition ID for the target status, then POST it. We resolve
    #      that on each call rather than caching, because customers add
    #      transitions to their workflows all the time.
    #   3. Issue keys (``ABC-123``) are stable identifiers we persist;
    #      the ``id`` field is an opaque numeric ID we do NOT use.

    @staticmethod
    def _adf_text(text: str) -> dict[str, Any]:
        """Wrap plain text into a minimal Atlassian Document Format doc."""
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {"type": "paragraph", "content": [{"type": "text", "text": text or ""}]},
            ],
        }

    def _issue_url(self, key: str) -> str:
        """Best-effort browser URL for a Jira issue key."""
        return f"{self._base_url}/browse/{key}"

    async def push_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Mint a Jira issue from an AiSOC case."""
        if not self._project_key:
            raise ValueError("jira.push_case: project_key not configured on connector instance")

        severity = (case.get("severity") or "medium").lower()
        title = case.get("title") or f"AiSOC case {case.get('case_number') or case.get('id')}"
        description = case.get("description") or ""
        case_id = case.get("id") or case.get("case_number")

        payload = {
            "fields": {
                "project": {"key": self._project_key},
                "summary": title[:255],  # Jira summary cap.
                "description": self._adf_text(description),
                "issuetype": {"name": "Task"},
                "priority": {"name": _SEVERITY_TO_PRIORITY.get(severity, "Medium")},
                # ``labels`` is the cheapest way to round-trip the AiSOC
                # case identifier without requiring a custom field. The
                # inbound webhook can then strip the prefix to find us.
                "labels": [f"aisoc-case-{case_id}", "aisoc"],
            }
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/rest/api/3/issue",
                headers=self._auth_header(),
                json=payload,
            )
            if resp.status_code >= 400:
                raise httpx.HTTPStatusError(
                    f"jira.push_case failed: {resp.status_code} {resp.text[:300]}",
                    request=resp.request,
                    response=resp,
                )
            data = resp.json()

        key = data.get("key")
        return {
            "external_id": key,
            "external_url": self._issue_url(key) if key else None,
            "vendor": self.connector_id,
            "external_status": "To Do",
        }

    async def _resolve_transition_id(
        self,
        client: httpx.AsyncClient,
        issue_key: str,
        target_name: str,
    ) -> str | None:
        """Look up the transition ID whose target status matches ``target_name``.

        Returns ``None`` if Jira's workflow doesn't expose a transition
        to that status — the caller MUST treat that as a no-op rather
        than retrying, because no amount of retrying will change the
        workflow.
        """
        resp = await client.get(
            f"{self._base_url}/rest/api/3/issue/{issue_key}/transitions",
            headers=self._auth_header(),
        )
        resp.raise_for_status()
        transitions = resp.json().get("transitions", [])
        target_lower = target_name.lower()
        for t in transitions:
            # Match on either the transition name ("Done") or the target
            # status name (``to.name``); customers rename one but not the
            # other surprisingly often.
            t_name = (t.get("name") or "").lower()
            to_name = ((t.get("to") or {}).get("name") or "").lower()
            if t_name == target_lower or to_name == target_lower:
                return t.get("id")
        return None

    async def push_status_change(
        self,
        case: dict[str, Any],
        old_status: str,
        new_status: str,
        external_ref: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Project an AiSOC status transition onto a Jira issue."""
        if external_ref is None:
            # First-time push: fall through to ``push_case`` so the
            # caller doesn't have to special-case "no link yet".
            return await self.push_case(case)

        issue_key = (external_ref or {}).get("external_id")
        if not issue_key:
            raise ValueError("jira.push_status_change: external_ref missing external_id")

        target_name = _STATUS_MAP_JIRA.get(new_status, "")
        if not target_name:
            # Unknown AiSOC status → no-op rather than throwing, since
            # the contract is "best effort projection" not "schema match".
            logger.info(
                "jira.push_status_change.no_mapping",
                external_id=issue_key,
                old=old_status,
                new=new_status,
            )
            return {
                "external_id": issue_key,
                "external_url": self._issue_url(issue_key),
                "vendor": self.connector_id,
                "external_status": (external_ref or {}).get("external_status"),
            }

        async with httpx.AsyncClient(timeout=30.0) as client:
            transition_id = await self._resolve_transition_id(client, issue_key, target_name)
            if transition_id is None:
                logger.warning(
                    "jira.push_status_change.no_transition",
                    external_id=issue_key,
                    target=target_name,
                )
                return {
                    "external_id": issue_key,
                    "external_url": self._issue_url(issue_key),
                    "vendor": self.connector_id,
                    "external_status": (external_ref or {}).get("external_status"),
                }

            resp = await client.post(
                f"{self._base_url}/rest/api/3/issue/{issue_key}/transitions",
                headers=self._auth_header(),
                json={"transition": {"id": transition_id}},
            )
            if resp.status_code >= 400:
                raise httpx.HTTPStatusError(
                    f"jira.push_status_change failed: {resp.status_code} {resp.text[:300]}",
                    request=resp.request,
                    response=resp,
                )

        return {
            "external_id": issue_key,
            "external_url": self._issue_url(issue_key),
            "vendor": self.connector_id,
            "external_status": target_name,
        }
