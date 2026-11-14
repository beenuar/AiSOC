"""
Jira Cloud client for the action layer.

Mirrors the wire-shape of :class:`services.connectors.app.connectors.jira_connector.JiraConnector`
but lives inside the actions service (separate Python package, so
we cannot import across service boundaries — each service ships
its own container).

The verbs we cover:

* :meth:`create_issue`     — POST ``/rest/api/3/issue``; minimal
                              ADF description; AiSOC case ID is
                              round-tripped in a ``labels`` entry
                              so the inbound webhook can find us.
* :meth:`add_comment`      — POST ``/rest/api/3/issue/{key}/comment``;
                              also ADF-encoded.
* :meth:`transition_issue` — resolve the transition ID from
                              ``/transitions`` first, then POST it.
                              Custom workflows are common so we
                              do not cache.
"""

from __future__ import annotations

from base64 import b64encode
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


# AiSOC severity → Jira priority. The Jira spec ladder is
# Highest / High / Medium / Low / Lowest, which maps 1:1 to our
# critical / high / medium / low / info ladder. Keeping it lossless
# means the round trip back via the connector is the identity.
_SEVERITY_TO_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


def _adf_text(text: str) -> dict[str, Any]:
    """Wrap plain text into a minimal Atlassian Document Format doc.

    Jira refuses raw strings in the description / comment body since
    v3 of the REST API. ADF v1 is the bare-minimum envelope that
    actually serializes round-trip with the editor — keep it
    simple, do not embed mention/link nodes here.
    """
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": text or ""}]},
        ],
    }


class JiraError(RuntimeError):
    """Raised when Jira returns a non-2xx that the caller can't recover from."""


class JiraClient:
    """Async wrapper for Jira Cloud REST API v3."""

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._api_token = api_token
        self._project_key = (project_key or "").strip() or None

    def _auth_header(self) -> dict[str, str]:
        creds = b64encode(f"{self._email}:{self._api_token}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _issue_url(self, key: str) -> str:
        return f"{self._base_url}/browse/{key}"

    async def create_issue(
        self,
        *,
        summary: str,
        description: str,
        severity: str = "medium",
        case_id: str | None = None,
        issue_type: str = "Task",
        project_key: str | None = None,
    ) -> dict[str, Any]:
        project = project_key or self._project_key
        if not project:
            raise ValueError("jira.create_issue: project_key is required")

        priority = _SEVERITY_TO_PRIORITY.get(severity.lower(), "Medium")
        labels = ["aisoc"]
        if case_id:
            labels.insert(0, f"aisoc-case-{case_id}")

        payload = {
            "fields": {
                "project": {"key": project},
                "summary": summary[:255],
                "description": _adf_text(description),
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
                "labels": labels,
            }
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/rest/api/3/issue",
                headers=self._auth_header(),
                json=payload,
            )
            if resp.status_code >= 400:
                raise JiraError(f"jira.create_issue failed: {resp.status_code} {resp.text[:300]}")
            data = resp.json()

        key = data.get("key")
        logger.info("jira.create_issue.success", key=key, project=project)
        return {
            "external_id": key,
            "external_url": self._issue_url(key) if key else None,
            "vendor": "jira",
        }

    async def add_comment(self, issue_key: str, comment: str) -> dict[str, Any]:
        payload = {"body": _adf_text(comment)}
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/rest/api/3/issue/{issue_key}/comment",
                headers=self._auth_header(),
                json=payload,
            )
            if resp.status_code >= 400:
                raise JiraError(f"jira.add_comment failed: {resp.status_code} {resp.text[:300]}")
        logger.info("jira.add_comment.success", issue=issue_key)
        return {"issue_key": issue_key, "commented": True}

    async def _resolve_transition_id(
        self,
        client: httpx.AsyncClient,
        issue_key: str,
        target_name: str,
    ) -> str | None:
        resp = await client.get(
            f"{self._base_url}/rest/api/3/issue/{issue_key}/transitions",
            headers=self._auth_header(),
        )
        resp.raise_for_status()
        transitions = resp.json().get("transitions", [])
        target_lower = target_name.lower()
        for t in transitions:
            # Match on either transition name or destination status
            # name — customers rename one but not the other often
            # enough to bite us in prod.
            t_name = (t.get("name") or "").lower()
            to_name = ((t.get("to") or {}).get("name") or "").lower()
            if t_name == target_lower or to_name == target_lower:
                return t.get("id")
        return None

    async def transition_issue(self, issue_key: str, target_status: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            tid = await self._resolve_transition_id(client, issue_key, target_status)
            if tid is None:
                logger.warning("jira.transition_issue.no_transition", issue=issue_key, target=target_status)
                return {"issue_key": issue_key, "transitioned": False, "reason": "no_transition"}

            resp = await client.post(
                f"{self._base_url}/rest/api/3/issue/{issue_key}/transitions",
                headers=self._auth_header(),
                json={"transition": {"id": tid}},
            )
            if resp.status_code >= 400:
                raise JiraError(f"jira.transition_issue failed: {resp.status_code} {resp.text[:300]}")
        logger.info("jira.transition_issue.success", issue=issue_key, target=target_status)
        return {"issue_key": issue_key, "transitioned": True, "target": target_status}
