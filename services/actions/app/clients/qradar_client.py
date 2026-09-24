"""IBM QRadar REST client — offense lifecycle writeback.

Scope is deliberately narrow: AiSOC needs to close an offense it judged
benign, and to annotate plus keep open one it confirmed. Everything else
QRadar can do stays out of this client.

Credentials expected in ``ActionRequest.parameters``:
    qradar_url: str          e.g. "https://qradar.corp.example.com"
    qradar_token: str        an authorised service token (``SEC`` header)
    qradar_verify_ssl: bool  default True

TLS verification defaults on. QRadar consoles are frequently fronted by an
internal CA, so an operator can opt out per instance — an explicit opt-in to
a weaker posture, never the default.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

#: QRadar rejects an unversioned request on recent appliances, and the version
#: it negotiates changes what the offense payload looks like. Pinned so a
#: console upgrade cannot silently change the response shape underneath us.
API_VERSION = "12.0"


class QRadarClient:
    """Async client for the QRadar offense API."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        verify_ssl: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = api_token
        self._verify_ssl = verify_ssl
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {
            "SEC": self._token,
            "Version": API_VERSION,
            "Accept": "application/json",
        }

    async def _post(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify_ssl) as client:
            response = await client.post(f"{self._base}{path}", headers=self._headers(), params=params)
            response.raise_for_status()
            return response.json() if response.content else {}

    async def get_offense(self, offense_id: str) -> dict[str, Any]:
        """Read one offense. Used as the writeback verification probe."""
        async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify_ssl) as client:
            response = await client.get(
                f"{self._base}/api/siem/offenses/{offense_id}",
                headers=self._headers(),
                params={"fields": "id,status,assigned_to,closing_reason_id"},
            )
            response.raise_for_status()
            return response.json() if response.content else {}

    async def add_note(self, offense_id: str, note_text: str) -> dict[str, Any]:
        """Attach a note to an offense.

        Notes are append-only in QRadar, which is what makes them the right
        place for an AiSOC verdict: the analyst's own notes are never
        overwritten and the platform's reasoning is timestamped alongside them.
        """
        body = await self._post(f"/api/siem/offenses/{offense_id}/notes", {"note_text": note_text[:2000]})
        logger.info("qradar.offense.note_added", offense_id=offense_id)
        return {"success": True, "action": "add_note", "offense_id": offense_id, "response": body}

    async def close_offense(
        self,
        offense_id: str,
        *,
        closing_reason_id: int,
        note_text: str | None = None,
    ) -> dict[str, Any]:
        """Close an offense.

        ``closing_reason_id`` is mandatory on the QRadar side and is
        deployment-specific — the console ships three defaults and most SOCs
        add their own, so there is no id this client could safely assume. The
        caller supplies it from connector configuration.
        """
        if note_text:
            await self.add_note(offense_id, note_text)
        body = await self._post(
            f"/api/siem/offenses/{offense_id}",
            {"status": "CLOSED", "closing_reason_id": int(closing_reason_id)},
        )
        logger.info("qradar.offense.closed", offense_id=offense_id, closing_reason_id=closing_reason_id)
        return {
            "success": True,
            "action": "close_offense",
            "offense_id": offense_id,
            "closing_reason_id": closing_reason_id,
            "response": body,
        }

    async def escalate_offense(
        self,
        offense_id: str,
        *,
        note_text: str,
        assigned_to: str | None = None,
    ) -> dict[str, Any]:
        """Annotate an offense and hand it to an owner, leaving it OPEN.

        No status change: an offense AiSOC confirmed is one a human has to
        look at, and QRadar has no state between OPEN and CLOSED that would
        mean anything more than the note already does.
        """
        await self.add_note(offense_id, note_text)
        params: dict[str, Any] = {"status": "OPEN"}
        if assigned_to:
            params["assigned_to"] = assigned_to
        body = await self._post(f"/api/siem/offenses/{offense_id}", params)
        logger.info("qradar.offense.escalated", offense_id=offense_id, assigned_to=assigned_to)
        return {
            "success": True,
            "action": "escalate_offense",
            "offense_id": offense_id,
            "assigned_to": assigned_to,
            "response": body,
        }
