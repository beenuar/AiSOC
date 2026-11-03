"""
Cisco Umbrella (Reporting v2) connector.

Cisco Umbrella exposes a Reporting v2 API at
https://api.umbrella.com/reports/v2. Auth is OAuth 2.0 client
credentials issued from a "Umbrella Management" key in the dashboard.
The connector pulls activity events (DNS + proxy), with severity
inferred from the verdict.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_PER_PAGE = 100
# Bound on pages per poll so an endpoint that never returns a short page
# cannot loop forever.
_MAX_PAGES = 50


class CiscoUmbrellaConnector(BaseConnector):
    """Cisco Umbrella DNS + proxy reporting."""

    connector_id = "cisco_umbrella"
    connector_name = "Cisco Umbrella"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=("Cisco Umbrella DNS + secure web gateway activity. Surfaces blocked domains, malware verdicts, and proxy events."),
            docs_url="/docs/connectors/cisco_umbrella",
            fields=[
                Field("api_key", "secret", "Umbrella Management API Key"),
                Field("api_secret", "secret", "Umbrella Management API Secret"),
                Field(
                    "org_id",
                    "string",
                    "Organization ID",
                    required=False,
                    help_text="Optional. If omitted, the token's default org is used.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.PIVOT_DOMAIN,
            Capability.PIVOT_IP,
            Capability.ENRICH_DOMAIN,
        )

    AUTH_URL = "https://api.umbrella.com/auth/v2/token"
    BASE_URL = "https://api.umbrella.com/reports/v2"

    def __init__(self, api_key: str, api_secret: str, org_id: str | None = None):
        self._key = api_key
        self._secret = api_secret
        self._org = org_id
        self._token: str | None = None
        self._token_expiry = 0.0

    async def _bearer(self) -> str | None:
        if self._token and time.time() < self._token_expiry - 30:
            return self._token
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    self.AUTH_URL,
                    auth=(self._key, self._secret),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={"grant_type": "client_credentials"},
                )
                if resp.status_code != 200:
                    logger.warning(
                        "umbrella.token_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return None
                payload = resp.json() or {}
                self._token = payload.get("access_token")
                self._token_expiry = time.time() + int(payload.get("expires_in", 3600))
                return self._token
        except Exception as exc:
            logger.warning("umbrella.token_exception", error=str(exc))
            return None

    async def test_connection(self) -> dict[str, Any]:
        token = await self._bearer()
        if not token:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "could not exchange API key/secret for token",
            }
        return {"success": True, "connector": self.connector_id}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        token = await self._bearer()
        if not token:
            return []
        from_ts = int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp() * 1000)
        to_ts = int(datetime.now(UTC).timestamp() * 1000)
        params: dict[str, Any] = {
            "from": from_ts,
            "to": to_ts,
            "limit": _PER_PAGE,
            "verdict": "blocked",
        }
        items: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # /activity is offset-paginated. Reading only the first page
                # dropped every blocked request past the 100th in a poll
                # window, and the next poll's window starts later, so those
                # requests were never read.
                for page in range(_MAX_PAGES):
                    params["offset"] = page * _PER_PAGE
                    resp = await client.get(
                        f"{self.BASE_URL}/activity",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/json",
                        },
                        params=params,
                    )
                    if resp.status_code != 200:
                        logger.warning(
                            "umbrella.fetch_failed",
                            status=resp.status_code,
                            body=resp.text[:300],
                        )
                        if not items:
                            return []
                        break
                    data = resp.json() or {}
                    batch = data.get("data") or data.get("activity") or []
                    items.extend(batch)
                    if len(batch) < _PER_PAGE:
                        break
                else:
                    logger.warning("umbrella.fetch_page_cap_reached", pages=_MAX_PAGES, events=len(items))
        except Exception as exc:
            logger.warning("umbrella.fetch_exception", error=str(exc))
            return []
        return [self.normalize(i) for i in items]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        verdict = (raw.get("verdict") or "").lower()
        sev = "high" if verdict == "blocked" else "info"
        domain = raw.get("domain") or raw.get("url")
        return {
            "source": "cisco_umbrella",
            "category": "network",
            "severity": sev,
            "title": f"Umbrella {verdict or 'event'}: {domain}",
            "description": raw.get("threats") or raw.get("categories"),
            "alert_id": str(raw.get("id") or raw.get("timestamp") or ""),
            "host": raw.get("internalIp") or raw.get("device") or None,
            "raw_event": raw,
        }
