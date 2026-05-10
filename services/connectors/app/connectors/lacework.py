"""
Lacework cloud security platform connector.

Lacework's API uses an account-scoped subdomain plus an Access Key ID +
Secret. Auth is OAuth-style: POST to /api/v2/access/tokens with the
credentials, then bearer the returned token. The schema captures only
the long-lived credentials; runtime exchanges them for short-lived
bearer tokens.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class LaceworkConnector(BaseConnector):
    """Lacework cloud security."""

    connector_id = "lacework"
    connector_name = "Lacework"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=("Lacework cloud security platform. Pulls alerts (events) and supports compliance / configuration query."),
            docs_url="/docs/connectors/lacework",
            fields=[
                Field(
                    "account",
                    "string",
                    "Account subdomain",
                    placeholder="yourcorp",
                    help_text=("First label of your Lacework console URL: https://<account>.lacework.net"),
                ),
                Field(
                    "subaccount",
                    "string",
                    "Subaccount (optional)",
                    placeholder="prod",
                    required=False,
                ),
                Field("key_id", "string", "Access Key ID"),
                Field("secret", "secret", "Secret Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.PIVOT_HOST,
            Capability.PIVOT_IP,
            Capability.ENRICH_VULN,
        )

    def __init__(
        self,
        account: str,
        key_id: str,
        secret: str,
        subaccount: str | None = None,
    ):
        self._account = account
        self._sub = subaccount
        self._key_id = key_id
        self._secret = secret
        self._base = f"https://{account}.lacework.net"

    async def _bearer(self) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._base}/api/v2/access/tokens",
                    headers={
                        "X-LW-UAKS": self._secret,
                        "Content-Type": "application/json",
                    },
                    json={"keyId": self._key_id, "expiryTime": 3600},
                )
                if resp.status_code == 201:
                    return (resp.json() or {}).get("token")
                logger.warning(
                    "lacework.token_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return None
        except Exception as exc:
            logger.warning("lacework.token_exception", error=str(exc))
            return None

    def _headers(self, token: str) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._sub:
            h["Account-Name"] = self._sub
        return h

    async def test_connection(self) -> dict[str, Any]:
        token = await self._bearer()
        if not token:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "could not exchange access keys for bearer token",
            }
        return {
            "success": True,
            "connector": self.connector_id,
            "account": self._account,
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        token = await self._bearer()
        if not token:
            return []
        end = datetime.now(UTC)
        start = end - timedelta(seconds=since_seconds)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/api/v2/Alerts",
                    headers=self._headers(token),
                    params={
                        "startTime": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "endTime": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "lacework.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("data") or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("lacework.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        sev_raw = (raw.get("severity") or "").lower()
        if sev_raw in ("critical",):
            sev = "high"
        elif sev_raw in ("info", "low", "medium", "high"):
            sev = sev_raw
        else:
            sev = "medium"
        return {
            "source": "lacework",
            "category": "cloud",
            "severity": sev,
            "title": raw.get("alertName") or raw.get("name") or "Lacework alert",
            "description": raw.get("alertInfo", {}).get("description") if isinstance(raw.get("alertInfo"), dict) else None,
            "alert_id": raw.get("alertId") or raw.get("id"),
            "host": None,
            "raw": raw,
        }
