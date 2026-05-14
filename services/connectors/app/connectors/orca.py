"""
Orca Security connector.

Pulls open security alerts from an Orca Security tenant via the public
REST API. Like the other CNAPP integrations in this release, one Orca
connector instance covers every Orca surface — workload, container,
cloud configuration, identity, and data risks — because the
``/api/alerts`` endpoint is unified across products.

Auth model:
    Long-lived API token, sent as ``Authorization: Token <token>``.
    Tokens are minted in the Orca console under
    Settings → Users & Permissions → API Tokens.

Severity mapping:
    Orca uses a 5-tier ladder (``hazardous, critical, high, medium,
    informational``). AiSOC also exposes 5 tiers (``critical, high,
    medium, low, info``). Both ``hazardous`` (Orca's "actively exploited /
    active threat" band) and ``critical`` map into AiSOC ``critical`` so
    P1 cloud findings keep their original priority. The original Orca
    tier is preserved on ``raw_event.state.severity``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_DEFAULT_API_URL = "https://api.orcasecurity.io"

# Orca's 5-tier ladder mapped into AiSOC's 5-tier canonical set.
# ``hazardous`` is Orca-internal terminology for "actively exploited /
# active threat" and is the most severe band — escalate it to AiSOC
# ``critical`` so the SOC P1 SLA fires. ``critical`` stays ``critical``.
_SEVERITY_MAP: dict[str, str] = {
    "hazardous": "critical",
    "imminent_compromise": "critical",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


class OrcaConnector(BaseConnector):
    """Orca Security cloud-native application protection platform."""

    connector_id = "orca"
    connector_name = "Orca Security"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Orca Security CNAPP. Pulls open alerts across workload, "
                "container, cloud configuration, identity, and data risk "
                "surfaces from the unified /api/alerts REST endpoint."
            ),
            docs_url="/docs/connectors/orca",
            fields=[
                Field("api_token", "secret", "API Token"),
                Field(
                    "api_url",
                    "string",
                    "API URL",
                    required=False,
                    default=_DEFAULT_API_URL,
                    placeholder=_DEFAULT_API_URL,
                    help_text=(
                        "Override only if your tenant lives on a region-specific "
                        "Orca endpoint. The default works for the standard "
                        "commercial cloud."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(self, api_token: str, api_url: str | None = None):
        self._api_token = api_token
        self._api_url = (api_url or _DEFAULT_API_URL).rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self._api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Orca's ``/api/user/session`` returns the auth-context
                # for the calling token. It's the cheapest auth-only call
                # and surfaces both bad-token and revoked-token cases
                # cleanly.
                resp = await client.get(
                    f"{self._api_url}/api/user/session",
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "api_url": self._api_url,
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"orca auth failed: HTTP {resp.status_code}",
                }
        except Exception as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": str(exc),
            }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        end = datetime.now(UTC)
        start = end - timedelta(seconds=since_seconds)
        # Orca's /api/alerts accepts an ISO-8601 ``start_at_gte`` to
        # limit results to alerts opened since the cursor. ``status``
        # filter keeps the volume sane by only returning open alerts.
        params = {
            "start_at_gte": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "open",
            "limit": 200,
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._api_url}/api/alerts",
                    headers=self._headers(),
                    params=params,
                )
                if resp.status_code != 200:
                    logger.warning(
                        "orca.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                payload = resp.json() or {}
        except Exception as exc:
            logger.warning("orca.fetch_exception", error=str(exc))
            return []

        # Orca has shipped both ``{"data": [...]}`` and
        # ``{"results": [...]}`` envelopes across product versions.
        # Accept both plus the bare-list fallback.
        items: list[dict[str, Any]]
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = payload.get("data") or payload.get("results") or payload.get("alerts") or []
        else:
            items = []

        return [self.normalize(i) for i in items]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        state = raw.get("state") or {}
        asset = raw.get("asset") or raw.get("source_asset") or {}
        cloud_account = raw.get("cloud_account") or {}

        sev_raw = (state.get("severity") or raw.get("severity") or raw.get("priority") or "medium").lower()
        severity = _SEVERITY_MAP.get(sev_raw, "medium")

        return {
            "source": self.connector_id,
            "category": "cloud",
            "external_id": raw.get("alert_id") or raw.get("id"),
            "title": raw.get("description") or raw.get("rule_name") or "Orca alert",
            "description": raw.get("recommendation") or raw.get("description") or "",
            "severity": severity,
            "hostname": asset.get("name") or asset.get("asset_name"),
            "cloud_resource": asset.get("vendor_id") or asset.get("asset_unique_id"),
            "cloud_platform": asset.get("vendor") or cloud_account.get("vendor") or raw.get("cloud_provider"),
            "cloud_region": asset.get("region") or asset.get("cloud_region"),
            "rule_name": raw.get("rule_name") or raw.get("type"),
            "raw_event": raw,
            "created_at": raw.get("created_at") or raw.get("source_event_time"),
        }
