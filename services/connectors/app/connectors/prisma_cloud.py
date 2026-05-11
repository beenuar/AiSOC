"""
Prisma Cloud (Palo Alto Networks) connector.

Pulls open security alerts from a Prisma Cloud tenant via the v1 REST API.
A single connector instance covers every Prisma Cloud surface — CSPM, CWPP,
CIEM, DSPM — because the ``/alert/v1/alert`` endpoint aggregates findings
across all of them.

Auth model:
    POST /login with ``username`` (= access key ID) and ``password`` (=
    secret) returns a short-lived JWT in ``token``. We exchange on every
    poll because Prisma Cloud tokens have a sliding TTL and re-auth is
    cheap; this avoids cache-invalidation bugs around expiry windows.

The optional ``compute_url`` field stays in the schema for forward
compatibility with the Compute (Twistlock) API, but the v7.1.0 release
only consumes the unified ``/alert`` surface — which already includes
runtime findings collapsed in from Compute.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Prisma Cloud uses a 4-tier severity ladder; map directly into AiSOC's
# canonical 4-tier set. ``critical`` collapses into ``high`` because AiSOC
# does not expose a separate critical band — playbooks that need the
# original tier can read it back from ``raw_event.severity``.
_SEVERITY_MAP: dict[str, str] = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


class PrismaCloudConnector(BaseConnector):
    """Prisma Cloud cloud security platform."""

    connector_id = "prisma_cloud"
    connector_name = "Prisma Cloud"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Prisma Cloud cloud security platform. Pulls open alerts across CSPM, CWPP, CIEM, and DSPM surfaces via the v1 REST API."
            ),
            docs_url="/docs/connectors/prisma-cloud",
            fields=[
                Field(
                    "api_url",
                    "string",
                    "API URL",
                    placeholder="https://api.prismacloud.io",
                    help_text=(
                        "Region-specific base URL of the Prisma Cloud REST API. "
                        "See Prisma Cloud → System → API Endpoints for the value "
                        "for your tenant (e.g. ``api2.eu``, ``api.gov``)."
                    ),
                ),
                Field("access_key_id", "string", "Access Key ID"),
                Field("secret_key", "secret", "Secret Key"),
                Field(
                    "compute_url",
                    "string",
                    "Compute API URL (optional)",
                    required=False,
                    placeholder="https://us-east1.cloud.twistlock.com/<tenant-id>",
                    help_text=(
                        "Tenant-specific Compute (Twistlock) API base URL. "
                        "Leave blank — v7.1.0 only consumes the unified "
                        "``/alert`` endpoint."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        api_url: str,
        access_key_id: str,
        secret_key: str,
        compute_url: str | None = None,
    ):
        self._api_url = api_url.rstrip("/")
        self._access_key_id = access_key_id
        self._secret_key = secret_key
        self._compute_url = (compute_url or "").rstrip("/") or None
        self._token: str | None = None

    async def _login(self) -> str | None:
        """Exchange access key ID + secret for a short-lived JWT.

        Returns the bearer string on success, or ``None`` on any failure
        (network, 4xx, malformed body). We log the failure but do not
        raise so the polling loop can degrade gracefully.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._api_url}/login",
                    headers={
                        "Accept": "application/json; charset=UTF-8",
                        "Content-Type": "application/json",
                    },
                    json={
                        "username": self._access_key_id,
                        "password": self._secret_key,
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "prisma_cloud.login_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return None
                token = (resp.json() or {}).get("token")
                if not token:
                    logger.warning("prisma_cloud.login_no_token")
                    return None
                self._token = token
                return token
        except Exception as exc:
            logger.warning("prisma_cloud.login_exception", error=str(exc))
            return None

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json; charset=UTF-8",
            "Content-Type": "application/json",
            "x-redlock-auth": self._token or "",
        }

    async def test_connection(self) -> dict[str, Any]:
        token = await self._login()
        if not token:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "could not exchange access keys for prisma cloud JWT",
            }
        return {
            "success": True,
            "connector": self.connector_id,
            "api_url": self._api_url,
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        token = await self._login()
        if not token:
            return []

        end = datetime.now(UTC)
        start = end - timedelta(seconds=since_seconds)

        # The Prisma Cloud /alert endpoint expects epoch milliseconds for
        # the time range filter when ``timeRange.type == "absolute"``.
        body = {
            "timeRange": {
                "type": "absolute",
                "value": {
                    "startTime": int(start.timestamp() * 1000),
                    "endTime": int(end.timestamp() * 1000),
                },
            },
            "filters": [
                {"name": "alert.status", "operator": "=", "value": "open"},
            ],
            "sortBy": ["alertTime:desc"],
            "limit": 200,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self._api_url}/alert/v1/alert",
                    headers=self._headers(),
                    json=body,
                )
                if resp.status_code != 200:
                    logger.warning(
                        "prisma_cloud.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                payload = resp.json() or {}
        except Exception as exc:
            logger.warning("prisma_cloud.fetch_exception", error=str(exc))
            return []

        # The /alert/v1/alert endpoint returns either a bare list or
        # ``{"items": [...]}`` depending on tenant region. Handle both
        # so a region rollover doesn't break the connector silently.
        items: list[dict[str, Any]]
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = payload.get("items") or payload.get("alerts") or []
        else:
            items = []

        return [self.normalize(i) for i in items]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        policy = raw.get("policy") or {}
        resource = raw.get("resource") or {}

        sev_raw = (policy.get("severity") or raw.get("severity") or "medium").lower()
        severity = _SEVERITY_MAP.get(sev_raw, "medium")

        # Prisma Cloud emits ``alertTime`` in epoch milliseconds; AiSOC
        # downstream code expects ISO-8601 strings. Convert defensively
        # because some legacy payloads ship ISO already.
        created_at = raw.get("alertTime") or raw.get("firstSeen")
        if isinstance(created_at, int | float):
            created_at = datetime.fromtimestamp(created_at / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "source": self.connector_id,
            "category": "cloud",
            "external_id": raw.get("id") or raw.get("alertId"),
            "title": policy.get("name") or raw.get("name") or "Prisma Cloud alert",
            "description": policy.get("description") or raw.get("description") or "",
            "severity": severity,
            "hostname": resource.get("name"),
            "cloud_resource": resource.get("rrn") or resource.get("id"),
            "cloud_platform": resource.get("cloudType"),
            "cloud_region": resource.get("regionId") or resource.get("region"),
            "rule_name": policy.get("name"),
            "raw_event": raw,
            "created_at": created_at,
        }
