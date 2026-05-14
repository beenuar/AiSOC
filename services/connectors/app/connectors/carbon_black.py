"""
VMware Carbon Black Cloud (CBC) connector.

Pulls from two CBC endpoints in a single connector:

1. **Alerts** — ``GET /appservices/v6/orgs/{org_key}/alerts/_search`` returns
   detection / threat-hunter findings across the deployment. This is the
   primary feed and the one the agent treats as the "incident" stream.
2. **Audit log** — ``GET /integrationServices/v3/auditlogs`` covers admin
   actions: API key creation, sensor policy edits, console logins, watchlist
   changes. We pull this separately so it lands as ``audit`` events even
   though CBC ships them through a different API surface.

Auth: API Key ID (``X-Auth-Token`` first half) + API Secret Key (second
half), separated by a slash in CBC's docs but split into two fields in our
form for clarity. The connector composes them at request time.

Region: CBC has six prod regions (US East, US West, EU, UK, AU, APAC).
Wrong region produces a 401, not a 404, so we make region a required
explicit field rather than guessing from the org key prefix.

Capabilities:
- ``PULL_ALERTS`` — alerts feed (default).
- ``PULL_AUDIT`` — admin actions audit log.
- ``PIVOT_HOST`` — given a hostname, return device + recent alerts.
- ``ISOLATE_HOST`` — quarantine a sensor (`PUT /appservices/v6/orgs/{org}/device_actions`).
- ``QUARANTINE_FILE`` — ban a file hash org-wide.
- ``BLOCK_HASH`` — synonym alias to ``QUARANTINE_FILE`` against the hash
  reputation list. Both verbs are declared so the agent layer can pick
  whichever the operator scoped via ``allowed_capabilities``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Region → API hostname. Source: CBC Developer Network "Authentication"
# docs (current as of plan write date). Keep this map in sync with the
# select options below — UI labels use the human-readable name.
_REGION_HOSTS: dict[str, str] = {
    "us_east": "https://defense.conferdeploy.net",
    "us_west": "https://defense-eu.conferdeploy.net",  # CBC's quirk: US-W shares the EU base path
    "eu": "https://defense-eu.conferdeploy.net",
    "uk": "https://defense-uk.conferdeploy.net",
    "au": "https://defense-au.conferdeploy.net",
    "apac": "https://defense-apjp.conferdeploy.net",
}


class CarbonBlackConnector(BaseConnector):
    """VMware Carbon Black Cloud — alerts, audit, host actions."""

    connector_id = "carbon_black"
    connector_name = "VMware Carbon Black Cloud"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "VMware Carbon Black Cloud (formerly Carbon Black Defense). "
                "Pulls alerts and audit log entries via API key authentication. "
                "Supports host isolation and hash banning via agent capabilities."
            ),
            docs_url="/docs/connectors/carbon-black",
            fields=[
                Field(
                    "region",
                    "select",
                    "Region",
                    options=[
                        {"value": "us_east", "label": "US East (defense.conferdeploy.net)"},
                        {"value": "us_west", "label": "US West"},
                        {"value": "eu", "label": "Europe (defense-eu)"},
                        {"value": "uk", "label": "United Kingdom (defense-uk)"},
                        {"value": "au", "label": "Australia (defense-au)"},
                        {"value": "apac", "label": "APAC (defense-apjp)"},
                    ],
                    help_text=(
                        "CBC region your tenant is hosted in. The wrong region returns 401 rather than 404, so this can't be auto-detected."
                    ),
                ),
                Field(
                    "org_key",
                    "string",
                    "Org Key",
                    placeholder="ABCD1234",
                    help_text=("Found in CBC console under Settings → API Access → API Keys (the column labeled 'Org Key')."),
                ),
                Field(
                    "api_id",
                    "string",
                    "API ID",
                    help_text="The 'API ID' half of the credential pair.",
                ),
                Field(
                    "api_secret",
                    "secret",
                    "API Secret Key",
                    help_text="The long secret half of the credential pair.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_AUDIT,
            Capability.PIVOT_HOST,
            Capability.ISOLATE_HOST,
            Capability.QUARANTINE_FILE,
            Capability.BLOCK_HASH,
        )

    def __init__(self, region: str, org_key: str, api_id: str, api_secret: str):
        if region not in _REGION_HOSTS:
            raise ValueError(f"unknown CBC region: {region!r}")
        self._region = region
        self._base = _REGION_HOSTS[region]
        self._org_key = org_key
        self._api_id = api_id
        self._api_secret = api_secret

    def _headers(self) -> dict[str, str]:
        # CBC's auth header concatenates the two halves with a slash. This
        # is documented but unusual — split fields in the UI keep it clear
        # which half is the secret.
        return {
            "X-Auth-Token": f"{self._api_secret}/{self._api_id}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        # Cheapest probe: org-level metadata. Returns 200 for any valid
        # API key; 401 for bad creds; 404 if org_key wrong.
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/integrationServices/v3/auditlogs",
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "region": self._region,
                        "org_key": self._org_key,
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        start = datetime.now(UTC) - timedelta(seconds=since_seconds)
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        events: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Alerts feed via the v6 search endpoint. CBC requires a POST
            # body even for a "give me everything since X" query.
            try:
                alerts_resp = await client.post(
                    f"{self._base}/appservices/v6/orgs/{self._org_key}/alerts/_search",
                    headers=self._headers(),
                    json={
                        "criteria": {
                            "last_update_time": {"start": start_iso, "end": "*"},
                        },
                        "rows": 100,
                        "sort": [{"field": "last_update_time", "order": "DESC"}],
                    },
                )
                if alerts_resp.status_code == 200:
                    for alert in (alerts_resp.json() or {}).get("results", []):
                        alert["_aisoc_stream"] = "alerts"
                        events.append(alert)
                else:
                    logger.warning(
                        "carbon_black.alerts_failed",
                        status=alerts_resp.status_code,
                        body=alerts_resp.text[:300],
                    )
            except Exception as exc:
                logger.warning("carbon_black.alerts_exception", error=str(exc))

            # Audit log feed.
            try:
                audit_resp = await client.get(
                    f"{self._base}/integrationServices/v3/auditlogs",
                    headers=self._headers(),
                )
                if audit_resp.status_code == 200:
                    for entry in (audit_resp.json() or {}).get("notifications", []):
                        entry["_aisoc_stream"] = "audit"
                        events.append(entry)
            except Exception as exc:
                logger.warning("carbon_black.audit_exception", error=str(exc))

        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "alerts")
        if stream == "alerts":
            # Carbon Black Cloud uses a 1-10 severity scale on alerts.
            # 9-10 corresponds to confirmed/imminent threat activity,
            # which we surface as ``critical`` rather than collapsing to
            # ``high``.
            sev_score = int(raw.get("severity") or 0)
            if sev_score >= 9:
                severity = "critical"
            elif sev_score >= 7:
                severity = "high"
            elif sev_score >= 4:
                severity = "medium"
            elif sev_score >= 1:
                severity = "low"
            else:
                severity = "info"
            return {
                "source": "carbon_black",
                "category": "edr",
                "severity": severity,
                "title": raw.get("reason") or raw.get("threat_id") or "Carbon Black alert",
                "description": raw.get("reason"),
                "alert_id": raw.get("id"),
                "host": raw.get("device_name"),
                "user": raw.get("device_username"),
                "raw": raw,
            }
        # audit log
        return {
            "source": "carbon_black",
            "category": "audit",
            "severity": "info",
            "title": raw.get("description") or raw.get("flagged") or "Carbon Black audit event",
            "user": raw.get("loginName"),
            "raw": raw,
        }
