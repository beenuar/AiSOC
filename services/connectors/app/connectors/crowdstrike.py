"""
CrowdStrike Falcon connector.

Polls Falcon alerts. The Detects API (`/detects/queries/detects/v1`) was
decommissioned on 2025-09-30 and now answers 404; the replacement is
`POST /alerts/combined/alerts/v1`, which needs the Alerts:Read scope.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class CrowdStrikeConnector(BaseConnector):
    connector_id = "crowdstrike"
    connector_name = "CrowdStrike Falcon"
    connector_category = "edr"

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # WS-E1: Live CrowdStrike Falcon RTR — all response actions now wired
        # via services/actions/app/clients/crowdstrike_rtr.py
        return (
            Capability.PULL_ALERTS,
            Capability.ISOLATE_HOST,
            Capability.UNISOLATE_HOST,
            Capability.KILL_PROCESS,
            Capability.QUARANTINE_FILE,
            Capability.RUN_SCRIPT,
        )

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="CrowdStrike Falcon alerts via the Falcon Alerts API.",
            docs_url="/docs/connectors/crowdstrike",
            fields=[
                Field("client_id", "string", "Client ID"),
                Field("client_secret", "secret", "Client Secret"),
                Field(
                    "base_url",
                    "string",
                    "Base URL",
                    required=False,
                    default="https://api.crowdstrike.com",
                    help_text="Override only if your tenant lives in a non-US cloud (e.g. api.eu-1.crowdstrike.com).",
                ),
            ],
        )

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url
        self._access_token: str | None = None

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base_url}/oauth2/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    async def test_connection(self) -> dict[str, Any]:
        # OAuth succeeding is not enough. A client with no Alerts:Read scope
        # still gets a token, and that is exactly how a saved connector looked
        # healthy while every poll 404'd the decommissioned Detects API.
        try:
            alerts = await self.fetch_alerts(since_seconds=60)
            return {
                "success": True,
                "connector": self.connector_id,
                "authenticated": True,
                "alerts_visible": len(alerts),
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        # A `Z`-suffixed UTC timestamp, which is the form CrowdStrike's own
        # FQL range examples use. `isoformat()` emits a `+00:00` offset
        # instead; whether Falcon accepts that has not been established
        # against a live tenant, and there is no reason to depend on it.
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        body: dict[str, Any] = {
            "filter": f"created_timestamp:>'{since}'",
            "limit": 100,
            "sort": "created_timestamp|asc",
        }
        alerts: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # One page is what the old Detects query returned. Follow `after`
            # a few times so a burst larger than 100 is not dropped, and stop
            # rather than paging a tenant's entire history.
            for _ in range(5):
                resp = await self._post_alerts(client, body)
                payload = resp.json()
                alerts.extend(item for item in (payload.get("resources") or []) if isinstance(item, dict))
                after = ((payload.get("meta") or {}).get("pagination") or {}).get("after")
                if not after:
                    break
                body = {**body, "after": after}
        return [self.normalize(alert) for alert in alerts]

    async def _post_alerts(self, client: httpx.AsyncClient, body: dict[str, Any]) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self._access_token}"}
        url = f"{self._base_url.rstrip('/')}/alerts/combined/alerts/v1"
        resp = await client.post(url, headers=headers, json=body)
        if resp.status_code == 401:
            await self._authenticate()
            headers = {"Authorization": f"Bearer {self._access_token}"}
            resp = await client.post(url, headers=headers, json=body)
        if resp.status_code == 403:
            raise RuntimeError(
                "CrowdStrike refused the alerts query (403). The API client needs the "
                "Alerts: Read scope. Falcon console → Support and resources → API clients "
                "and keys → edit this client → Alerts → Read."
            )
        resp.raise_for_status()
        return resp

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # CrowdStrike Falcon's `/detects` API exposes severity in three
        # related forms:
        #   * ``max_severity`` — integer 0-100 (band-scored).
        #   * ``max_severity_displayname`` — the band name itself
        #     ("Informational", "Low", "Medium", "High", "Critical").
        #   * ``severity`` (per-behavior) — same 0-100 scale.
        # Earlier versions of this connector treated ``max_severity`` as a
        # 1-4 scale and collapsed everything else to "medium", which
        # silently downgraded ``Critical`` detections. We now prefer the
        # explicit display name when present and otherwise bucket the
        # numeric score along the bands documented by CrowdStrike.
        severity_bands_displayname = {
            "informational": "info",
            # Both spellings: the band is published as "Informational", and
            # `severity_name` has been observed carrying the short form.
            # Missing one sends an otherwise-named band down the numeric
            # path, which is a different answer, not a tidier one.
            "info": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }

        # Alerts API names the band `severity_name`. The decommissioned
        # Detects payload used `max_severity_displayname`. Accept both.
        display_name = (raw.get("severity_name") or raw.get("max_severity_displayname") or "").strip().lower()
        if display_name in severity_bands_displayname:
            severity = severity_bands_displayname[display_name]
        else:
            score = raw.get("severity")
            if score is None:
                score = raw.get("max_severity")
            try:
                score_int = int(score) if score is not None else None
            except (TypeError, ValueError):
                score_int = None
            if score_int is None:
                severity = "medium"
            elif score_int >= 80:
                severity = "critical"
            elif score_int >= 60:
                severity = "high"
            elif score_int >= 40:
                severity = "medium"
            elif score_int >= 20:
                severity = "low"
            else:
                severity = "info"

        behaviors = raw.get("behaviors") or []
        title = (
            (raw.get("display_name") or "").strip()
            or (behaviors[0].get("display_name") if behaviors else "")
            or (raw.get("name") or "").strip()
            or "CrowdStrike Detection"
        )

        # Alerts carry the actor on the alert. Detects carried it only on
        # each behavior. `assigned_to_name` is the analyst the alert is
        # assigned to, not the actor, and must not be used here.
        actor = (raw.get("user_name") or "").strip()
        for behavior in behaviors:
            if actor:
                break
            candidate = (behavior.get("user_name") or "").strip()
            if candidate:
                domain = (behavior.get("user_id") or "").strip()
                actor = f"{candidate}@{domain}" if "@" not in candidate and "@" in domain else candidate
                break

        # Bound once rather than called twice inside the conditional: two
        # separate `raw.get("device")` calls give the checker nothing to
        # narrow, so `device` stays `Any | dict | None` and every `.get`
        # below it is an unchecked attribute on a possible None.
        raw_device = raw.get("device")
        device: dict[str, Any] = raw_device if isinstance(raw_device, dict) else {}
        hostname = device.get("hostname") or raw.get("hostname")
        techniques: list[str] = []
        for candidate in (raw.get("technique_id"),):
            if candidate and candidate not in techniques:
                techniques.append(candidate)
        for behavior in behaviors:
            technique = behavior.get("technique_id")
            if technique and technique not in techniques:
                techniques.append(technique)
        for item in raw.get("mitre_attack") or []:
            technique = item.get("technique_id") if isinstance(item, dict) else item
            if technique and technique not in techniques:
                techniques.append(technique)
        description = (raw.get("description") or "").strip() or f"CrowdStrike detection on {hostname or 'unknown'}"

        return {
            "source": self.connector_id,
            "external_id": raw.get("composite_id") or raw.get("id") or raw.get("detection_id") or "",
            "title": title,
            "description": description,
            "severity": severity,
            "src_ip": device.get("external_ip") or device.get("local_ip"),
            "hostname": hostname,
            "actor": actor or None,
            "mitre_techniques": techniques,
            "raw_event": raw,
            "created_at": raw.get("created_timestamp"),
        }
