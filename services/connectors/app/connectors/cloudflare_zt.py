"""
Cloudflare WAF + Zero Trust events connector.

Distinct from the existing ``cloudflare`` connector (account audit log):
this one pulls *data-plane* events from two streams and folds them into
the same normalised shape:

  * **WAF / firewall events** — ``GET /zones/{zone_id}/security/events``.
    Per-zone request-level decisions: block, challenge, log, jschallenge.
    The new endpoint replaced the legacy ``firewall/events`` API in
    mid-2024; payloads carry rule_id, action, source IP, country, ray_id.
  * **Zero Trust (Access) audit** — ``GET /accounts/{account_id}/access/logs/access_requests``.
    Application access decisions: who tried to reach which Access app,
    were they allowed, and why. Carries email, ip, app_uid, decision.

A single ``mode`` field on the connector selects which stream is active
for a given instance — operators add one Cloudflare account-id + token,
then instantiate the connector twice (once per stream) rather than us
multiplexing both into one polling job and tangling the rate limits.

Auth is a single account-scoped API token with both ``Account: Access:
Audit Logs: Read`` and ``Zone: Firewall Services: Read`` (the WAF events
endpoint reads zone-scoped firewall events). Bearer-token model only —
the legacy global-key path is not supported.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_BASE = "https://api.cloudflare.com/client/v4"
_PER_PAGE = 100
_MAX_PAGES = 20


class CloudflareZTConnector(BaseConnector):
    """Cloudflare WAF + Zero Trust events."""

    connector_id = "cloudflare_zt"
    connector_name = "Cloudflare WAF + Zero Trust"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Cloudflare data-plane events: WAF / firewall decisions "
                "(per-zone) and Zero Trust Access audit log "
                "(per-account). Auth is an account-scoped API token "
                "with Zone:Firewall Services:Read and Account:Access "
                "Audit Logs:Read."
            ),
            docs_url="/docs/connectors/cloudflare_zt",
            fields=[
                Field(
                    "mode",
                    "select",
                    "Event stream",
                    options=[
                        {"value": "waf", "label": "WAF / firewall events"},
                        {"value": "access", "label": "Zero Trust Access audit"},
                    ],
                    help_text=("Pick which stream this instance pulls. Run two " "instances side-by-side for full coverage."),
                ),
                Field(
                    "account_id",
                    "string",
                    "Account ID",
                    placeholder="abc123def456",
                    help_text="Cloudflare account ID, found in the dashboard right pane.",
                ),
                Field(
                    "zone_id",
                    "string",
                    "Zone ID (WAF mode only)",
                    placeholder="zone-uuid",
                    required=False,
                    help_text="Required when mode=waf. Leave empty for Access mode.",
                ),
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=(
                        "Account-scoped token with Zone:Firewall " "Services:Read (WAF) AND Account:Access " "Audit Logs:Read (Zero Trust)."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_AUDIT,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(
        self,
        mode: str,
        account_id: str,
        api_token: str,
        zone_id: str | None = None,
    ):
        mode = (mode or "").lower()
        if mode not in ("waf", "access"):
            raise ValueError(f"cloudflare_zt: unknown mode '{mode}' (need 'waf' or 'access')")
        if mode == "waf" and not zone_id:
            raise ValueError("cloudflare_zt: zone_id is required when mode='waf'")
        self._mode = mode
        self._account_id = account_id
        self._zone_id = zone_id
        self._api_token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Token health first — gives a clean signal that auth is OK.
                resp = await client.get(
                    f"{_BASE}/user/tokens/verify",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"token verify HTTP {resp.status_code}",
                    }
                status = (resp.json() or {}).get("result", {}).get("status")
                if status != "active":
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"token status: {status}",
                    }

                # Then probe the active mode's endpoint with limit=1 so an
                # ill-scoped token surfaces a useful "missing permission" hint
                # rather than just "auth ok, no data".
                probe = await client.get(
                    self._endpoint(),
                    headers=self._headers(),
                    params=self._params(since_iso=None, per_page=1),
                )
                if probe.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": (f"token verified but {self._mode} probe HTTP " f"{probe.status_code}: {probe.text[:200]}"),
                    }
            return {
                "success": True,
                "connector": self.connector_id,
                "mode": self._mode,
                "account_id": self._account_id,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    def _endpoint(self) -> str:
        if self._mode == "waf":
            return f"{_BASE}/zones/{self._zone_id}/security/events"
        return f"{_BASE}/accounts/{self._account_id}/access/logs/access_requests"

    def _params(self, since_iso: str | None, per_page: int = _PER_PAGE) -> dict[str, Any]:
        params: dict[str, Any] = {"per_page": per_page, "limit": per_page}
        if since_iso:
            # The two endpoints use different parameter names for the
            # lower bound. Keep both off the hot path.
            if self._mode == "waf":
                params["since"] = since_iso
            else:
                params["since"] = since_iso
        return params

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                params = self._params(since_iso=since)
                if cursor:
                    params["cursor"] = cursor
                resp = await client.get(self._endpoint(), headers=self._headers(), params=params)
                if resp.status_code != 200:
                    logger.warning(
                        "cloudflare_zt.fetch_failed",
                        mode=self._mode,
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                body = resp.json() or {}
                events = body.get("result") or []
                for ev in events:
                    out.append(self.normalize(ev))
                # Cloudflare returns ``result_info.cursor`` for keyset paging
                # on the new security events endpoint. When the cursor is
                # present the server is telling us there is more — trust it
                # even if this page came back short. The cursor going empty
                # is the authoritative end-of-stream signal.
                info = body.get("result_info") or {}
                cursor = info.get("cursor") or info.get("next_cursor")
                if not cursor:
                    break
        return out

    # ----------------------- normalize --------------------------

    # WAF actions where the request was actively prevented — these are the
    # ones a SOC actually wants surfaced. ``log`` and ``allow`` flow through
    # as ``info``.
    _WAF_BLOCKING_ACTIONS = ("block", "drop", "managed_challenge", "jschallenge", "challenge")
    # Access decisions that indicate a denied / non-allowed access attempt.
    _ACCESS_DENY_DECISIONS = ("non_identity", "denied", "blocked", "non-identity")

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if self._mode == "waf":
            return self._normalize_waf(raw)
        return self._normalize_access(raw)

    def _normalize_waf(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = (raw.get("action") or "").lower()
        rule_id = raw.get("rule_id") or raw.get("ruleId")
        severity = "info"
        if action in self._WAF_BLOCKING_ACTIONS:
            severity = "medium"
        if action == "block" and rule_id and "owasp" in str(rule_id).lower():
            severity = "high"
        return {
            "source": self.connector_id,
            "stream": "waf",
            "external_id": raw.get("rayName") or raw.get("ray_id") or raw.get("id") or "",
            "title": f"Cloudflare WAF {action or 'event'}",
            "description": (
                f"action={action}; rule_id={rule_id}; "
                f"host={raw.get('host')}; "
                f"client_ip={raw.get('client_ip') or raw.get('clientIP')}; "
                f"country={raw.get('country')}"
            ),
            "severity": severity,
            "src_ip": raw.get("client_ip") or raw.get("clientIP"),
            "actor": raw.get("client_ip") or raw.get("clientIP"),
            "event_type": f"cloudflare_zt.waf.{action or 'event'}",
            "raw_event": raw,
            "created_at": raw.get("occurred_at") or raw.get("datetime"),
        }

    def _normalize_access(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = (raw.get("action") or raw.get("decision") or "").lower()
        allowed = raw.get("allowed")
        severity = "info"
        if allowed is False or action in self._ACCESS_DENY_DECISIONS:
            severity = "medium"
        if action in ("blocked",):
            severity = "high"
        email = raw.get("user_email") or raw.get("email")
        return {
            "source": self.connector_id,
            "stream": "access",
            "external_id": raw.get("ray_id") or raw.get("id") or "",
            "title": f"Cloudflare Access {action or 'request'}",
            "description": (
                f"decision={action}; user={email}; "
                f"app={raw.get('app_uid') or raw.get('app_name')}; "
                f"ip={raw.get('ip_address') or raw.get('ip')}; "
                f"country={raw.get('country')}"
            ),
            "severity": severity,
            "src_ip": raw.get("ip_address") or raw.get("ip"),
            "actor": email,
            "actor_email": email,
            "event_type": f"cloudflare_zt.access.{action or 'request'}",
            "raw_event": raw,
            "created_at": raw.get("created_at") or raw.get("datetime"),
        }
