"""
Cloudflare audit logs connector.

Pulls the account-level audit log from the Cloudflare API. Auth is the
modern API token model — recommend a token scoped to ``Account: Audit Logs:
Read`` (and optionally ``Account: Account Settings: Read`` if you want
metadata). Account-scoped tokens beat global API keys for blast radius.

Endpoint: ``GET /accounts/{account_id}/audit_logs`` returns user/admin
activity such as zone changes, API token grants, member adds/removes, WAF
rule edits, and so on. Volume is generally low (most accounts produce
single-digit events per minute even at scale) so we use a flat list call
without pagination on the hot path.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_BASE = "https://api.cloudflare.com/client/v4"
_PER_PAGE = 100


class CloudflareConnector(BaseConnector):
    """Cloudflare account audit logs."""

    connector_id = "cloudflare"
    connector_name = "Cloudflare"
    # ``saas`` covers admin/config audit; the actual edge product is a
    # network service but our data here is operator activity, not packets.
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Cloudflare account audit logs (zone changes, API token "
                "grants, member adds, WAF/firewall edits) via the v4 API. "
                "Requires an API token scoped to Account: Audit Logs: Read."
            ),
            docs_url="/docs/connectors/cloudflare",
            fields=[
                Field(
                    "account_id",
                    "string",
                    "Account ID",
                    placeholder="abc123def456...",
                    help_text=('Found in the Cloudflare dashboard under any zone\'s Overview, lower-right pane ("Account ID").'),
                ),
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=("Account-scoped API token with the Audit Logs: Read permission. Avoid using the legacy Global API Key."),
                ),
            ],
            # Cloudflare doesn't have a meaningful OAuth flow for this API;
            # the token model is the recommended path for service-to-service.
            oauth=OAuthHints(
                supported_in_hosted=False,
                authorize_url=None,
                token_url=None,
                scopes=[],
            ),
        )

    def __init__(self, account_id: str, api_token: str):
        self._account_id = account_id
        self._api_token = api_token

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        # Cloudflare's recommended header for API tokens — distinct from
        # the legacy ``X-Auth-Email`` + ``X-Auth-Key`` global-key model.
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # ``/user/tokens/verify`` is the canonical token-health
                # endpoint; it returns 200 + ``status: active`` for a good
                # token without needing any account scope.
                resp = await client.get(
                    f"{_BASE}/user/tokens/verify",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                    }
                token_status = resp.json().get("result", {}).get("status")
                if token_status != "active":
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"Token status: {token_status}",
                    }

                # Now confirm the token has audit-log access for this account
                # by issuing a 1-record list. 403 here means "token is good
                # but missing the Audit Logs: Read permission" — that's a
                # different and more useful error than a generic auth fail.
                audit_resp = await client.get(
                    f"{_BASE}/accounts/{self._account_id}/audit_logs",
                    headers=self._headers(),
                    params={"per_page": 1},
                )
                if audit_resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": (f"Token verified but audit_logs failed: HTTP {audit_resp.status_code}: {audit_resp.text[:200]}"),
                    }

            return {
                "success": True,
                "connector": self.connector_id,
                "account_id": self._account_id,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        params = {
            "since": since,
            "per_page": _PER_PAGE,
            "direction": "desc",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{_BASE}/accounts/{self._account_id}/audit_logs",
                headers=self._headers(),
                params=params,
            )
            if resp.status_code != 200:
                logger.warning(
                    "cloudflare.fetch_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return []
            entries = resp.json().get("result", []) or []

        return [self.normalize(e) for e in entries]

    # ----------------------- normalize --------------------------

    # Cloudflare ``action.type`` values that we always escalate. The full
    # taxonomy is documented at
    # https://developers.cloudflare.com/api/operations/audit-logs-list-account-audit-logs
    # — these are the ones with material security impact.
    _HIGH_RISK_ACTIONS = (
        # API token / authentication changes
        "tokenCreate",
        "tokenDelete",
        "tokenUpdate",
        # account membership
        "memberAdd",
        "memberRemove",
        "memberRoleUpdate",
        "ownerChange",
        # firewall/WAF rule deletions are a classic ATT&CK T1562 pattern
        "firewallDelete",
        "wafPackageDelete",
        "wafRuleDelete",
        # zone / DNS deletions
        "zoneDelete",
        "dnsRecordDelete",
        # access (Zero Trust) policy changes
        "accessPolicyDelete",
        "accessApplicationDelete",
        "accessIdpDelete",
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = raw.get("action") or {}
        action_type = action.get("type", "")
        actor = raw.get("actor") or {}
        resource = raw.get("resource") or {}

        # Severity heuristic: high-risk actions → high; failed actions
        # (action.result == false) → low; ``info`` for everything else.
        severity = "info"
        if any(h == action_type for h in self._HIGH_RISK_ACTIONS):
            severity = "high"
        elif action.get("result") is False:
            severity = "low"

        actor_email = actor.get("email")

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": action_type or "Cloudflare audit event",
            "description": (
                f"actor={actor_email or actor.get('id', 'unknown')}; "
                f"action={action_type}; "
                f"resource={resource.get('type', '')}/{resource.get('id', '')}"
            ),
            "severity": severity,
            "actor": actor.get("email") or actor.get("id"),
            "actor_email": actor_email,
            "src_ip": raw.get("actor", {}).get("ip"),
            "event_type": f"cloudflare.{action_type}" if action_type else "cloudflare.audit",
            "raw_event": raw,
            "created_at": raw.get("when"),
        }
