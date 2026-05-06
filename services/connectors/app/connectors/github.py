"""
GitHub organization audit log + code scanning alerts connector.

Pulls two distinct streams in a single connector:

1. **Audit log** — ``GET /orgs/{org}/audit-log`` covers every admin/security
   action: member adds, role changes, repo creation/deletion, PAT grants,
   secret-scanning policy changes, branch protection edits, etc. Requires
   the ``read:audit_log`` scope. Org must be on a plan that exposes the
   audit log API (Team and above).

2. **Code Scanning alerts** — ``GET /orgs/{org}/code-scanning/alerts``
   surfaces CodeQL / third-party scanner findings across every repo in the
   org. Requires ``security_events`` scope.

Auth: fine-grained personal access token OR a GitHub App installation
token. We accept the token directly; for App-based auth, the operator
generates an installation token externally and pastes it. Hosted OAuth
flow is deferred — the schema advertises that explicitly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_BASE = "https://api.github.com"
_PER_PAGE = 100


class GitHubConnector(BaseConnector):
    """GitHub org audit log + code-scanning alerts."""

    connector_id = "github"
    connector_name = "GitHub"
    connector_category = "vcs"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "GitHub organization audit log and Code Scanning alerts. "
                "Requires a token with read:audit_log and security_events "
                "scopes (fine-grained PAT or GitHub App installation token)."
            ),
            docs_url="/docs/connectors/github",
            fields=[
                Field(
                    "organization",
                    "string",
                    "Organization slug",
                    placeholder="my-org",
                ),
                Field(
                    "token",
                    "secret",
                    "Personal Access Token or App Installation Token",
                    help_text=(
                        "Fine-grained PAT recommended. Required scopes: "
                        "read:audit_log, security_events. For GitHub App "
                        "auth, paste a fresh installation token."
                    ),
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=False,
                authorize_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
                scopes=["read:audit_log", "security_events"],
            ),
        )

    def __init__(self, organization: str, token: str):
        self._org = organization
        self._token = token

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            # Pin the API version to avoid surprise breakages when GitHub
            # rolls out v2-style changes. ``2022-11-28`` is the long-stable
            # current version.
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # ``/orgs/{org}`` is cheap and returns 200 for any token
                # that can read the org. 401/403 here is the canonical
                # "your token is bad or doesn't have access" signal.
                resp = await client.get(
                    f"{_BASE}/orgs/{self._org}",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                    }

                # Audit log probe — confirms the token actually has
                # ``read:audit_log``. The endpoint returns 200 + [] on a
                # quiet org, 403 if the scope is missing, 404 if the org
                # plan doesn't include audit logs.
                audit_resp = await client.get(
                    f"{_BASE}/orgs/{self._org}/audit-log",
                    headers=self._headers(),
                    params={"per_page": 1},
                )
                if audit_resp.status_code not in (200, 404):
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": (f"Org reachable but audit-log probe failed: HTTP {audit_resp.status_code}: {audit_resp.text[:200]}"),
                    }
                audit_available = audit_resp.status_code == 200

            return {
                "success": True,
                "connector": self.connector_id,
                "organization": self._org,
                "audit_log_available": audit_available,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # GitHub timestamps audit-log events in milliseconds-since-epoch;
        # the ``phrase`` query param is the supported way to filter by
        # time window (``created:>=YYYY-MM-DDTHH:MM:SSZ``).
        start = datetime.now(UTC) - timedelta(seconds=since_seconds)
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        start_ms = int(start.timestamp() * 1000)

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1) audit log
            audit_resp = await client.get(
                f"{_BASE}/orgs/{self._org}/audit-log",
                headers=self._headers(),
                params={
                    "phrase": f"created:>={start_iso}",
                    "per_page": _PER_PAGE,
                    "order": "desc",
                },
            )
            if audit_resp.status_code == 200:
                for entry in audit_resp.json() or []:
                    entry["_aisoc_stream"] = "audit_log"
                    events.append(entry)
            elif audit_resp.status_code == 404:
                # Plan doesn't expose the audit log — log once and continue
                # with code-scanning. Don't error out the whole poll.
                logger.info(
                    "github.audit_log_unavailable",
                    organization=self._org,
                )
            else:
                logger.warning(
                    "github.audit_log_failed",
                    status=audit_resp.status_code,
                    body=audit_resp.text[:300],
                )

            # 2) code scanning alerts. Filtering by ``created`` is cleaner
            # than ``updated`` for our poll model — we want net-new
            # findings, not state churn (which would re-emit the same
            # alert every time a triager moves it through review).
            cs_resp = await client.get(
                f"{_BASE}/orgs/{self._org}/code-scanning/alerts",
                headers=self._headers(),
                params={
                    "state": "open",
                    "per_page": _PER_PAGE,
                    "sort": "created",
                    "direction": "desc",
                },
            )
            if cs_resp.status_code == 200:
                for alert in cs_resp.json() or []:
                    # Client-side filter on creation time. GitHub doesn't
                    # accept ``since`` on this endpoint, and pulling >100
                    # results just to filter would be wasteful at scale.
                    created_at = alert.get("created_at")
                    if created_at:
                        try:
                            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                            if created_dt.timestamp() * 1000 < start_ms:
                                # Sorted desc → first too-old result means
                                # all subsequent ones are also too old.
                                break
                        except ValueError:
                            pass  # unparseable timestamp; keep event without age filter
                    alert["_aisoc_stream"] = "code_scanning"
                    events.append(alert)
            elif cs_resp.status_code in (403, 404):
                # 403 = scope missing or feature disabled; 404 = no
                # advanced security on this plan. Both are configuration
                # issues, not transient failures.
                logger.info(
                    "github.code_scanning_unavailable",
                    status=cs_resp.status_code,
                )
            else:
                logger.warning(
                    "github.code_scanning_failed",
                    status=cs_resp.status_code,
                    body=cs_resp.text[:300],
                )

        return [self.normalize(e) for e in events]

    # ----------------------- normalize --------------------------

    # GitHub ``action`` strings that we always treat as high. These all
    # have the shape ``<category>.<verb>`` — list maintained from
    # https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
    _HIGH_RISK_ACTIONS = (
        # org membership / ownership
        "org.add_member",
        "org.remove_member",
        "org.update_member",  # role changes (member → owner is the canary)
        "org.transfer",
        # access tokens / SSH / SSO
        "personal_access_token.create",
        "personal_access_token.access_granted",
        "oauth_authorization.create",
        "public_key.create",
        "deploy_key.create",
        "two_factor_authentication.disabled",
        # branch protection bypass / deletion
        "protected_branch.destroy",
        "protected_branch.update_admin_enforced",
        # repository deletions
        "repo.destroy",
        "repo.transfer",
        "repo.access",  # visibility changes
        # secret scanning / dependabot tampering
        "secret_scanning.disable",
        "secret_scanning_alert.resolve",
        "dependabot_alerts.disable",
        # GitHub Apps with admin scopes
        "integration_installation.create",
        "integration_installation.repositories_added",
    )

    def _normalize_audit(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = raw.get("action", "")
        actor = raw.get("actor", "unknown")

        if any(h == action for h in self._HIGH_RISK_ACTIONS):
            severity = "high"
        elif action.endswith(".destroy") or action.endswith(".delete"):
            # Catch-all for delete-style actions we haven't enumerated
            # above. Better to over-flag deletions than miss them.
            severity = "medium"
        else:
            severity = "info"

        # ``created_at`` is a ms-since-epoch integer in audit log entries.
        created_ms = raw.get("created_at") or raw.get("@timestamp")
        created_iso: str | None = None
        if isinstance(created_ms, int | float):
            created_iso = datetime.fromtimestamp(created_ms / 1000, tz=UTC).isoformat()
        elif isinstance(created_ms, str):
            created_iso = created_ms

        return {
            "source": self.connector_id,
            "external_id": str(raw.get("_document_id") or raw.get("@timestamp") or ""),
            "title": action or "GitHub audit event",
            "description": (f"actor={actor}; action={action}; repo={raw.get('repo', '')}; org={raw.get('org', self._org)}"),
            "severity": severity,
            "actor": actor,
            "actor_email": raw.get("user_email"),
            "src_ip": raw.get("actor_ip"),
            "event_type": f"github.{action}" if action else "github.audit",
            "raw_event": raw,
            "created_at": created_iso,
        }

    # Code scanning severity values come from the rule, not the alert.
    # GitHub uses ``security-severity`` (CVSS-style numeric) and a
    # categorical ``severity`` (note/warning/error/critical/high/medium/low).
    # We honor the categorical first since it's set on every result.
    _CODE_SEVERITY_MAP = {
        "critical": "high",  # collapse into AiSOC's 4-tier ladder
        "high": "high",
        "error": "high",
        "medium": "medium",
        "warning": "medium",
        "low": "low",
        "note": "info",
    }

    def _normalize_code_scanning(self, raw: dict[str, Any]) -> dict[str, Any]:
        rule = raw.get("rule", {}) or {}
        gh_severity = (rule.get("security_severity_level") or rule.get("severity") or "").lower()
        severity = self._CODE_SEVERITY_MAP.get(gh_severity, "info")

        repo = (raw.get("repository") or {}).get("full_name", "")
        rule_id = rule.get("id", "")
        rule_desc = rule.get("description", "")

        return {
            "source": self.connector_id,
            "external_id": f"code-scanning-{raw.get('number', '')}",
            "title": f"Code Scanning: {rule_id or rule_desc or 'finding'}",
            "description": (
                f"repo={repo}; "
                f"rule={rule_id}; "
                f"tool={(raw.get('tool') or {}).get('name', '')}; "
                f"path={(raw.get('most_recent_instance') or {}).get('location', {}).get('path', '')}"
            ),
            "severity": severity,
            "actor": "code-scanning",
            "actor_email": None,
            "src_ip": None,
            "event_type": f"github.code_scanning.{rule_id}" if rule_id else "github.code_scanning",
            "raw_event": raw,
            "created_at": raw.get("created_at"),
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "audit_log")
        if stream == "code_scanning":
            return self._normalize_code_scanning(raw)
        return self._normalize_audit(raw)
