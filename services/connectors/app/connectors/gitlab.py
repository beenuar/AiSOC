"""
GitLab group audit events + vulnerability findings connector.

Pulls two distinct streams in a single connector, mirroring the GitHub
connector pattern:

1. **Audit events** — ``GET /api/v4/groups/{group_id}/audit_events`` covers
   every group-level audit action: member adds, role changes, project
   creation/deletion, deploy-token edits, two-factor changes, etc.
   Requires a Personal Access Token with the ``api`` scope and the
   authenticating user must be an Owner of the group. On the SaaS plan
   audit events are available for Premium + Ultimate groups; on
   self-managed installations they ship from Premium up.

2. **Vulnerability findings** — ``GET /api/v4/groups/{group_id}/security/
   vulnerability_findings``. Surfaces Container Scanning, SAST, DAST,
   Secret Detection, Dependency Scanning, and Coverage Fuzzing results
   across every project in the group. Requires the ``api`` scope and a
   GitLab tier that exposes the Security Center (Ultimate today).

Auth: Personal Access Token. We accept the token directly; OAuth is
deferred to Workstream 2 (the schema advertises the endpoints). Self-
managed installs work too — operators set the ``gitlab_url`` field to
the base URL of their instance.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_DEFAULT_BASE = "https://gitlab.com"
_PER_PAGE = 100


class GitLabConnector(BaseConnector):
    """GitLab group audit events + vulnerability findings."""

    connector_id = "gitlab"
    connector_name = "GitLab"
    connector_category = "vcs"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "GitLab group audit events and security vulnerability "
                "findings. Requires a Personal Access Token with the "
                "'api' scope; the authenticating user must own the group. "
                "Self-managed GitLab works too — set gitlab_url to your "
                "instance base URL."
            ),
            docs_url="/docs/connectors/gitlab",
            fields=[
                Field(
                    "gitlab_url",
                    "string",
                    "GitLab base URL",
                    placeholder=_DEFAULT_BASE,
                    help_text=(
                        "Leave default for gitlab.com. For self-managed "
                        "installations, paste the URL operators use to "
                        "reach the web UI (no trailing slash)."
                    ),
                ),
                Field(
                    "group",
                    "string",
                    "Group path or numeric ID",
                    placeholder="my-org or 1234567",
                ),
                Field(
                    "token",
                    "secret",
                    "Personal Access Token (scope: api)",
                    help_text=(
                        "PAT with the 'api' scope. The authenticating "
                        "user must be a group Owner to read audit "
                        "events. Security findings require Ultimate."
                    ),
                ),
            ],
            # Workstream 2 — hosted OAuth. GitLab supports OAuth 2.0 PKCE
            # for both gitlab.com and self-managed instances; the
            # authorize/token URLs below are gitlab.com defaults that the
            # router rewrites per-tenant if a custom gitlab_url is set.
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url=f"{_DEFAULT_BASE}/oauth/authorize",
                token_url=f"{_DEFAULT_BASE}/oauth/token",
                scopes=["api", "read_api"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # GitLab group audit log + security vulnerability findings.
        return (Capability.PULL_AUDIT, Capability.PULL_ALERTS)

    def __init__(
        self,
        group: str,
        token: str,
        gitlab_url: str | None = None,
    ):
        self._group = group
        self._token = token
        self._base = (gitlab_url or _DEFAULT_BASE).rstrip("/")

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        return {
            # GitLab accepts both Bearer and PRIVATE-TOKEN; PRIVATE-TOKEN
            # is the historical PAT header and works on every plan.
            "PRIVATE-TOKEN": self._token,
            "Accept": "application/json",
        }

    @property
    def _group_path(self) -> str:
        """URL-encoded group slug.

        GitLab's API accepts either a numeric ID or a URL-encoded full
        path. The user supplies one of those forms; we encode it here so
        slashes inside nested-group paths (``parent/child``) survive.
        """
        return quote(str(self._group), safe="")

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # ``/groups/{id}`` is cheap and returns 200 for any
                # authenticated token that can read the group; 401 / 403
                # is the canonical "bad token or missing access" signal,
                # 404 means the group path is wrong.
                resp = await client.get(
                    f"{self._base}/api/v4/groups/{self._group_path}",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                    }

                # Audit-events probe — confirms the token has the right
                # tier + ownership for the audit stream. 200+[] on a quiet
                # group, 403 if user isn't an owner, 404 if the tier
                # doesn't ship audit events.
                audit_resp = await client.get(
                    f"{self._base}/api/v4/groups/{self._group_path}/audit_events",
                    headers=self._headers(),
                    params={"per_page": 1},
                )
                if audit_resp.status_code not in (200, 403, 404):
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": (
                            f"Group reachable but audit-events probe failed: " f"HTTP {audit_resp.status_code}: {audit_resp.text[:200]}"
                        ),
                    }
                audit_available = audit_resp.status_code == 200

            return {
                "success": True,
                "connector": self.connector_id,
                "group": self._group,
                "gitlab_url": self._base,
                "audit_events_available": audit_available,
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # GitLab audit events expose ``created_after`` filtering directly
        # on the endpoint, so we don't need post-hoc filtering for that
        # stream. Vulnerability findings don't expose a ``since`` param,
        # so we sort by ``created_at desc`` and stop client-side once we
        # pass the window.
        start = datetime.now(UTC) - timedelta(seconds=since_seconds)
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        start_ms = int(start.timestamp() * 1000)

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1) audit events
            audit_resp = await client.get(
                f"{self._base}/api/v4/groups/{self._group_path}/audit_events",
                headers=self._headers(),
                params={
                    "created_after": start_iso,
                    "per_page": _PER_PAGE,
                },
            )
            if audit_resp.status_code == 200:
                for entry in audit_resp.json() or []:
                    entry["_aisoc_stream"] = "audit_events"
                    events.append(entry)
            elif audit_resp.status_code in (403, 404):
                # Tier or ownership missing — log once, keep going.
                logger.info(
                    "gitlab.audit_events_unavailable",
                    status=audit_resp.status_code,
                    group=self._group,
                )
            else:
                logger.warning(
                    "gitlab.audit_events_failed",
                    status=audit_resp.status_code,
                    body=audit_resp.text[:300],
                )

            # 2) security vulnerability findings. Ultimate-tier only;
            # we treat 403/404 as "not available on this plan" rather
            # than as an error.
            vf_resp = await client.get(
                f"{self._base}/api/v4/groups/{self._group_path}/security/vulnerability_findings",
                headers=self._headers(),
                params={
                    "per_page": _PER_PAGE,
                    "order_by": "created_at",
                    "sort": "desc",
                },
            )
            if vf_resp.status_code == 200:
                for finding in vf_resp.json() or []:
                    created_at = finding.get("created_at")
                    if created_at:
                        try:
                            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                            if created_dt.timestamp() * 1000 < start_ms:
                                # Sorted desc — first too-old result means
                                # all remaining ones are also too old.
                                break
                        except ValueError:
                            pass  # unparseable timestamp; keep event
                    finding["_aisoc_stream"] = "vulnerability_finding"
                    events.append(finding)
            elif vf_resp.status_code in (403, 404):
                logger.info(
                    "gitlab.vulnerability_findings_unavailable",
                    status=vf_resp.status_code,
                )
            else:
                logger.warning(
                    "gitlab.vulnerability_findings_failed",
                    status=vf_resp.status_code,
                    body=vf_resp.text[:300],
                )

        return [self.normalize(e) for e in events]

    # ----------------------- normalize --------------------------

    # GitLab ``action_name`` strings that we always treat as high.
    # Maintained from the public docs (gitlab.com/help/administration/
    # audit_event_streaming/audit_event_types).
    _HIGH_RISK_ACTIONS = (
        # group membership / ownership
        "user_add",
        "user_remove",
        "change_role",
        "transfer_ownership",
        # access tokens / SSH / OAuth
        "personal_access_token_create",
        "personal_access_token_revoke",
        "group_access_token_create",
        "project_access_token_create",
        "ssh_key_add",
        "two_factor_authentication_disabled",
        # branch / project protection bypass
        "remove_protected_branch",
        "remove_protected_tag",
        # project / group destruction
        "project_destroyed",
        "group_destroyed",
        "project_transfer",
        # security feature tampering
        "security_dashboard_disabled",
        "container_scanning_disabled",
        "sast_disabled",
        "secret_detection_disabled",
        # CI/CD risky surface
        "ci_cd_settings_changed",
        "runner_registered",
    )

    def _normalize_audit(self, raw: dict[str, Any]) -> dict[str, Any]:
        # ``details`` is a nested dict with the human-readable change; the
        # action key sits inside it.
        details = raw.get("details") or {}
        action = details.get("custom_message") or details.get("action") or details.get("event_name") or details.get("change") or ""
        # Best-effort actor extraction — GitLab places the user name in
        # ``author_name`` (or ``details.author_name`` on streamed events).
        actor = raw.get("author_name") or details.get("author_name") or "unknown"

        action_lower = action.lower()
        if any(h in action_lower for h in self._HIGH_RISK_ACTIONS):
            severity = "high"
        elif "destroy" in action_lower or "delete" in action_lower or "remove" in action_lower:
            severity = "medium"
        else:
            severity = "info"

        return {
            "source": self.connector_id,
            "external_id": str(raw.get("id") or ""),
            "title": action or "GitLab audit event",
            "description": (
                f"actor={actor}; action={action}; " f"entity_type={raw.get('entity_type', '')}; " f"entity_id={raw.get('entity_id', '')}"
            ),
            "severity": severity,
            "actor": actor,
            "actor_email": details.get("author_email"),
            "src_ip": details.get("ip_address"),
            "event_type": f"gitlab.{action_lower or 'audit'}",
            "raw_event": raw,
            "created_at": raw.get("created_at"),
        }

    # GitLab uses ``severity`` directly (info/unknown/low/medium/high/critical)
    # on vulnerability findings. AiSOC's 5-tier ladder
    # (info | low | medium | high | critical) preserves the critical tier
    # end-to-end so Ultimate-tier SAST/DAST P1s keep their priority.
    _FINDING_SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "unknown": "info",
    }

    def _normalize_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        gl_severity = (raw.get("severity") or "").lower()
        severity = self._FINDING_SEVERITY_MAP.get(gl_severity, "info")

        scanner = (raw.get("scanner") or {}).get("name", "")
        project = (raw.get("project") or {}).get("name", "")
        identifier_value = ""
        identifiers = raw.get("identifiers") or []
        if identifiers and isinstance(identifiers, list):
            identifier_value = identifiers[0].get("name") or identifiers[0].get("external_id", "")

        return {
            "source": self.connector_id,
            "external_id": f"finding-{raw.get('uuid') or raw.get('id') or ''}",
            "title": raw.get("name") or f"GitLab security finding ({scanner})",
            "description": (
                f"project={project}; " f"scanner={scanner}; " f"identifier={identifier_value}; " f"state={raw.get('state', '')}"
            ),
            "severity": severity,
            "actor": "gitlab-security",
            "actor_email": None,
            "src_ip": None,
            "event_type": f"gitlab.security.{scanner}" if scanner else "gitlab.security",
            "raw_event": raw,
            "created_at": raw.get("created_at"),
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "audit_events")
        if stream == "vulnerability_finding":
            return self._normalize_finding(raw)
        return self._normalize_audit(raw)
