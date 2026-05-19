"""
Tines connector.

Pulls Tines story / case events via the Tines REST API. Tines is a
no-code SOAR / automation platform organised around *stories* (the
workflows) and *cases* (the work items the workflows produce). For SOC
observability we want both surfaces:

1. **Story events** — ``GET /api/v1/audit_logs`` returns admin actions
   on tenants, stories, agents, credentials, and team membership. This
   is the audit trail for *configuration* changes (who edited a story,
   who rotated a credential).
2. **Case events** — ``GET /api/v1/cases`` returns the cases produced
   by stories. We page through the index endpoint and treat the
   per-case state (``open / in_progress / closed``) plus the most-recent
   record severity as the AiSOC-facing severity.

The connector polls both streams on every cycle and merges them.

Auth is API-token based: each operator creates a token under
**Profile → Personal Access Tokens** with the ``read_only`` role (the
``audit_logs`` and ``cases`` endpoints both honour read-only tokens).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

# Maximum pages we will follow in a single poll. Tines paginates with
# ``page`` + ``per_page`` (default 20, max 500). At 500/page * 20 = 10k
# events per stream per poll, which is well above what a healthy tenant
# emits in a 5-minute window. The bound is a safety net against runaway
# enumeration if the API ever returns a malformed cursor.
_MAX_PAGES = 20
_PER_PAGE = 100


class TinesConnector(BaseConnector):
    """Tines automation platform: story audit + case events."""

    connector_id = "tines"
    connector_name = "Tines"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Tines automation platform. Pulls story / agent audit events and case "
                "lifecycle events via the Tines REST API. Requires a personal access "
                "token with at least read-only scope on the target tenant."
            ),
            docs_url="/docs/connectors/tines",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Tines tenant URL",
                    placeholder="https://acme.tines.com",
                    help_text=(
                        "Your Tines tenant URL, including scheme. For self-hosted " "deployments use the full HTTPS URL of the Rails app."
                    ),
                ),
                Field(
                    "api_token",
                    "secret",
                    "Personal Access Token",
                    help_text=(
                        "Generate under Profile → Personal Access Tokens. Read-only "
                        "scope is sufficient; the connector never writes back to Tines."
                    ),
                ),
                Field(
                    "team_id",
                    "string",
                    "Team ID (optional)",
                    required=False,
                    help_text=("Scope event ingestion to a single Team. Leave blank to ingest across all teams the token can see."),
                ),
            ],
            # Tines exposes OAuth 2.0 on enterprise plans, but the vast
            # majority of tenants use personal access tokens. We advertise
            # the hosted-OAuth slot as not-yet-supported so the UI renders
            # the API-token form without the OAuth call-to-action.
            oauth=OAuthHints(supported_in_hosted=False),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.PULL_ALERTS,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, base_url: str, api_token: str, team_id: str | None = None):
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._team_id = (team_id or "").strip() or None

    # --------------------------- auth ---------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
            "User-Agent": "AiSOC-Connector/1.0",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/api/v1/users/info",
                    headers=self._headers(),
                )
                if resp.status_code != 200:
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                    }
                me = resp.json() or {}
            return {
                "success": True,
                "connector": self.connector_id,
                "tenant": self._base_url,
                "user_email": me.get("email"),
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(seconds=since_seconds)
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # ---- audit logs (story / agent / credential admin events) ----
            audit_params: dict[str, Any] = {
                "per_page": _PER_PAGE,
                # ``operation_name`` is left blank — Tines doesn't expose
                # a time filter on this endpoint, so we sort desc and stop
                # as soon as we cross ``since`` in normalize-time.
            }
            if self._team_id:
                audit_params["team_id"] = self._team_id
            audit_events = await self._paginate(
                client=client,
                path="/api/v1/audit_logs",
                params=audit_params,
                stream="audit_log",
                since=since,
                created_at_field="created_at",
            )
            events.extend(audit_events)

            # ---- cases (story-produced work items) ----
            case_params: dict[str, Any] = {
                "per_page": _PER_PAGE,
                # Tines supports a ``modified_after`` filter on the cases
                # index for incremental pulls. We pass it explicitly so
                # we do not re-emit stale cases on every poll.
                "modified_after": since_iso,
            }
            if self._team_id:
                case_params["team_id"] = self._team_id
            case_events = await self._paginate(
                client=client,
                path="/api/v1/cases",
                params=case_params,
                stream="case",
                since=since,
                created_at_field="updated_at",
            )
            events.extend(case_events)

        return [self.normalize(e) for e in events]

    async def _paginate(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any],
        stream: str,
        since: datetime,
        created_at_field: str,
    ) -> list[dict[str, Any]]:
        """Walk a Tines paginated index endpoint.

        Tines returns ``{"audit_logs": [...], "meta": {"current_page": N,
        "next_page": N+1 | null}}`` (or ``cases`` instead of
        ``audit_logs``). We follow ``next_page`` up to ``_MAX_PAGES``.
        """
        out: list[dict[str, Any]] = []
        page = 1
        for _ in range(_MAX_PAGES):
            page_params = dict(params, page=page)
            resp = await client.get(f"{self._base_url}{path}", headers=self._headers(), params=page_params)
            if resp.status_code != 200:
                logger.warning("tines.fetch_failed", path=path, status=resp.status_code, body=resp.text[:200])
                break

            body = resp.json() or {}
            # The Tines API uses the plural collection name as the key.
            items_key = "audit_logs" if "audit_logs" in body else ("cases" if "cases" in body else None)
            items = body.get(items_key) if items_key else None
            if not items:
                break

            stopped_on_age = False
            for item in items:
                # Client-side time filter on the audit-log stream (which
                # doesn't honour ``modified_after``). For cases the
                # filter is server-side; we still guard here in case the
                # server returns extras.
                created_raw = item.get(created_at_field) or item.get("created_at")
                if created_raw and isinstance(created_raw, str):
                    try:
                        created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
                        if created < since:
                            stopped_on_age = True
                            continue
                    except ValueError:
                        pass  # unparseable → keep the event, don't drop silently
                item["_aisoc_stream"] = stream
                out.append(item)

            # Sorted-desc heuristic: once we hit a too-old item, every
            # subsequent page is older still, so stop pagination.
            if stopped_on_age:
                break

            next_page = ((body.get("meta") or {}).get("next_page")) if isinstance(body.get("meta"), dict) else None
            if not next_page:
                break
            page = next_page

        return out

    # ----------------------- normalize --------------------------

    # Tines audit-log ``operation_name`` strings that are always
    # security-relevant. Source: Tines admin → "Audit log filters" UI.
    _HIGH_RISK_AUDIT_OPS = (
        "credential.created",
        "credential.deleted",
        "credential.updated",
        "team.member_added",
        "team.member_removed",
        "team.member_role_changed",
        "tenant.api_key_created",
        "tenant.api_key_revoked",
        "story.deleted",
        "story.published",
        "story.disabled",
        "tenant.sso_disabled",
        "tenant.password_policy_updated",
    )

    # Tines case "record severity" — the worst severity of any record
    # attached to the case — uses the vendor-native string ladder. We
    # collapse to the AiSOC 4-tier ladder per the wave-1 mapping rule.
    _CASE_SEVERITY_MAP = {
        "critical": "high",
        "error": "high",
        "high": "high",
        "warn": "low",
        "warning": "low",
        "medium": "medium",
        "info": "info",
        "low": "low",
        "success": "info",
        "ok": "info",
    }

    def _normalize_audit(self, raw: dict[str, Any]) -> dict[str, Any]:
        op = raw.get("operation_name") or "tines.audit"
        actor = raw.get("user_email") or (raw.get("user") or {}).get("email") or "unknown"

        if any(op == h for h in self._HIGH_RISK_AUDIT_OPS):
            severity = "high"
        elif op.endswith(".deleted") or op.endswith(".destroyed"):
            severity = "medium"
        elif op.endswith(".failed"):
            severity = "low"
        else:
            severity = "info"

        return {
            "source": self.connector_id,
            "external_id": f"tines-audit-{raw.get('id', '')}",
            "title": f"Tines audit: {op}",
            "description": (f"actor={actor}; op={op}; tenant={raw.get('tenant_id', '')}; team={raw.get('team_id', '')}"),
            "severity": severity,
            "actor": actor,
            "actor_email": raw.get("user_email"),
            "src_ip": raw.get("request_ip"),
            "event_type": f"tines.{op}",
            "raw_event": raw,
            "created_at": raw.get("created_at"),
        }

    def _normalize_case(self, raw: dict[str, Any]) -> dict[str, Any]:
        record_sev = (raw.get("record_severity") or raw.get("severity") or "info").lower()
        severity = self._CASE_SEVERITY_MAP.get(record_sev, "info")

        # Closed cases that resolved cleanly are not actionable noise —
        # collapse them to "info" regardless of their record severity.
        # Open / in_progress cases keep their record-derived severity.
        status = (raw.get("status") or "").lower()
        if status == "closed" and (raw.get("resolution") or "").lower() in ("resolved", "closed", "completed"):
            severity = "info"

        assignee = (raw.get("assignee") or {}).get("email") if isinstance(raw.get("assignee"), dict) else None
        case_name = raw.get("name") or f"Tines case {raw.get('id', '')}"

        return {
            "source": self.connector_id,
            "external_id": f"tines-case-{raw.get('id', '')}",
            "title": f"Tines case: {case_name}",
            "description": (
                f"status={status}; record_severity={record_sev}; story_id={raw.get('story_id', '')}; assignee={assignee or 'unassigned'}"
            ),  # noqa: E501
            "severity": severity,
            "actor": assignee or "unassigned",
            "actor_email": assignee,
            "src_ip": None,
            "event_type": f"tines.case.{status or 'updated'}",
            "raw_event": raw,
            "created_at": raw.get("updated_at") or raw.get("created_at"),
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "audit_log")
        if stream == "case":
            return self._normalize_case(raw)
        return self._normalize_audit(raw)
