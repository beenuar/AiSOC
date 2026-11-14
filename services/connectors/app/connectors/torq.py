"""
Torq connector.

Pulls workflow execution events and audit events from Torq via the
public Public API at ``https://api.torq.io/public/v1``.

Two streams:

1. **Workflow executions** — ``GET /workflows/executions`` returns the
   per-run results for all workflows the API key can see, with status
   (``success / warning / failed / killed / running``) and timing data.
2. **Audit log events** — ``GET /audit-logs`` returns the admin event
   stream: workflow create / edit / delete, integration credential
   changes, user role changes, API token issuance.

Auth: Torq uses OAuth-style client credentials. The operator creates an
"API key" pair under **Settings → API Keys** (a ``key_id`` +
``key_secret``); the connector exchanges them for a short-lived bearer
token at ``/auth/v1/token`` and caches it for ~1 hour.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_DEFAULT_BASE = "https://api.torq.io/public/v1"
_AUTH_URL = "https://api.torq.io/auth/v1/token"
_MAX_PAGES = 20
_PAGE_SIZE = 100


class TorqConnector(BaseConnector):
    """Torq automation: workflow execution + audit events."""

    connector_id = "torq"
    connector_name = "Torq"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Torq automation platform. Streams workflow execution outcomes and "
                "tenant audit events (workflow edits, credential changes, role "
                "assignments). Requires an API key pair (key_id + secret) issued "
                "under Settings → API Keys."
            ),
            docs_url="/docs/connectors/torq",
            fields=[
                Field("key_id", "string", "API Key ID"),
                Field("key_secret", "secret", "API Key Secret"),
                Field(
                    "base_url",
                    "string",
                    "API Base URL (advanced)",
                    required=False,
                    default=_DEFAULT_BASE,
                    placeholder=_DEFAULT_BASE,
                    help_text=("Override only for regional or self-hosted Torq deployments. Leave blank for the SaaS default."),
                ),
            ],
            oauth=OAuthHints(supported_in_hosted=False),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.PULL_ALERTS,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, key_id: str, key_secret: str, base_url: str | None = None):
        self._key_id = key_id
        self._key_secret = key_secret
        self._base_url = (base_url or _DEFAULT_BASE).rstrip("/")
        # Bearer token cache. We refresh lazily on every poll because
        # poll cadence is well below the 1h token TTL; refreshing every
        # cycle keeps the code simple and the cost is one extra round
        # trip per 5 minutes.
        self._token: str | None = None

    # --------------------------- auth ---------------------------

    async def _refresh_token(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            _AUTH_URL,
            json={"key_id": self._key_id, "key_secret": self._key_secret},
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"torq auth failed: HTTP {resp.status_code}: {resp.text[:200]}")
        body = resp.json() or {}
        token = body.get("access_token") or body.get("token")
        if not token:
            raise RuntimeError("torq auth response missing access_token")
        self._token = str(token)
        return self._token

    def _headers(self) -> dict[str, str]:
        if not self._token:
            raise RuntimeError("torq: token has not been refreshed; call _refresh_token first")
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "AiSOC-Connector/1.0",
        }

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                await self._refresh_token(client)
                resp = await client.get(
                    f"{self._base_url}/workflows",
                    headers=self._headers(),
                    params={"page_size": 1},
                )
                if resp.status_code not in (200, 404):
                    return {
                        "success": False,
                        "connector": self.connector_id,
                        "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                    }
            return {"success": True, "connector": self.connector_id, "base_url": self._base_url}
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(seconds=since_seconds)
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        events: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._refresh_token(client)

            exec_events = await self._paginate(
                client=client,
                path="/workflows/executions",
                params={"page_size": _PAGE_SIZE, "started_after": since_iso},
                stream="execution",
                items_key="executions",
            )
            events.extend(exec_events)

            audit_events = await self._paginate(
                client=client,
                path="/audit-logs",
                params={"page_size": _PAGE_SIZE, "from": since_iso},
                stream="audit_log",
                items_key="events",
            )
            events.extend(audit_events)

        return [self.normalize(e) for e in events]

    async def _paginate(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any],
        stream: str,
        items_key: str,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        next_token: str | None = None
        for _ in range(_MAX_PAGES):
            call_params = dict(params)
            if next_token:
                call_params["page_token"] = next_token
            resp = await client.get(f"{self._base_url}{path}", headers=self._headers(), params=call_params)
            if resp.status_code != 200:
                logger.warning("torq.fetch_failed", path=path, status=resp.status_code, body=resp.text[:200])
                break
            body = resp.json() or {}
            items = body.get(items_key) or body.get("items") or []
            if not items:
                break
            for item in items:
                item["_aisoc_stream"] = stream
                out.append(item)
            # Torq returns ``next_page_token`` (sometimes ``next_token``).
            next_token = body.get("next_page_token") or body.get("next_token")
            if not next_token:
                break
        return out

    # ----------------------- normalize --------------------------

    # Workflow execution outcome → AiSOC severity per the wave-1 rule.
    _EXECUTION_SEVERITY = {
        "success": "info",
        "completed": "info",
        "running": "info",
        "warning": "low",
        "warn": "low",
        "failed": "high",
        "error": "high",
        "killed": "high",
        "critical": "high",
    }

    # Audit operations that are always high-risk.
    _HIGH_RISK_AUDIT_OPS = (
        "workflow.deleted",
        "workflow.disabled",
        "credential.created",
        "credential.deleted",
        "credential.updated",
        "user.role_changed",
        "user.invited",
        "user.removed",
        "api_key.created",
        "api_key.revoked",
        "integration.created",
        "integration.deleted",
        "sso.disabled",
    )

    def _normalize_execution(self, raw: dict[str, Any]) -> dict[str, Any]:
        status = (raw.get("status") or raw.get("outcome") or "").lower()
        severity = self._EXECUTION_SEVERITY.get(status, "info")
        workflow_name = raw.get("workflow_name") or (raw.get("workflow") or {}).get("name") or "unknown"
        return {
            "source": self.connector_id,
            "external_id": f"torq-exec-{raw.get('id') or raw.get('execution_id', '')}",
            "title": f"Torq workflow: {workflow_name}",
            "description": (
                f"workflow={workflow_name}; "
                f"status={status}; "
                f"trigger={raw.get('trigger_type', 'unknown')}; "
                f"duration_ms={raw.get('duration_ms', '')}"
            ),
            "severity": severity,
            "actor": (raw.get("triggered_by") or {}).get("email") if isinstance(raw.get("triggered_by"), dict) else raw.get("triggered_by"),
            "actor_email": (raw.get("triggered_by") or {}).get("email") if isinstance(raw.get("triggered_by"), dict) else None,
            "src_ip": None,
            "event_type": f"torq.execution.{status or 'unknown'}",
            "raw_event": raw,
            "created_at": raw.get("started_at") or raw.get("created_at"),
        }

    def _normalize_audit(self, raw: dict[str, Any]) -> dict[str, Any]:
        op = raw.get("event_type") or raw.get("operation") or "torq.audit"
        actor_email = (raw.get("actor") or {}).get("email") if isinstance(raw.get("actor"), dict) else raw.get("actor_email")

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
            "external_id": f"torq-audit-{raw.get('id', '')}",
            "title": f"Torq audit: {op}",
            "description": (f"actor={actor_email or 'unknown'}; op={op}; resource={raw.get('resource_id', '')}"),
            "severity": severity,
            "actor": actor_email,
            "actor_email": actor_email,
            "src_ip": raw.get("source_ip"),
            "event_type": f"torq.{op}",
            "raw_event": raw,
            "created_at": raw.get("timestamp") or raw.get("created_at"),
        }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        stream = raw.get("_aisoc_stream", "execution")
        if stream == "audit_log":
            return self._normalize_audit(raw)
        return self._normalize_execution(raw)
