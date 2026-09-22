"""AI gateway / MCP server runtime telemetry (pull side of the AI estate).

`llm_usage` covers the AI *control plane* — who minted an API key, who was made
an owner. This covers the runtime: which agents are calling which tools against
which resources, on whose behalf, and whether any guardrail objected.

Two ways telemetry arrives, and both land in the same OCSF shape:

* **Push**, via `aisoc-ai-sdk` posting spans to an inbox token with the
  `ai-runtime` / `ai-finding` templates. That is the low-friction path for an
  app the customer controls, and it needs no connector at all.
* **Pull**, this connector, for gateways that already aggregate AI traffic and
  expose a query API — LiteLLM, Portkey, Helicone, or an in-house proxy. An
  organisation that routes its models through a gateway gets coverage of every
  app behind it without instrumenting each one.

The pull path matters for the same reason an agentless scanner matters: the apps
you most need visibility into are the ones nobody will retrofit an SDK into.

Severity is derived, not trusted. A gateway reports usage; it has no opinion
about security. So a guardrail violation or a blocked request is raised here,
while routine completions stay `info` and are archived to the lake rather than
alerted on — the same routine/finding split the OCSF profiles encode.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 200
_TIMEOUT = 30.0

#: Gateway outcome values that mean something refused the request. These are
#: the reason to pull at all: a gateway that blocked a call already made a
#: security decision, and the SOC should see it.
_BLOCKED_OUTCOMES = frozenset({"blocked", "denied", "rejected", "filtered", "guardrail_violation"})

#: Finding types the `ai-*` detection rules match on. Kept as a constant so the
#: mapping below and the specs in
#: `scripts/detection_specs_part3_application.py` cannot drift apart silently.
_FINDING_PROMPT_INJECTION = "prompt_injection"
_FINDING_UNAPPROVED_MODEL = "unapproved_model"
_FINDING_SENSITIVE_EGRESS = "sensitive_data_egress"


class AIGatewayConnector(BaseConnector):
    """LLM gateway / MCP server request logs."""

    connector_id = "ai_gateway"
    connector_name = "AI Gateway / MCP Runtime"
    connector_category = "ai"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        approved_models: str = "",
        verify_tls: bool = True,
        **_: Any,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        # Comma-separated, because the connector config UI collects a string.
        # An empty list means "do not judge", not "nothing is approved" — a
        # connector that alerted on every model until someone filled in a form
        # would be turned off within the hour.
        self._approved = {m.strip().lower() for m in approved_models.split(",") if m.strip()}
        self._verify_tls = verify_tls

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull request logs from an LLM gateway or MCP server (LiteLLM, Portkey, "
                "Helicone, or an in-house proxy) to see which agents call which tools and "
                "models, on whose behalf. Covers every app behind the gateway without "
                "instrumenting each one. For apps you control, the aisoc-ai-sdk push path "
                "is lower friction."
            ),
            docs_url="/docs/connectors/ai_gateway",
            capabilities=(Capability.PULL_ALERTS, Capability.PULL_AUDIT),
            fields=[
                Field("base_url", "string", "Gateway base URL", placeholder="https://llm-gateway.internal"),
                Field("api_key", "secret", "Gateway API key"),
                Field(
                    "approved_models",
                    "string",
                    "Approved models (comma-separated)",
                    required=False,
                    placeholder="gpt-4o, claude-sonnet-4, llama-3.3-70b",
                    help_text=(
                        "Any model outside this list raises an unapproved_model finding. "
                        "Leave blank to disable the check rather than flag everything."
                    ),
                ),
                Field(
                    "verify_tls",
                    "boolean",
                    "Verify TLS certificate",
                    required=False,
                    default=True,
                    help_text="Disable only for an internal gateway using a private CA.",
                ),
            ],
        )

    # ── connectivity ──────────────────────────────────────────────────────

    async def test_connection(self) -> dict[str, Any]:
        if not self._base_url or not self._api_key:
            return {"success": False, "message": "base_url and api_key are both required"}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self._verify_tls) as client:
                resp = await client.get(
                    f"{self._base_url}/v1/models",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
        except httpx.HTTPError as exc:
            return {"success": False, "message": f"could not reach the gateway: {exc}"}
        if resp.status_code in (401, 403):
            return {"success": False, "message": "gateway rejected the API key"}
        if resp.status_code >= 400:
            return {"success": False, "message": f"gateway returned HTTP {resp.status_code}"}
        return {"success": True, "message": "connected to the AI gateway"}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, verify=self._verify_tls) as client:
                resp = await client.get(
                    f"{self._base_url}/v1/logs",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    params={"since_seconds": since_seconds, "limit": _LIMIT},
                )
                resp.raise_for_status()
                body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("ai_gateway.fetch_failed", error=str(exc))
            return []

        rows = body.get("data") or body.get("logs") or body if isinstance(body, list) else body.get("data") or []
        if not isinstance(rows, list):
            return []
        return [self.normalize(row) for row in rows if isinstance(row, dict)]

    # ── normalization ─────────────────────────────────────────────────────

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Fold a gateway log row into the canonical envelope.

        Emits `raw_event` (not `raw`), which is what the ingest normalizer's
        `isCanonicalEnvelope` check looks for and what the detection engine
        merges into its match namespace.
        """
        model = str(raw.get("model") or raw.get("model_name") or "")
        outcome = str(raw.get("status") or raw.get("outcome") or "success").lower()
        agent_id = str(raw.get("agent_id") or raw.get("user") or raw.get("api_key_alias") or "unknown-agent")
        tool_name = str(raw.get("tool") or raw.get("tool_name") or (f"model:{model}" if model else "unknown"))

        finding_type = self._finding_type(raw, model, outcome)
        severity = self._severity(finding_type, outcome)

        event: dict[str, Any] = {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": severity,
            "title": self._title(finding_type, tool_name, model, agent_id),
            "description": (f"agent={agent_id}; tool={tool_name}; model={model or 'n/a'}; outcome={outcome}"),
            "external_id": str(raw.get("id") or raw.get("request_id") or ""),
            "created_at": raw.get("timestamp") or raw.get("created_at") or raw.get("start_time"),
            # Flat fields the ai-* detection rules match on.
            "agent_id": agent_id,
            "agent_name": raw.get("agent_name") or agent_id,
            "tool_name": tool_name,
            "model": model,
            "provider": raw.get("provider") or raw.get("custom_llm_provider"),
            "server_name": raw.get("server_name") or raw.get("gateway"),
            "on_behalf_of": raw.get("end_user") or raw.get("on_behalf_of"),
            "outcome": outcome,
            "prompt_tokens": raw.get("prompt_tokens"),
            "completion_tokens": raw.get("completion_tokens"),
            "latency_ms": raw.get("latency_ms") or raw.get("duration_ms"),
            "session_id": raw.get("session_id") or raw.get("trace_id"),
            "raw_event": raw,
        }
        if finding_type:
            event["finding_type"] = finding_type
        return event

    def _finding_type(self, raw: dict[str, Any], model: str, outcome: str) -> str | None:
        """Classify a row, or None when it is routine activity.

        Ordered by seriousness rather than by how the gateway labelled it: a
        row can be both blocked and on an unapproved model, and the injection
        signal is the one an analyst needs first.
        """
        flagged = str(raw.get("guardrail") or raw.get("violation") or "").lower()
        if "injection" in flagged or bool(raw.get("prompt_injection")):
            return _FINDING_PROMPT_INJECTION
        if "pii" in flagged or "dlp" in flagged or "sensitive" in flagged:
            return _FINDING_SENSITIVE_EGRESS
        if self._approved and model and model.lower() not in self._approved:
            return _FINDING_UNAPPROVED_MODEL
        if outcome in _BLOCKED_OUTCOMES:
            # Something refused this and did not say why. Worth surfacing as a
            # denial rather than inventing a more specific finding type.
            return None
        return None

    @staticmethod
    def _severity(finding_type: str | None, outcome: str) -> str:
        if finding_type == _FINDING_SENSITIVE_EGRESS:
            return "critical"
        if finding_type == _FINDING_PROMPT_INJECTION:
            return "high"
        if finding_type == _FINDING_UNAPPROVED_MODEL:
            return "medium"
        if outcome in _BLOCKED_OUTCOMES:
            return "low"
        # Routine completions. Archived to the lake and hunted, not alerted on:
        # an agent doing its job is not an incident.
        return "info"

    @staticmethod
    def _title(finding_type: str | None, tool_name: str, model: str, agent_id: str) -> str:
        if finding_type == _FINDING_PROMPT_INJECTION:
            return f"Prompt injection flagged for agent {agent_id}"
        if finding_type == _FINDING_SENSITIVE_EGRESS:
            return f"Sensitive data flagged leaving via agent {agent_id}"
        if finding_type == _FINDING_UNAPPROVED_MODEL:
            return f"Agent {agent_id} used unapproved model {model}"
        return f"AI activity: {tool_name} by {agent_id}"
