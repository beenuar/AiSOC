"""
Falco connector.

Falco is the CNCF runtime detection engine for Linux / Kubernetes.
There are two common shapes for ingesting Falco events:

1. **falcosidekick HTTP output** — falcosidekick is the de-facto
   forwarder that sits next to Falco, receives the rule-engine output,
   and fans it out to dozens of sinks. AiSOC ships an inbound webhook
   that accepts the standard falcosidekick JSON envelope (a JSON list
   of rule hits, each with ``rule``, ``priority``, ``output``,
   ``output_fields``, ``time``, ``hostname``).

2. **Falco HTTP output plugin** — Falco itself can POST events directly.
   The payload shape is identical to falcosidekick's "alerta" output
   minus a couple of fields. We accept either.

Because the source is push-driven, the connector implements a small
``fetch_alerts()`` polling path that drains an in-memory webhook
buffer. In production the buffer is replaced by a real receiver
(Redis Stream / SQS), but the contract — "give me the last N rule
hits and let me normalise them" — is the same.

The connector also exposes a ``verify_webhook()`` helper that the
inbound webhook endpoint uses to validate the optional shared-secret
header (``X-Falco-Secret``).
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()


class FalcoConnector(BaseConnector):
    """Falco runtime security events (Linux / Kubernetes)."""

    connector_id = "falco"
    connector_name = "Falco"
    # The wave-1 task brief calls for ``siem`` so the registry stays
    # tight; Falco lives next to the SIEM stream conceptually because
    # it produces a continuous rule-based event firehose.
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Falco runtime security events for Linux and Kubernetes. Receives "
                "JSON rule hits over HTTP, either from falcosidekick or from Falco's "
                "built-in HTTP output plugin. Optionally validates a shared-secret "
                "header on each delivery."
            ),
            docs_url="/docs/connectors/falco",
            fields=[
                Field(
                    "webhook_path",
                    "string",
                    "Webhook path",
                    default="/v1/webhooks/falco",
                    placeholder="/v1/webhooks/falco",
                    help_text=("Path on the AiSOC ingest service where Falco / falcosidekick should POST events."),
                ),
                Field(
                    "shared_secret",
                    "secret",
                    "Shared secret (optional)",
                    required=False,
                    help_text=("If set, each incoming request must include the matching value in the X-Falco-Secret header."),
                ),
                Field(
                    "minimum_priority",
                    "select",
                    "Minimum priority",
                    required=False,
                    default="DEBUG",
                    options=[
                        {"value": "DEBUG", "label": "DEBUG (everything)"},
                        {"value": "INFORMATIONAL", "label": "INFORMATIONAL"},
                        {"value": "NOTICE", "label": "NOTICE"},
                        {"value": "WARNING", "label": "WARNING"},
                        {"value": "ERROR", "label": "ERROR"},
                        {"value": "CRITICAL", "label": "CRITICAL"},
                        {"value": "ALERT", "label": "ALERT"},
                        {"value": "EMERGENCY", "label": "EMERGENCY"},
                    ],
                    help_text=(
                        "Drop events whose Falco priority is below this threshold. Defaults to DEBUG so nothing is filtered server-side."
                    ),  # noqa: E501
                ),
            ],
            oauth=OAuthHints(supported_in_hosted=False),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PULL_LOGS)

    def __init__(self, webhook_path: str = "/v1/webhooks/falco", shared_secret: str | None = None, minimum_priority: str = "DEBUG"):
        self._webhook_path = webhook_path or "/v1/webhooks/falco"
        self._shared_secret = (shared_secret or "").strip() or None
        self._minimum_priority = (minimum_priority or "DEBUG").upper()
        # In-memory ring buffer of recent rule hits. The webhook handler
        # ``POST``s into this list; ``fetch_alerts()`` drains it. In a
        # real deployment this is replaced by a durable queue, but the
        # contract — produce-once-consume-once — is identical.
        self._buffer: list[dict[str, Any]] = []

    # --------------------------- webhook --------------------------

    def verify_webhook(self, headers: dict[str, str] | None) -> bool:
        """Constant-time compare of the optional ``X-Falco-Secret`` header.

        Returns True when no secret is configured (open mode) OR the
        header value matches. ``headers`` is a case-insensitive-ish
        mapping; we look for both the exact and lower-case variants
        because httpx and Starlette disagree on which one they pass.
        """
        if not self._shared_secret:
            return True
        if not headers:
            return False
        provided = headers.get("X-Falco-Secret") or headers.get("x-falco-secret") or ""
        return hmac.compare_digest(provided, self._shared_secret)

    def ingest_webhook(self, payload: dict[str, Any] | list[dict[str, Any]]) -> int:
        """Append events from a single webhook delivery to the buffer.

        Falcosidekick batches events into a list; the built-in Falco
        HTTP output sends a single event. We accept either.

        Returns the number of events queued.
        """
        if isinstance(payload, list):
            events = payload
        else:
            events = [payload]

        before = len(self._buffer)
        for ev in events:
            if not isinstance(ev, dict):
                continue
            self._buffer.append(ev)
        return len(self._buffer) - before

    # ------------------------- contract -------------------------

    async def test_connection(self) -> dict[str, Any]:
        # Falco is push-driven; "connection" is really "is the webhook
        # configured?". We report success unconditionally with the path
        # so the operator can verify it round-trips in the UI.
        return {
            "success": True,
            "connector": self.connector_id,
            "webhook_path": self._webhook_path,
            "secret_configured": bool(self._shared_secret),
            "minimum_priority": self._minimum_priority,
            "buffered_events": len(self._buffer),
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Pagination contract: drain the buffer until empty. The
        # ``since_seconds`` argument is honoured by filtering on the
        # ``time`` field in the Falco envelope (RFC3339).
        if not self._buffer:
            return []

        now = datetime.now(UTC)
        # Drain the buffer atomically so concurrent webhook deliveries
        # don't see partial state. Python's list.swap is GIL-protected.
        drained, self._buffer = self._buffer, []

        out: list[dict[str, Any]] = []
        for raw in drained:
            # Priority floor filter — applied here rather than in
            # normalize() so dropped events don't pay the dict-build cost.
            if not self._priority_passes(raw.get("priority", "DEBUG")):
                continue
            # Age filter — events older than the window are dropped.
            # ``time`` is RFC3339 in falcosidekick's envelope.
            ev_time = raw.get("time") or raw.get("output_time")
            if ev_time and isinstance(ev_time, str):
                try:
                    parsed = datetime.fromisoformat(ev_time.replace("Z", "+00:00"))
                    age = (now - parsed).total_seconds()
                    if age > since_seconds:
                        continue
                except ValueError:
                    pass  # unparseable timestamp → keep, don't silently drop
            out.append(self.normalize(raw))

        return out

    def _priority_passes(self, priority: str) -> bool:
        order = (
            "DEBUG",
            "INFORMATIONAL",
            "INFO",
            "NOTICE",
            "WARNING",
            "WARN",
            "ERROR",
            "CRITICAL",
            "ALERT",
            "EMERGENCY",
        )
        # Normalise: Falco sometimes spells INFORMATIONAL "Info".
        norm_floor = self._minimum_priority.upper()
        norm_event = (priority or "DEBUG").upper()
        if norm_floor in order and norm_event in order:
            return order.index(norm_event) >= order.index(norm_floor)
        return True  # unknown priority → don't drop

    # ----------------------- normalize --------------------------

    # Falco's priority ladder follows syslog severities. Wave-1 mapping:
    _PRIORITY_SEVERITY = {
        "EMERGENCY": "high",
        "ALERT": "high",
        "CRITICAL": "high",
        "ERROR": "medium",
        "WARNING": "low",
        "WARN": "low",
        "NOTICE": "info",
        "INFO": "info",
        "INFORMATIONAL": "info",
        "DEBUG": "info",
    }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        priority = (raw.get("priority") or "INFORMATIONAL").upper()
        severity = self._PRIORITY_SEVERITY.get(priority, "info")

        rule = raw.get("rule") or "Falco rule"
        output = raw.get("output") or ""
        fields = raw.get("output_fields") or {}

        # Best-effort identity extraction from common Falco rule fields.
        # ``user.name`` is set by container / process rules; ``k8s.ns.name``
        # is set by every K8s-aware rule.
        user = fields.get("user.name") or fields.get("user")
        hostname = raw.get("hostname") or fields.get("container.name") or fields.get("k8s.pod.name")
        namespace = fields.get("k8s.ns.name")
        container = fields.get("container.id") or fields.get("container.name")

        event_id = raw.get("uuid") or raw.get("id") or f"{raw.get('time', '')}-{rule}"

        return {
            "source": self.connector_id,
            "external_id": f"falco-{event_id}",
            "title": f"Falco: {rule}",
            "description": output[:500],
            "severity": severity,
            "actor": user,
            "actor_email": None,
            "src_ip": fields.get("fd.cip") or fields.get("fd.rip"),
            "hostname": hostname,
            "namespace": namespace,
            "container_id": container,
            "event_type": f"falco.{rule.lower().replace(' ', '_')}",
            "raw_event": raw,
            "created_at": raw.get("time") or raw.get("output_time"),
        }
