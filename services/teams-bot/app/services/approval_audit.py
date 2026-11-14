"""Approval-trail audit sink for the AiSOC Teams bot.

**Vendored, byte-identical below this banner, from
``services/slack-bot/app/services/approval_audit.py``.** Same reasoning as
``cors.py``, ``service_auth.py`` and ``tenant_scope.py``: each service is
built with its own directory as its Docker context, so a sibling service's
source tree is not in the image and cannot be imported from it.

That is not a hypothetical. ``aisoc_clients.build_audit_sink`` used to locate
this module by walking ``Path(__file__).resolve().parents[3] / "slack-bot" /
...``, which resolves to ``<repo>/services/slack-bot/...`` in a checkout and
to ``/slack-bot/...`` inside the built image -- a path that does not exist.
So the sink fell back to ``_NullAuditSink`` and **approval decisions made
through Teams were not audited at all**, silently, in exactly the
configuration a customer runs, while every developer running from source saw
them recorded (GHSA-vf98-8367-45mp, F62).

``tests/test_inbound_auth_and_audit.py`` fails if the two copies drift.
"""

# --- vendored content ---
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

log = structlog.get_logger(__name__)


@dataclass(slots=True, frozen=True)
class ApprovalAuditEvent:
    """
    One immutable audit-trail row for an approval decision.

    Field naming intentionally matches ``services/api`` ``AuditLog`` columns
    (``actor_ip``, ``resource_id``) so the structlog event can be
    rehydrated into the API's audit table without a translation layer.
    """

    case_id: str
    action_id: str
    approver_id: str
    decision: str  # "approved" | "rejected" | "need_info" | "timeout_fallback"
    channel: str | None = None
    actor_ip: str | None = None
    source: str = "slack"  # "slack" | "teams" | "email" | "scheduler"
    error: str | None = None
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        """Render the event as a flat dict suitable for structlog / HTTP audit."""
        d: dict[str, Any] = {
            "case_id": self.case_id,
            "action_id": self.action_id,
            "approver_id": self.approver_id,
            "decision": self.decision,
            "channel": self.channel,
            "actor_ip": self.actor_ip,
            "source": self.source,
            "timestamp": self.timestamp,
        }
        if self.error:
            d["error"] = self.error
        if self.metadata:
            d["metadata"] = self.metadata
        return d


class ApprovalAuditSink(Protocol):
    """Anything that can swallow an :class:`ApprovalAuditEvent`."""

    async def record(self, event: ApprovalAuditEvent) -> None:  # pragma: no cover - protocol
        # Protocol stub body: ``pass`` rather than ``...`` to silence
        # CodeQL ``py/ineffectual-statement``.
        pass


class NullAuditSink:
    """No-op sink used when the caller doesn't care about audit (mostly tests)."""

    async def record(self, event: ApprovalAuditEvent) -> None:
        return None


class InMemoryAuditSink:
    """
    Test sink that appends every recorded event to ``events``.

    Used by the T3.6 test suite to assert that the approve/deny/need-info
    and timeout-fallback paths each land an audit row with the expected
    fields. Never mount this in production — it grows unbounded.
    """

    def __init__(self) -> None:
        self.events: list[ApprovalAuditEvent] = []

    async def record(self, event: ApprovalAuditEvent) -> None:
        self.events.append(event)


class StructlogAuditSink:
    """
    Production sink. Emits one ``aisoc.approval_decision`` structlog event
    per recorded :class:`ApprovalAuditEvent`. The event is then captured by
    the JSON log pipeline and surfaced in the audit export bundle on the
    API side.

    Catches every exception so a transient logger failure can never break
    the interactive Slack reply.
    """

    def __init__(self, logger: Any | None = None) -> None:
        self._log = logger or log

    async def record(self, event: ApprovalAuditEvent) -> None:
        try:
            self._log.info("aisoc.approval_decision", **event.as_dict())
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            self._log.error("aisoc.approval_decision_audit_failed", error=str(exc))
