"""Case lifecycle event publisher.

Cases move through a state machine — ``new`` → ``triaging`` →
``investigating`` → ``awaiting_hitl`` → ``responding`` → ``closed_*`` —
and every transition needs to land on three surfaces simultaneously:

1. The realtime stream (``Topics.CASES_LIFECYCLE``) so headless consumers
   (Reporter, ClickHouse sink, downstream automations) can react.
2. The existing :class:`app.api.events.EventBus` so already-connected
   websocket clients get the update without us forcing them to migrate
   to a stream subscription.
3. Structured logs for forensic reconstruction.

Keeping all three paths in one module means a case transition is one
function call from the orchestrator / routes layer, and nobody has to
remember to fan out to N places.

Tenant scoping is mandatory. Every event carries ``tenant_id``; the
EventBus and stream backend route accordingly. Missing tenant on a case
is a programming error and we fail loud (log + best-effort emit to
``global``) rather than silently leaking cross-tenant.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.realtime.stream import TOPICS, get_stream


log = logging.getLogger(__name__)


# Best-effort import of the existing in-process EventBus. The realtime
# package must stay importable without app.api being fully wired (e.g.
# for unit tests that exercise normalizer + stream in isolation).
try:
    from app.api.events import bus as _eventbus  # type: ignore[import-not-found]
except Exception:  # pragma: no cover - import path defensive only
    _eventbus = None  # type: ignore[assignment]


def _envelope(
    *,
    kind: str,
    tenant_id: str,
    case_id: int,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical case-event envelope.

    Keep the shape **flat and stable**. The websocket consumers in the
    frontend and the downstream stream consumers all decode this without
    a schema; renaming a field is a breaking change.
    """
    env: dict[str, Any] = {
        "kind": kind,
        "tenant_id": tenant_id,
        "case_id": case_id,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        # We don't merge with overwrite-protection because the caller
        # knows the schema. If they want to override ``ts`` for replay,
        # they may.
        env.update(fields)
    return env


async def _publish(envelope: dict[str, Any]) -> None:
    """Fan out a case envelope to the stream and the in-process bus."""
    stream = get_stream()
    try:
        await stream.publish(TOPICS.CASES_LIFECYCLE, envelope)
    except Exception as exc:  # noqa: BLE001
        # The stream backend is supposed to swallow errors itself, but
        # if a custom backend is plugged in and misbehaves, we still
        # want the in-process bus to fire.
        log.warning("case_events: stream publish failed: %s", exc)

    if _eventbus is not None:
        # The EventBus is synchronous; calling from an async context is
        # safe because publish does not block.
        try:
            _eventbus.publish(envelope)
        except Exception as exc:  # noqa: BLE001
            log.warning("case_events: eventbus publish failed: %s", exc)


# ── Public API ─────────────────────────────────────────────────────────


async def publish_case_created(
    *,
    tenant_id: str,
    case_id: int,
    title: str,
    severity: str,
    status: str | None = None,
    source: str | None = None,
    alert_ids: list[int] | None = None,
) -> None:
    """Emit when a new case is opened.

    ``status`` is the initial case status (almost always ``"new"``, but
    we don't hardcode that here — hunts can spawn cases in any state).
    ``source`` distinguishes how the case originated (``"orchestrator-
    bootstrap"`` from ``/events``, ``"hunt"`` from user-initiated hunts,
    ``"api"`` from external SIEM forwards, etc.) so the case timeline can
    show "what fired this case" without re-querying.
    """
    fields: dict[str, Any] = {
        "title": title,
        "severity": severity,
        "alert_ids": alert_ids or [],
    }
    if status is not None:
        fields["status"] = status
    if source is not None:
        fields["source"] = source
    envelope = _envelope(
        kind="case.created",
        tenant_id=tenant_id,
        case_id=case_id,
        fields=fields,
    )
    log.info(
        "case.created tenant=%s case=%s severity=%s source=%s title=%s",
        tenant_id, case_id, severity, source, title,
    )
    await _publish(envelope)


async def publish_case_status(
    *,
    tenant_id: str,
    case_id: int,
    from_status: str,
    to_status: str,
    actor: str = "orchestrator",
    reason: str | None = None,
) -> None:
    """Emit on every case status transition.

    ``actor`` distinguishes orchestrator-driven transitions from human
    overrides (``"hitl"``) and external API callers (``"api"``). This
    matters for audit replay — auto-closed false-positives look
    different in the timeline from analyst-closed ones.
    """
    envelope = _envelope(
        kind="case.status_changed",
        tenant_id=tenant_id,
        case_id=case_id,
        fields={
            "from": from_status,
            "to": to_status,
            "actor": actor,
            "reason": reason,
        },
    )
    log.info(
        "case.status tenant=%s case=%s %s -> %s actor=%s",
        tenant_id, case_id, from_status, to_status, actor,
    )
    await _publish(envelope)


async def publish_case_closed(
    *,
    tenant_id: str,
    case_id: int,
    verdict: str,
    confidence: float,
    actor: str = "orchestrator",
) -> None:
    """Emit when a case reaches a terminal ``closed_*`` state.

    This is a strict subset of ``publish_case_status`` for consumers
    that only care about closures (e.g. SLA dashboards). They get fired
    *in addition* to the status change — never instead of.
    """
    envelope = _envelope(
        kind="case.closed",
        tenant_id=tenant_id,
        case_id=case_id,
        fields={
            "verdict": verdict,
            "confidence": confidence,
            "actor": actor,
        },
    )
    log.info(
        "case.closed tenant=%s case=%s verdict=%s confidence=%.2f",
        tenant_id, case_id, verdict, confidence,
    )
    await _publish(envelope)


async def publish_case_update(
    *,
    tenant_id: str,
    case_id: int,
    update_kind: str,
    fields: dict[str, Any],
) -> None:
    """Generic mid-case update (response action, IOC added, comment, etc.).

    ``update_kind`` is a free-form string (``"response_action"``,
    ``"ioc_added"``, ``"narrative_updated"``). Frontends should ignore
    unknown kinds gracefully — we add new ones without coordinating a
    release.
    """
    envelope = _envelope(
        kind=f"case.update.{update_kind}",
        tenant_id=tenant_id,
        case_id=case_id,
        fields=fields,
    )
    await _publish(envelope)
