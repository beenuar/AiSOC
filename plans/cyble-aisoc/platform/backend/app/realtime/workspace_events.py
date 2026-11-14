"""Workspace op publisher (Theme 2l).

Workspace ops (``note.append``, ``mention``, ``agent.started`` …) need
to reach two surfaces:

1. The in-process :class:`app.api.events.EventBus` so already-subscribed
   websocket clients receive the op without a round-trip to the DB.
2. The :class:`app.realtime.stream.StreamBackend` so out-of-process
   subscribers (other workers, future Kafka consumers) get a copy.

This module is the single place we marshal an op into the wire
envelope. The shape mirrors the case-events envelope on purpose — the
frontend uses one websocket connection and demultiplexes by ``kind``.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.realtime.stream import TOPICS, get_stream

log = logging.getLogger(__name__)


try:
    from app.api.events import bus as _eventbus  # type: ignore[import-not-found]
except Exception:  # pragma: no cover
    _eventbus = None  # type: ignore[assignment]


def _envelope(
    *,
    tenant_id: str,
    case_id: int,
    op: dict[str, Any],
) -> dict[str, Any]:
    """Wrap an op dict in the canonical envelope.

    ``kind`` is fixed to ``workspace.op`` so frontends switch once on
    the outer kind and then on ``op["kind"]`` for sub-dispatch. We
    deliberately do *not* flatten ``op`` into the envelope — it would
    collide with case-event field names like ``ts`` and ``case_id``.
    """
    return {
        "kind": "workspace.op",
        "tenant_id": tenant_id,
        "case_id": case_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "op": op,
    }


async def publish_workspace_op(
    *,
    tenant_id: str,
    case_id: int,
    op: dict[str, Any],
) -> None:
    """Broadcast a workspace op to bus + stream.

    ``op`` is the serialized :class:`WorkspaceOp` (id, seq, kind,
    payload, author_*, client_op_id, created_at). Callers should build
    this via :func:`app.workspace.service.serialize_op` so the shape
    stays consistent.
    """
    env = _envelope(tenant_id=tenant_id, case_id=case_id, op=op)
    try:
        stream = get_stream()
        # Reuse the case lifecycle topic — workspace ops are case-scoped
        # and downstream consumers already filter by ``kind``. A second
        # topic would just fragment subscribers without benefit.
        await stream.publish(TOPICS.CASES_LIFECYCLE, env)
    except Exception as exc:  # noqa: BLE001
        log.warning("workspace_events: stream publish failed: %s", exc)

    if _eventbus is not None:
        try:
            _eventbus.publish(env)
        except Exception as exc:  # noqa: BLE001
            log.warning("workspace_events: eventbus publish failed: %s", exc)
