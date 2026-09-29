"""The operator door onto a dead-letter replay (deferral 5b).

``services/fusion`` executes the replay, because it owns the three things a
safe one needs in one place: the topic, the producer, and the validator that
refused the messages. This module is the half that belongs to the API —
authorisation, the tenant session, and the durable record of the action —
which is the same split ``siem_writeback`` and the playbook action bridge
already use, for the same reason: the API holds the credential and the
session, the other service holds the domain.

What this adds over a plain proxy
---------------------------------
**A row before the call, not after.** ``aisoc_dlq_replays`` is written with
``status = 'queued'`` before fusion is contacted and updated when it answers.
A replay that starts and never returns leaves evidence that it started; a row
written only on success would make the interesting case — the one that
hung — the invisible one.

**Dry run unless asked otherwise, at this layer too.** The default is
``execute=False`` here, in the request model, and in fusion. Three defaults
rather than one because the dangerous direction is a caller who omits the
field, and each layer has a different caller.

**The bound restated.** :data:`MAX_REPLAY_MESSAGES` is checked here as well
as by fusion and by a CHECK constraint in migration 075. A bound that lives
only in a request model is a bound a service-to-service caller skips.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

import httpx
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.dlq_replay")

#: Mirrors ``services/fusion/app/services/dlq_replay.MAX_REPLAY_MESSAGES`` and
#: the CHECK constraint in migration 075.
MAX_REPLAY_MESSAGES = 1000

_TENANT_HEADER = "X-AiSOC-Tenant-ID"

#: A replay reads up to a thousand messages and may produce them. It is
#: slower than an entity-risk lookup and must not be cut off mid-flight,
#: because a timed-out replay leaves an operator unable to say what was
#: produced.
_REPLAY_TIMEOUT_SECONDS = 120.0


class DlqReplayRequest(BaseModel):
    """An explicit, bounded range of refused messages to re-check."""

    topic: str = Field(min_length=1, max_length=200)
    partition: int = Field(ge=0)
    start_offset: int = Field(ge=0)
    max_messages: int = Field(default=100, ge=1, le=MAX_REPLAY_MESSAGES)
    execute: bool = False


class DlqReplayResponse(BaseModel):
    """What the replay found, and what it did about it."""

    replay_id: uuid.UUID
    status: str
    executed: bool

    messages_read: int = 0
    #: How many would pass the validation that refused them. On a dry run
    #: this is the whole answer: it is the operator's evidence that the cause
    #: is fixed, before anything is produced.
    would_pass: int = 0
    #: How many still fail, and were therefore refused a second time rather
    #: than replayed into the consumer that refused them first.
    refused: int = 0
    produced: int = 0

    refusals: dict[str, int] = Field(default_factory=dict)
    produced_offsets: list[int] = Field(default_factory=list)
    error: str | None = None


def _fusion_url() -> str:
    return (os.getenv("FUSION_SERVICE_URL") or os.getenv("FUSION_URL") or "").rstrip("/")


def _headers(tenant_id: uuid.UUID) -> dict[str, str]:
    headers = {_TENANT_HEADER: str(tenant_id)}
    token = (os.getenv("AISOC_FUSION_SERVICE_TOKEN") or os.getenv("AISOC_SERVICE_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


_INSERT = text(
    """
    INSERT INTO aisoc_dlq_replays
        (tenant_id, topic, topic_partition, start_offset, max_messages, executed, requested_by)
    VALUES (:tenant_id, :topic, :partition, :start_offset, :max_messages, :executed, :requested_by)
    RETURNING id
    """
)

_COMPLETE = text(
    """
    UPDATE aisoc_dlq_replays
       SET status = :status, messages_read = :messages_read, would_pass = :would_pass,
           refused = :refused, produced = :produced, error = :error, completed_at = now()
     WHERE id = :id AND tenant_id = :tenant_id
    """
)


async def run_replay(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    requested_by: uuid.UUID | None,
    request: DlqReplayRequest,
) -> DlqReplayResponse:
    """Record the request, ask fusion to run it, record the outcome."""
    replay_id = (
        await db.execute(
            _INSERT,
            {
                "tenant_id": str(tenant_id),
                "topic": request.topic,
                "partition": request.partition,
                "start_offset": request.start_offset,
                "max_messages": request.max_messages,
                "executed": request.execute,
                "requested_by": str(requested_by) if requested_by else None,
            },
        )
    ).scalar_one()
    # Committed before the call, deliberately: the evidence that a replay was
    # attempted must survive the attempt failing.
    await db.commit()

    base = _fusion_url()
    if not base:
        return await _fail(
            db,
            replay_id,
            tenant_id,
            request,
            "FUSION_SERVICE_URL is not set, so there is no service to run the replay. "
            "This is a configuration gap, not an empty dead-letter queue.",
        )

    payload: dict[str, Any] = {
        "topic": request.topic,
        "partition": request.partition,
        "start_offset": request.start_offset,
        "max_messages": request.max_messages,
        "execute": request.execute,
    }
    try:
        async with httpx.AsyncClient(timeout=_REPLAY_TIMEOUT_SECONDS) as client:
            resp = await client.post(f"{base}/dlq/replay", json=payload, headers=_headers(tenant_id))
    except httpx.HTTPError as exc:
        return await _fail(db, replay_id, tenant_id, request, f"fusion unreachable: {type(exc).__name__}")

    if resp.status_code >= 400:
        detail = resp.text[:500].replace("\r", "").replace("\n", " ")
        return await _fail(db, replay_id, tenant_id, request, f"fusion refused the replay (HTTP {resp.status_code}): {detail}")

    body = resp.json()
    await db.execute(
        _COMPLETE,
        {
            "id": replay_id,
            "tenant_id": str(tenant_id),
            "status": "completed",
            "messages_read": int(body.get("messages_read") or 0),
            "would_pass": int(body.get("would_pass") or 0),
            "refused": int(body.get("refused") or 0),
            "produced": int(body.get("produced") or 0),
            "error": None,
        },
    )
    await db.commit()

    return DlqReplayResponse(
        replay_id=replay_id,
        status="completed",
        executed=bool(body.get("executed")),
        messages_read=int(body.get("messages_read") or 0),
        would_pass=int(body.get("would_pass") or 0),
        refused=int(body.get("refused") or 0),
        produced=int(body.get("produced") or 0),
        refusals=dict(body.get("refusals") or {}),
        produced_offsets=list(body.get("produced_offsets") or []),
    )


async def _fail(
    db: AsyncSession,
    replay_id: uuid.UUID,
    tenant_id: uuid.UUID,
    request: DlqReplayRequest,
    reason: str,
) -> DlqReplayResponse:
    """Record a replay that could not run, and say why rather than returning zeros.

    A failed replay reporting ``produced: 0`` and nothing else is
    indistinguishable from a successful one that found nothing to do — which
    is the reading that would let an operator believe the queue was drained.
    """
    await db.execute(
        _COMPLETE,
        {
            "id": replay_id,
            "tenant_id": str(tenant_id),
            "status": "failed",
            "messages_read": 0,
            "would_pass": 0,
            "refused": 0,
            "produced": 0,
            "error": reason[:2000],
        },
    )
    await db.commit()
    logger.warning("dlq_replay failed: %s", reason.replace("\r", "").replace("\n", " ")[:300])
    return DlqReplayResponse(replay_id=replay_id, status="failed", executed=request.execute, error=reason)


__all__ = ["MAX_REPLAY_MESSAGES", "DlqReplayRequest", "DlqReplayResponse", "run_replay"]
