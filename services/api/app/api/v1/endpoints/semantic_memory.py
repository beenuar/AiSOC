"""Semantic memory: recall with provenance, and the conflicts before it.

Depth plan 9.2 (parity 6.5).

Routes:

* ``POST   /memory/items``            ingest or correct one item
* ``GET    /memory/items``            list, filtered by kind and state
* ``POST   /memory/recall``           vector recall, every hit with provenance
* ``GET    /memory/conflicts``        what an analyst has to settle
* ``POST   /memory/conflicts/{id}/resolve``  settle one
* ``DELETE /memory/items/{id}``       retire one (never a hard delete)
* ``GET    /memory/status``           can this deployment recall at all

Why ingest can *create* a conflict rather than overwrite
---------------------------------------------------------
Two items with the same ``(kind, subject)`` and different content are two
claims about the same thing. The cheap behaviour is last-write-wins, and it
is wrong in the case the feature exists for: an analyst corrects an entry an
agent got wrong, and an hour later the job that produced the wrong one runs
again. Last-write-wins silently restores the error, and the agent then cites
it. So a contradiction suspends **both** sides and asks a human.

An ingest that carries the same content hash is not a contradiction -- it is
the same claim arriving twice -- and is idempotent.

Why retirement is not deletion
------------------------------
A memory item is something the agent was told, so "what did it know when it
decided that" has to stay answerable after somebody decides the item was
wrong. Retiring sets ``state='not_in_use'`` and drops the vector; the row
and its provenance stay.

Honest unavailability
---------------------
Recall needs an embedding backend and a reachable Qdrant. Where either is
missing the route answers **503 with the reason**, and ``/memory/status``
says which. It does not fall back to full-text and present the result as
semantic recall, and it does not return an empty list -- "we searched and
found nothing" and "we could not search" are different facts and the console
renders them differently.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.semantic_memory import MEMORY_KINDS, MemoryItem
from app.services.audit import emit_audit
from app.services.semantic_memory import (
    EmbeddingsUnavailable,
    VectorStoreUnavailable,
    content_hash,
    forget_item,
    index_item,
)
from app.services.semantic_memory import search as vector_search
from app.services.semantic_memory import status as memory_status

logger = structlog.get_logger()

router = APIRouter(prefix="/memory", tags=["semantic-memory"])


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class MemoryItemIn(BaseModel):
    kind: str = Field(description="case | runbook | memory")
    subject: str = Field(min_length=1, max_length=400)
    content: str = Field(min_length=1, max_length=200_000)
    title: str = Field(default="", max_length=400)
    source_ref: str = Field(default="", max_length=400)
    #: Provenance the caller can state. ``author`` defaults to the
    #: authenticated principal below rather than being trusted from the body:
    #: an author a caller can set is not provenance.
    source: str = Field(default="analyst", max_length=60)
    scope: str = Field(default="tenant")
    expires_at: datetime | None = None


class MemoryItemOut(BaseModel):
    id: str
    kind: str
    subject: str
    title: str
    content: str
    source_ref: str
    author: str
    source: str
    scope: str
    state: str
    state_reason: str
    conflicts_with: str | None
    expires_at: datetime | None
    embedding_model: str | None
    embedded_at: datetime | None
    created_at: datetime
    updated_at: datetime


class MemoryIngestResult(BaseModel):
    item: MemoryItemOut
    #: ``created`` | ``unchanged`` | ``conflict``. Named rather than inferred
    #: from the state, because "I stored it" and "I suspended it and the one
    #: it disagrees with" need different words in a console.
    outcome: str
    indexed: bool
    #: Why the vector was not written, when it was not. Never silent.
    index_error: str | None = None


class MemoryRecallIn(BaseModel):
    query: str = Field(min_length=1, max_length=4_000)
    kinds: list[str] = Field(default_factory=list)
    limit: int = Field(default=5, ge=1, le=50)


class MemoryRecallHit(BaseModel):
    item: MemoryItemOut
    score: float


class MemoryConflictOut(BaseModel):
    left: MemoryItemOut
    right: MemoryItemOut | None


class MemoryConflictResolution(BaseModel):
    #: Which of the two to keep. The other is retired.
    keep: str
    note: str = Field(default="", max_length=500)


def _out(row: MemoryItem) -> MemoryItemOut:
    return MemoryItemOut(
        id=str(row.id),
        kind=row.kind,
        subject=row.subject,
        title=row.title,
        content=row.content,
        source_ref=row.source_ref,
        author=row.author,
        source=row.source,
        scope=row.scope,
        state=row.state,
        state_reason=row.state_reason,
        conflicts_with=str(row.conflicts_with) if row.conflicts_with else None,
        expires_at=row.expires_at,
        embedding_model=row.embedding_model,
        embedded_at=row.embedded_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


@router.post("/items", response_model=MemoryIngestResult, status_code=status.HTTP_201_CREATED)
async def ingest_item(
    body: MemoryItemIn,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
) -> MemoryIngestResult:
    if body.kind not in MEMORY_KINDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"kind must be one of {list(MEMORY_KINDS)}",
        )
    if body.scope not in ("tenant", "global"):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="scope must be tenant or global")

    digest = content_hash(body.content)
    # The author is the authenticated principal, never the body. Provenance a
    # caller can set is not provenance.
    author = current_user.api_key_prefix or current_user.email

    existing = (
        await db.execute(
            select(MemoryItem).where(
                MemoryItem.tenant_id == current_user.tenant_id,
                MemoryItem.kind == body.kind,
                MemoryItem.subject == body.subject,
                MemoryItem.state == "in_use",
            )
        )
    ).scalar_one_or_none()

    if existing is not None and existing.content_hash == digest:
        # The same claim arriving twice. Idempotent, and deliberately does not
        # re-embed: that would spend an embedding call per re-ingest on a
        # vector that cannot change.
        return MemoryIngestResult(item=_out(existing), outcome="unchanged", indexed=True)

    row = MemoryItem(
        tenant_id=current_user.tenant_id,
        kind=body.kind,
        subject=body.subject,
        source_ref=body.source_ref,
        title=body.title or body.subject,
        content=body.content,
        content_hash=digest,
        author=author,
        source=body.source,
        scope=body.scope,
        expires_at=body.expires_at,
        state="in_use",
    )

    outcome = "created"
    if existing is not None:
        # A contradiction. Both sides are suspended; see the module header for
        # why the newer one does not simply win.
        outcome = "conflict"
        row.state = "conflict"
        row.state_reason = f"Contradicts {existing.id}, which makes a different claim about {body.subject!r}."
        existing.state = "conflict"
        existing.state_reason = row.state_reason.replace(str(existing.id), "the newly ingested item")
        existing.updated_at = datetime.now(UTC)

    db.add(row)
    await db.flush()
    if existing is not None:
        row.conflicts_with = existing.id
        existing.conflicts_with = row.id
        # The suspended item must stop being recalled immediately, so its
        # point goes now rather than on a sweep.
        await forget_item(existing.id)

    indexed = False
    index_error: str | None = None
    if row.state == "in_use":
        try:
            model = await index_item(
                tenant_id=current_user.tenant_id,
                item_id=row.id,
                kind=row.kind,
                subject=row.subject,
                title=row.title,
                content=row.content,
                state=row.state,
            )
            row.embedding_model = model
            row.embedded_at = datetime.now(UTC)
            indexed = True
        except (EmbeddingsUnavailable, VectorStoreUnavailable) as exc:
            # Stored, not indexed, and the response says so. Silently
            # storing an unindexed row produces a memory that exists and is
            # never recalled, which is worse than a visible failure.
            index_error = str(exc)
            logger.warning("semantic_memory.index_failed", item_id=str(row.id), error=str(exc))

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="memory:ingest",
        resource="memory_item",
        resource_id=str(row.id),
        changes={"kind": row.kind, "subject": row.subject, "outcome": outcome, "indexed": indexed},
        request=request,
    )
    await db.commit()
    await db.refresh(row)
    return MemoryIngestResult(item=_out(row), outcome=outcome, indexed=indexed, index_error=index_error)


@router.get("/items", response_model=list[MemoryItemOut])
async def list_items(
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:read"))],
    kind: str | None = Query(default=None),
    state: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[MemoryItemOut]:
    stmt = select(MemoryItem).where(MemoryItem.tenant_id == current_user.tenant_id).order_by(MemoryItem.updated_at.desc()).limit(limit)
    if kind:
        stmt = stmt.where(MemoryItem.kind == kind)
    if state:
        stmt = stmt.where(MemoryItem.state == state)
    return [_out(row) for row in (await db.execute(stmt)).scalars().all()]


@router.delete("/items/{item_id}", response_model=MemoryItemOut)
async def retire_item(
    item_id: uuid.UUID,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
    reason: str = Query(default=""),
) -> MemoryItemOut:
    """Retire, never hard-delete. 'What did the agent know' must stay answerable."""
    row = (
        await db.execute(
            select(MemoryItem).where(
                MemoryItem.id == item_id,
                MemoryItem.tenant_id == current_user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such memory item")
    row.state = "not_in_use"
    row.state_reason = reason or "retired"
    row.updated_at = datetime.now(UTC)
    await forget_item(row.id)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="memory:retire",
        resource="memory_item",
        resource_id=str(row.id),
        changes={"reason": row.state_reason},
        request=request,
    )
    await db.commit()
    await db.refresh(row)
    return _out(row)


# ---------------------------------------------------------------------------
# Recall
# ---------------------------------------------------------------------------


@router.post("/recall", response_model=list[MemoryRecallHit])
async def recall(
    body: MemoryRecallIn,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("knowledge_base:read"))],
) -> list[MemoryRecallHit]:
    """Vector recall over this tenant's memory. Every hit carries its provenance.

    ``knowledge_base:read`` is the right permission and it already exists:
    ``POST /kb/query`` uses it for the full-text half of the same corpus,
    and every role that triages holds it. Reusing it rather than minting a
    ``memory:read`` keeps one answer to "may this principal search what the
    organisation knows" — two permissions over one corpus is two answers
    that can disagree, and the disagreement surfaces on the day somebody
    narrows a role.
    """
    unknown = [k for k in body.kinds if k not in MEMORY_KINDS]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"unknown kind(s): {unknown}. Expected a subset of {list(MEMORY_KINDS)}.",
        )
    try:
        hits = await vector_search(
            body.query,
            tenant_id=current_user.tenant_id,
            kinds=body.kinds or None,
            limit=body.limit,
        )
    except (EmbeddingsUnavailable, VectorStoreUnavailable) as exc:
        # 503 with the reason, never an empty list. "Found nothing" and
        # "could not search" must not render the same.
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    if not hits:
        return []

    scores = dict(hits)
    rows = (
        (
            await db.execute(
                select(MemoryItem).where(
                    MemoryItem.tenant_id == current_user.tenant_id,
                    MemoryItem.id.in_(list(scores)),
                    MemoryItem.state == "in_use",
                )
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)

    # Expiry is applied at read, not by a sweep: a worker being down must not
    # resurrect an expired claim.
    #
    # `_aware` exists because the column is TIMESTAMPTZ on Postgres and
    # returns an aware value, while some drivers hand back a naive one — and
    # comparing the two raises `TypeError` inside the handler, which would
    # turn an expired item from "withheld" into a 500 on the whole recall.
    # Treating a naive timestamp as UTC is right here: every writer in this
    # service stores UTC.
    def _aware(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    live = [r for r in rows if r.expires_at is None or _aware(r.expires_at) > now]
    live.sort(key=lambda r: scores.get(r.id, 0.0), reverse=True)
    return [MemoryRecallHit(item=_out(r), score=scores.get(r.id, 0.0)) for r in live]


# ---------------------------------------------------------------------------
# Conflicts
# ---------------------------------------------------------------------------


@router.get("/conflicts", response_model=list[MemoryConflictOut])
async def list_conflicts(
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:read"))],
) -> list[MemoryConflictOut]:
    rows = (
        (
            await db.execute(
                select(MemoryItem)
                .where(
                    MemoryItem.tenant_id == current_user.tenant_id,
                    MemoryItem.state == "conflict",
                )
                .order_by(MemoryItem.updated_at.desc())
            )
        )
        .scalars()
        .all()
    )
    by_id = {row.id: row for row in rows}
    seen: set[uuid.UUID] = set()
    out: list[MemoryConflictOut] = []
    for row in rows:
        if row.id in seen:
            continue
        seen.add(row.id)
        other = by_id.get(row.conflicts_with) if row.conflicts_with else None
        if other is not None:
            seen.add(other.id)
        out.append(MemoryConflictOut(left=_out(row), right=_out(other) if other else None))
    return out


@router.post("/conflicts/{item_id}/resolve", response_model=MemoryConflictOut)
async def resolve_conflict(
    item_id: uuid.UUID,
    body: MemoryConflictResolution,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
) -> MemoryConflictOut:
    """Settle a conflict by naming which side survives. The other is retired."""
    try:
        keep_id = uuid.UUID(body.keep)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="keep must be an item id") from exc

    row = (
        await db.execute(
            select(MemoryItem).where(
                MemoryItem.id == item_id,
                MemoryItem.tenant_id == current_user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None or row.state != "conflict":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such conflict")
    other = None
    if row.conflicts_with:
        other = (
            await db.execute(
                select(MemoryItem).where(
                    MemoryItem.id == row.conflicts_with,
                    MemoryItem.tenant_id == current_user.tenant_id,
                )
            )
        ).scalar_one_or_none()

    pair = [r for r in (row, other) if r is not None]
    if keep_id not in {r.id for r in pair}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="keep must name one of the two items in this conflict",
        )

    actor = current_user.api_key_prefix or current_user.email
    for item in pair:
        item.conflicts_with = None
        item.updated_at = datetime.now(UTC)
        if item.id == keep_id:
            item.state = "in_use"
            item.state_reason = body.note or f"kept by {actor}"
        else:
            item.state = "not_in_use"
            item.state_reason = body.note or f"superseded by {keep_id}, decided by {actor}"
            await forget_item(item.id)

    kept = next(r for r in pair if r.id == keep_id)
    try:
        model = await index_item(
            tenant_id=current_user.tenant_id,
            item_id=kept.id,
            kind=kept.kind,
            subject=kept.subject,
            title=kept.title,
            content=kept.content,
            state="in_use",
        )
        kept.embedding_model = model
        kept.embedded_at = datetime.now(UTC)
    except (EmbeddingsUnavailable, VectorStoreUnavailable) as exc:
        logger.warning("semantic_memory.reindex_failed", item_id=str(kept.id), error=str(exc))

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="memory:conflict_resolved",
        resource="memory_item",
        resource_id=str(keep_id),
        changes={"kept": str(keep_id), "retired": [str(r.id) for r in pair if r.id != keep_id]},
        request=request,
    )
    await db.commit()
    for item in pair:
        await db.refresh(item)
    return MemoryConflictOut(left=_out(row), right=_out(other) if other else None)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@router.get("/status")
async def recall_status(
    db: TenantDBSession,
    current_user: AuthUser,
) -> dict[str, Any]:
    """Can this deployment recall at all, and over how much.

    Every count here is computed from rows this request counted, not read
    from a cached figure, and an unknown stays ``null`` rather than becoming
    a confident zero.
    """
    out = await memory_status()
    rows = (
        (await db.execute(select(MemoryItem.state, MemoryItem.embedding_model).where(MemoryItem.tenant_id == current_user.tenant_id)))
        .tuples()
        .all()
    )
    by_state: dict[str, int] = {}
    unembedded = 0
    stale_model = 0
    configured = out.get("embedding_model")
    for state_value, model in rows:
        by_state[state_value] = by_state.get(state_value, 0) + 1
        if state_value != "in_use":
            continue
        if model is None:
            unembedded += 1
        elif configured and model != configured:
            # Embedded by a model nobody is running any more. Distinct from
            # never embedded, and the two call for different actions.
            stale_model += 1
    out["items_by_state"] = by_state
    out["in_use_never_embedded"] = unembedded
    out["in_use_embedded_by_another_model"] = stale_model
    out["recall_available"] = bool(out.get("embedding_backend")) and bool(out.get("vector_store_reachable"))
    return out
