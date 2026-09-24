"""Public investigation-replay publishing — v8 W3.

Turns a tenant-private investigation ledger into an immutable, redacted, public
share link at ``<console-base>/r/<slug>``, where the console base comes from
``CONSOLE_PUBLIC_BASE_URL`` (see :func:`app.core.config.console_base_url`).

Flow:

1. ``POST /ledger/{run_id}/publish/preview`` (auth ``cases:read``) — build the
   redacted snapshot and return it **with the alias map** so the publisher can
   review exactly what will be hidden (the pre-publish diff).
2. ``POST /ledger/{run_id}/publish`` (auth ``cases:write``) — re-build the
   snapshot server-side (the client-supplied preview is never trusted), persist
   an immutable ``published_replays`` row, and return the public slug + URL.
3. ``GET /r/{slug}`` — **public, no auth** — return the redacted snapshot for
   the replay page. Increments a best-effort view counter.
4. ``DELETE /ledger/publish/{slug}`` (auth ``cases:write``) — unpublish
   (tenant-scoped).
5. ``GET /ledger/{run_id}/published`` (auth ``cases:read``) — list a run's
   published replays.

Only the redacted snapshot is persisted; the alias map is preview-only and is
never stored.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.config import console_base_url
from app.db.rls import TenantDBSession
from app.models.investigation import InvestigationEvent, InvestigationRun
from app.models.published_replay import PublishedReplay
from app.services.replay_redaction import build_redacted_snapshot

logger = structlog.get_logger()

# Public-share operations hang off /ledger; the public read hangs off /r.
router = APIRouter(prefix="/ledger", tags=["replay"])
public_router = APIRouter(prefix="/r", tags=["replay-public"])


def _public_base() -> str:
    """Origin for published share links, resolved per call.

    Deliberately a function, not a module constant: the constant was baked in
    at import time and hard-coded one deployment's hostname, so every
    self-hosted install handed out share links into somebody else's console.
    """
    return f"{console_base_url()}/r"


class PublishPreview(BaseModel):
    """Pre-publish diff: what the public will see + what will be hidden."""

    run_id: uuid.UUID
    title: str
    snapshot: dict
    # alias -> original, so the publisher can confirm the redaction. Never stored.
    alias_map: dict[str, str]


class PublishRequest(BaseModel):
    confirm: bool = Field(default=False, description="Must be true to publish.")
    title_override: str | None = Field(default=None, max_length=200)


class PublishResult(BaseModel):
    slug: str
    url: str
    run_id: uuid.UUID
    created_at: datetime


class PublishedSummary(BaseModel):
    slug: str
    url: str
    title: str
    case_id: str
    view_count: int
    created_at: datetime


class PublicReplay(BaseModel):
    slug: str
    title: str
    case_id: str
    snapshot: dict
    view_count: int
    created_at: datetime


def _sanitize(value: object, limit: int = 64) -> str:
    """Inline log sanitization (CodeQL py/log-injection): strip CR/LF + clamp."""
    return str(value).replace("\r", "").replace("\n", " ")[:limit]


async def _load_run_and_events(
    db: TenantDBSession, run_id: uuid.UUID, tenant_id: uuid.UUID
) -> tuple[InvestigationRun, list[InvestigationEvent]]:
    run = (
        await db.execute(
            select(InvestigationRun).where(
                InvestigationRun.id == run_id,
                InvestigationRun.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation run not found")
    events = list(
        (
            await db.execute(
                select(InvestigationEvent)
                .where(InvestigationEvent.run_id == run_id, InvestigationEvent.tenant_id == tenant_id)
                .order_by(InvestigationEvent.seq.asc())
                .limit(10000)
            )
        )
        .scalars()
        .all()
    )
    return run, events


def _run_to_dict(run: InvestigationRun) -> dict:
    return {
        "case_id": run.case_id,
        "alert_summary": run.alert_summary,
        "raw_alert": run.raw_alert,
        "model_used": run.model_used,
        "status": run.status,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
    }


def _events_to_dicts(events: list[InvestigationEvent]) -> list[dict]:
    return [
        {
            "seq": e.seq,
            "kind": e.kind,
            "agent": e.agent,
            "summary": e.summary,
            "payload": e.payload,
            "ts": e.ts,
            "duration_ms": e.duration_ms,
        }
        for e in events
    ]


@router.post("/{run_id}/publish/preview", response_model=PublishPreview)
async def preview_publish(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> PublishPreview:
    """Build the redacted snapshot + alias map for the pre-publish review."""
    run, events = await _load_run_and_events(db, run_id, current_user.tenant_id)
    result = build_redacted_snapshot(run=_run_to_dict(run), events=_events_to_dicts(events))
    return PublishPreview(
        run_id=run_id,
        title=result.title,
        snapshot=result.snapshot,
        alias_map=result.alias_map,
    )


async def _unique_slug(db: DBSession) -> str:
    """Mint a short, URL-safe slug, retrying on the (rare) collision."""
    for _ in range(6):
        slug = secrets.token_urlsafe(8).replace("-", "").replace("_", "")[:12].lower()
        if len(slug) < 8:
            continue
        exists = (await db.execute(select(PublishedReplay.id).where(PublishedReplay.slug == slug))).first()
        if not exists:
            return slug
    raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Could not allocate a unique slug; retry.")


@router.post("/{run_id}/publish", response_model=PublishResult, status_code=status.HTTP_201_CREATED)
async def publish_replay(
    run_id: uuid.UUID,
    body: PublishRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: TenantDBSession,
) -> PublishResult:
    """Persist an immutable, redacted public snapshot and return its share URL."""
    if not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Set confirm=true to publish. Review the /publish/preview diff first.",
        )
    run, events = await _load_run_and_events(db, run_id, current_user.tenant_id)
    result = build_redacted_snapshot(run=_run_to_dict(run), events=_events_to_dicts(events))
    title = (body.title_override or result.title)[:200]

    slug = await _unique_slug(db)
    row = PublishedReplay(
        slug=slug,
        run_id=run_id,
        tenant_id=current_user.tenant_id,
        case_id=run.case_id,
        title=title,
        snapshot=result.snapshot,
        published_by=current_user.user_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    logger.info("replay.published", slug=_sanitize(slug), run_id=_sanitize(run_id), tenant=_sanitize(current_user.tenant_id))
    return PublishResult(slug=slug, url=f"{_public_base()}/{slug}", run_id=run_id, created_at=row.created_at)


@router.get("/{run_id}/published", response_model=list[PublishedSummary])
async def list_published(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> list[PublishedSummary]:
    rows = (
        (
            await db.execute(
                select(PublishedReplay)
                .where(PublishedReplay.run_id == run_id, PublishedReplay.tenant_id == current_user.tenant_id)
                .order_by(PublishedReplay.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return [
        PublishedSummary(
            slug=r.slug,
            url=f"{_public_base()}/{r.slug}",
            title=r.title,
            case_id=r.case_id,
            view_count=r.view_count,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.delete("/publish/{slug}", status_code=status.HTTP_204_NO_CONTENT)
async def unpublish_replay(
    slug: str,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: TenantDBSession,
) -> None:
    row = (
        await db.execute(
            select(PublishedReplay).where(
                PublishedReplay.slug == slug,
                PublishedReplay.tenant_id == current_user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Published replay not found")
    await db.delete(row)
    await db.commit()


@public_router.get("/{slug}", response_model=PublicReplay)
async def get_public_replay(slug: str, db: DBSession) -> PublicReplay:
    """Public, unauthenticated read of a redacted replay snapshot.

    Uses a non-RLS session because ``published_replays`` is intentionally
    public-by-design (post-redaction, non-identifying). Increments a
    best-effort view counter (the only mutation the immutability trigger
    permits).
    """
    row = (await db.execute(select(PublishedReplay).where(PublishedReplay.slug == slug))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Replay not found")

    # Best-effort view bump; never fail the read on a counter error.
    try:
        await db.execute(update(PublishedReplay).where(PublishedReplay.id == row.id).values(view_count=PublishedReplay.view_count + 1))
        await db.commit()
    except Exception:  # pragma: no cover - counter is best-effort only
        await db.rollback()

    return PublicReplay(
        slug=row.slug,
        title=row.title,
        case_id=row.case_id,
        snapshot=row.snapshot,
        view_count=row.view_count + 1,
        created_at=row.created_at,
    )
