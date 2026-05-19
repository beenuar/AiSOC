"""Saved natural-language hunts CRUD — Track 3, T3.4 (`/hunt` NL surface).

The ``/hunt`` page lets analysts ask questions like
*"Did we get any new attacks from Iran?"* and save the prompt for re-use or
scheduled execution. This endpoint backs the saved-hunts list on that page.

Endpoints
---------
* ``POST   /saved-hunts``               — translate + save a NL question.
* ``GET    /saved-hunts``               — list saved hunts in the tenant.
* ``GET    /saved-hunts/{id}``          — fetch one (re-translates).
* ``DELETE /saved-hunts/{id}``          — delete one.
* ``POST   /saved-hunts/{id}/run``      — manually run a saved hunt now.

Why a separate endpoint from ``/hunts`` (the hypothesis-driven hunt
workbench)?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``/hunts`` (`endpoints/hunts.py`) is the heavyweight detection-engineering
surface: each row has a hypothesis, MITRE mapping, status, multi-platform
queries, findings rollup, and a separate ``hunt_runs`` log. It's been in
the public API since Tier 2 and changing its wire shape would break the
hunt workbench page.

``/saved-hunts`` (this module) is the lightweight tier-1 analyst surface:
each row stores the *original NL question* plus the translator's structured
output. The two tables (``aisoc_hunts`` vs ``aisoc_saved_hunts``) live side
by side because they answer different jobs-to-be-done.

Authorisation
~~~~~~~~~~~~~

Saved hunts are *tenant-shared* (every analyst in the tenant sees every
saved hunt — like a shared knowledge base) and gated on authentication
only. Authoring permission inherits from the role; for now, anyone with
read access to the ``/hunt`` page can save and delete. A finer
``hunt:save`` / ``hunt:delete`` split is a deliberate v1.x follow-up if
multi-team tenants ask for it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, delete, select, update
from sqlalchemy.exc import IntegrityError

from app.api.v1.deps import AuthUser

# Defer import of the NL translator helpers — `nl_query.py` already does the
# vendored-tree resolution dance at import time and we want the same module
# instance so a future LLM enhancement applies uniformly.
from app.api.v1.endpoints.nl_query import (  # noqa: E402
    deterministic_translate,
)
from app.db.rls import TenantDBSession
from app.models.saved_hunt import SavedHunt

logger = structlog.get_logger()

router = APIRouter(prefix="/saved-hunts", tags=["saved-hunts"])

# Reasonable upper bounds.
_MAX_NAME_LEN = 160
_MAX_NL_QUERY_LEN = 4000
_MAX_SCHEDULE_LEN = 120

HuntLanguage = Literal["esql", "kql", "spl"]


# ---------------------------------------------------------------------------
# Cron validation
# ---------------------------------------------------------------------------


def _validate_cron(schedule: str) -> str:
    """Cheap structural cron validation.

    The hunt scheduler worker uses :mod:`croniter`-compatible parsing, but
    croniter isn't currently a hard dependency of the API service. To keep
    the endpoint useful in environments that don't have it, we do a minimal
    structural check here:

    * Must be five whitespace-separated fields (classic cron, not the
      6-field "with seconds" extension).
    * Each field must use only the allowed character set
      ``0-9 , - * /``. We deliberately don't validate ranges (so
      ``99 99 99 99 99`` slips through); the worker rejects unparseable
      cron strings at run time, which is the authoritative gate.

    This keeps an obviously-wrong schedule from being persisted while not
    forcing a heavyweight cron library on the API container.
    """
    schedule = schedule.strip()
    fields = schedule.split()
    if len(fields) != 5:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=("schedule must be a 5-field cron string, e.g. '0 */6 * * *'"),
        )
    allowed = set("0123456789,-*/")
    for fld in fields:
        if not fld or any(ch not in allowed for ch in fld):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"schedule field {fld!r} contains unsupported characters",
            )
    return schedule


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class TranslatedQueryEnvelope(BaseModel):
    """Translator output stored alongside the NL question.

    Mirrors :class:`services.agents.app.nl_query.translator.TranslatedQuery`
    but without the ``intents`` IR (which is internal to the translator).
    """

    esql: str = ""
    kql: str = ""
    spl: str = ""
    explanation: str = ""

    @classmethod
    def from_translator(cls, tq: Any) -> TranslatedQueryEnvelope:
        return cls(
            esql=getattr(tq, "esql", "") or "",
            kql=getattr(tq, "kql", "") or "",
            spl=getattr(tq, "spl", "") or "",
            explanation=getattr(tq, "explanation", "") or "",
        )


class SavedHuntModel(BaseModel):
    """Wire format for a saved hunt row."""

    id: str
    name: str
    nl_query: str
    translated_query: TranslatedQueryEnvelope
    language: HuntLanguage
    schedule: str | None = None
    last_run_at: str | None = None
    created_at: str
    updated_at: str
    created_by: str | None = None

    model_config = ConfigDict(from_attributes=False)

    @classmethod
    def from_orm(cls, row: SavedHunt) -> SavedHuntModel:
        translated_raw = dict(row.translated_query or {})
        return cls(
            id=str(row.id),
            name=row.name,
            nl_query=row.nl_query,
            translated_query=TranslatedQueryEnvelope(
                esql=str(translated_raw.get("esql") or ""),
                kql=str(translated_raw.get("kql") or ""),
                spl=str(translated_raw.get("spl") or ""),
                explanation=str(translated_raw.get("explanation") or ""),
            ),
            language=row.language,  # type: ignore[arg-type]
            schedule=row.schedule,
            last_run_at=row.last_run_at.isoformat() if row.last_run_at else None,
            created_at=row.created_at.isoformat(),
            updated_at=row.updated_at.isoformat(),
            created_by=str(row.created_by) if row.created_by else None,
        )


class CreateSavedHuntRequest(BaseModel):
    """Body for ``POST /saved-hunts``.

    The caller supplies the NL question and a name; we translate server-side
    so the stored ``translated_query`` is guaranteed to match what the
    platform will execute (no client-side drift).
    """

    name: str = Field(..., min_length=1, max_length=_MAX_NAME_LEN)
    nl_query: str = Field(..., min_length=3, max_length=_MAX_NL_QUERY_LEN)
    language: HuntLanguage = "esql"
    schedule: str | None = Field(default=None, max_length=_MAX_SCHEDULE_LEN)


class RunSavedHuntResponse(BaseModel):
    """Synchronous run result returned by ``POST /saved-hunts/{id}/run``.

    The endpoint *does not* execute the underlying ES|QL — that path is the
    job of :mod:`app.api.v1.endpoints.nl_query` (``/nl-query/execute``) and
    requires a configured Elasticsearch URL. The ``/run`` endpoint here only
    re-translates and stamps ``last_run_at`` so the UI can show "last run
    just now" and so the scheduler treats a manual run as resetting cadence.
    """

    id: str
    name: str
    nl_query: str
    translated_query: TranslatedQueryEnvelope
    last_run_at: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved hunt not found",
        ) from exc


def _translate(nl_query: str) -> TranslatedQueryEnvelope:
    """Translate ``nl_query`` deterministically.

    Wrapped so test code can monkeypatch one symbol. The deterministic
    translator never raises on valid input — the grammar validators are
    internal to it — so there's no exception swallow needed here.
    """
    tq = deterministic_translate(nl_query)
    return TranslatedQueryEnvelope.from_translator(tq)


async def _load_owned_hunt(
    db: Any,  # noqa: ANN401
    hunt_id: uuid.UUID,
    user: Any,  # noqa: ANN401
) -> SavedHunt:
    row = await db.scalar(
        select(SavedHunt).where(
            SavedHunt.id == hunt_id,
            SavedHunt.tenant_id == user.tenant_id,
        )
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved hunt not found",
        )
    return row


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[SavedHuntModel])
async def list_saved_hunts(
    user: AuthUser,
    db: TenantDBSession,
) -> list[SavedHuntModel]:
    """Return every saved hunt visible in the caller's tenant.

    Sorted by ``updated_at DESC`` so the most recently re-run hunt lands
    first; the UI renders this list as the "Saved hunts" sidebar.
    """
    rows = (
        (await db.execute(select(SavedHunt).where(SavedHunt.tenant_id == user.tenant_id).order_by(SavedHunt.updated_at.desc())))
        .scalars()
        .all()
    )
    return [SavedHuntModel.from_orm(r) for r in rows]


@router.post(
    "",
    response_model=SavedHuntModel,
    status_code=status.HTTP_201_CREATED,
)
async def create_saved_hunt(
    payload: CreateSavedHuntRequest,
    user: AuthUser,
    db: TenantDBSession,
) -> SavedHuntModel:
    """Translate the NL question and persist the hunt."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="name must not be blank",
        )
    nl_query = payload.nl_query.strip()
    if len(nl_query) < 3:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="nl_query must be at least 3 characters",
        )
    schedule = _validate_cron(payload.schedule) if payload.schedule else None

    translated = _translate(nl_query)

    now = datetime.now(UTC)
    row = SavedHunt(
        id=uuid.uuid4(),
        tenant_id=user.tenant_id,
        created_by=user.user_id,
        name=name,
        nl_query=nl_query,
        translated_query=translated.model_dump(),
        language=payload.language,
        schedule=schedule,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        await db.flush()
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A saved hunt named {name!r} already exists in this tenant",
        ) from exc

    await db.refresh(row)

    logger.info(
        "saved_hunt.create",
        tenant_id=str(user.tenant_id),
        user_id=str(user.user_id) if user.user_id else None,
        hunt_id=str(row.id),
        scheduled=schedule is not None,
    )
    return SavedHuntModel.from_orm(row)


@router.get("/{hunt_id}", response_model=SavedHuntModel)
async def get_saved_hunt(
    hunt_id: str,
    user: AuthUser,
    db: TenantDBSession,
) -> SavedHuntModel:
    """Fetch one saved hunt."""
    row = await _load_owned_hunt(db, _coerce_uuid(hunt_id), user)
    return SavedHuntModel.from_orm(row)


@router.delete(
    "/{hunt_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_saved_hunt(
    hunt_id: str,
    user: AuthUser,
    db: TenantDBSession,
) -> None:
    """Delete a saved hunt owned by the caller's tenant."""
    hunt_uuid = _coerce_uuid(hunt_id)
    result = await db.execute(
        delete(SavedHunt).where(
            and_(
                SavedHunt.id == hunt_uuid,
                SavedHunt.tenant_id == user.tenant_id,
            )
        )
    )
    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved hunt not found",
        )
    await db.commit()
    logger.info(
        "saved_hunt.delete",
        tenant_id=str(user.tenant_id),
        hunt_id=str(hunt_uuid),
    )


@router.post(
    "/{hunt_id}/run",
    response_model=RunSavedHuntResponse,
)
async def run_saved_hunt(
    hunt_id: str,
    user: AuthUser,
    db: TenantDBSession,
) -> RunSavedHuntResponse:
    """Re-translate the saved NL question and stamp ``last_run_at``.

    Why re-translate on every run? The translator is the platform's source
    of truth for "what does this question mean today?" — improving the
    translator (e.g. adding a new field alias) should automatically benefit
    saved hunts the next time they're executed without an analyst having to
    re-save them. The stored ``translated_query`` is the snapshot taken at
    save time and serves as a baseline for diffing.
    """
    hunt_uuid = _coerce_uuid(hunt_id)
    row = await _load_owned_hunt(db, hunt_uuid, user)

    translated = _translate(row.nl_query)
    now = datetime.now(UTC)

    # Persist the refreshed translation alongside the run timestamp so the
    # next list call surfaces the latest envelope. The schedule worker uses
    # the same column (``last_run_at``) to gate cadence — keeping both code
    # paths converge on a single timestamp avoids the "manual run didn't
    # reset the cron" bug.
    await db.execute(
        update(SavedHunt)
        .where(SavedHunt.id == hunt_uuid)
        .values(
            translated_query=translated.model_dump(),
            last_run_at=now,
            updated_at=now,
        )
    )
    await db.commit()

    return RunSavedHuntResponse(
        id=str(row.id),
        name=row.name,
        nl_query=row.nl_query,
        translated_query=translated,
        last_run_at=now.isoformat(),
    )
