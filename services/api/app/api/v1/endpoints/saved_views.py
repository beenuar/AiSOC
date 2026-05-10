"""Per-user saved views CRUD — Workstream F3 (analyst quality-of-life).

Endpoints
---------

* ``GET    /saved-views?view_type=alerts``       — list the caller's
  presets for one list page.
* ``POST   /saved-views``                        — create a preset.
* ``PATCH  /saved-views/{id}``                   — rename, retune
  filters/columns, or toggle ``is_default``.
* ``DELETE /saved-views/{id}``                   — delete a preset.

Scoping
-------

Saved views are *per-user-per-tenant*: every query filters on
``tenant_id == current_user.tenant_id`` AND
``user_id == current_user.user_id``. The DB-level RLS policy in
migration 037 enforces tenant isolation as a defence-in-depth layer;
user-level scoping lives here in the API. Sharing presets across
users is a deliberate v1.1 follow-up — keeping presets private to
the caller in v1.0 lets us ship without a "scope" enum and avoid the
"my buddy renamed our shared view" support ticket.

Authorization
-------------

Saved views are a personal-preference surface; every authenticated
user can manage their own. We therefore gate on authentication only
(no ``require_permission(...)`` factory). Read-only roles (e.g.
``viewer``) keep a read-write surface for their *own* preferences,
which matches how analysts actually use saved views in practice.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, delete, select, update
from sqlalchemy.exc import IntegrityError

from app.api.v1.deps import AuthUser
from app.db.rls import TenantDBSession
from app.models.saved_view import SavedView

logger = structlog.get_logger()

router = APIRouter(prefix="/saved-views", tags=["saved-views"])

# Mirrors the CHECK constraint on the table. Keep the two in lockstep:
# adding "dashboards" or "hunts" later requires both the migration and
# this allowlist.
_VALID_VIEW_TYPES = {"alerts", "cases", "investigations", "playbooks"}

# Reasonable upper bounds — saved views are per-user UI state, not a
# data store. Past these limits something is wrong (either a bug or
# an analyst trying to use the table as a key/value cache).
_MAX_NAME_LEN = 120
_MAX_FILTERS_BYTES = 8 * 1024  # 8 KB JSON is more than enough for any list page.
_MAX_COLUMNS_BYTES = 4 * 1024


def _validate_view_type(view_type: str) -> str:
    if view_type not in _VALID_VIEW_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(f"view_type must be one of: {', '.join(sorted(_VALID_VIEW_TYPES))}"),
        )
    return view_type


def _validate_payload_size(blob: Any, *, field: str, limit: int) -> None:
    """Reject saved views whose JSON blob is unreasonably large.

    The DB will technically accept arbitrary JSONB, but a runaway
    payload turns the saved-views endpoint into a per-user blob store
    we'd then have to maintain. Capping early keeps the surface
    honest.
    """
    if blob is None:
        return
    try:
        import json  # noqa: PLC0415

        approx = len(json.dumps(blob, separators=(",", ":")))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field} must be JSON-serialisable",
        ) from exc
    if approx > limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{field} exceeds maximum size of {limit} bytes",
        )


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class SavedViewModel(BaseModel):
    """Wire format for a saved view row."""

    id: str
    view_type: str
    name: str
    filters: dict[str, Any] = Field(default_factory=dict)
    columns: list[Any] | dict[str, Any] | None = None
    is_default: bool = False
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=False)

    @classmethod
    def from_orm(cls, row: SavedView) -> SavedViewModel:
        return cls(
            id=str(row.id),
            view_type=row.view_type,
            name=row.name,
            filters=dict(row.filters or {}),
            columns=row.columns,
            is_default=bool(row.is_default),
            created_at=row.created_at.isoformat(),
            updated_at=row.updated_at.isoformat(),
        )


class CreateSavedViewRequest(BaseModel):
    view_type: str
    name: str = Field(..., min_length=1, max_length=_MAX_NAME_LEN)
    filters: dict[str, Any] = Field(default_factory=dict)
    columns: list[Any] | dict[str, Any] | None = None
    is_default: bool = False


class UpdateSavedViewRequest(BaseModel):
    """Partial update — every field is optional.

    Sending an empty body is a no-op (returns the row unchanged). To
    *clear* ``columns`` and fall back to the page default column set,
    the caller passes ``columns: null`` explicitly — the optional /
    null distinction is preserved in the JSON.
    """

    name: str | None = Field(default=None, min_length=1, max_length=_MAX_NAME_LEN)
    filters: dict[str, Any] | None = None
    columns: list[Any] | dict[str, Any] | None = None
    is_default: bool | None = None

    # Track which fields the caller actually sent so we can distinguish
    # "explicit null" from "omitted" without reaching into Pydantic
    # internals at every call site.
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[SavedViewModel])
async def list_saved_views(
    user: AuthUser,
    db: TenantDBSession,
    view_type: str = Query(
        ...,
        description=(f"Which list page to return presets for. One of: {', '.join(sorted(_VALID_VIEW_TYPES))}."),
    ),
) -> list[SavedViewModel]:
    """Return the caller's saved views for one list page.

    Sorted by ``is_default DESC, updated_at DESC`` so the default
    preset always lands first, with the rest ordered by recency. The
    UI uses this ordering directly to render the saved-views menu.
    """
    _validate_view_type(view_type)

    rows = (
        (
            await db.execute(
                select(SavedView)
                .where(
                    SavedView.tenant_id == user.tenant_id,
                    SavedView.user_id == user.user_id,
                    SavedView.view_type == view_type,
                )
                .order_by(SavedView.is_default.desc(), SavedView.updated_at.desc())
            )
        )
        .scalars()
        .all()
    )

    return [SavedViewModel.from_orm(r) for r in rows]


@router.post("", response_model=SavedViewModel, status_code=status.HTTP_201_CREATED)
async def create_saved_view(
    payload: CreateSavedViewRequest,
    user: AuthUser,
    db: TenantDBSession,
) -> SavedViewModel:
    """Create a new saved view.

    If ``is_default=True`` is passed, any existing default for the
    same ``(tenant, user, view_type)`` is demoted *first* so the
    partial unique index in 037 doesn't trip. We do the demote + insert
    in a single transaction so a concurrent ``POST`` from the same
    user can't leave the table without a default.
    """
    _validate_view_type(payload.view_type)
    _validate_payload_size(payload.filters, field="filters", limit=_MAX_FILTERS_BYTES)
    _validate_payload_size(payload.columns, field="columns", limit=_MAX_COLUMNS_BYTES)

    name = payload.name.strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="name must not be blank",
        )

    if payload.is_default:
        await _demote_existing_default(
            db,
            tenant_id=user.tenant_id,
            user_id=user.user_id,
            view_type=payload.view_type,
        )

    # Stamp timestamps eagerly so the response payload has them even if
    # we skip ``db.refresh`` (e.g. in unit tests with mocked sessions).
    # SQLAlchemy's Python-side defaults only run during flush, which
    # gets bypassed when the test fixture mocks ``flush`` to a no-op.
    now = datetime.now(UTC)
    row = SavedView(
        id=uuid.uuid4(),
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        view_type=payload.view_type,
        name=name,
        filters=dict(payload.filters or {}),
        columns=payload.columns,
        is_default=bool(payload.is_default),
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        await db.flush()
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        # Surface the most likely cause: duplicate name within
        # (tenant, user, view_type). The other unique index — partial
        # on is_default — is guarded by _demote_existing_default
        # above, so a hit here is almost certainly the name.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"A saved view named '{name}' already exists for this user and view type"),
        ) from exc

    await db.refresh(row)

    logger.info(
        "saved_view.create",
        tenant_id=str(user.tenant_id),
        user_id=str(user.user_id),
        view_type=payload.view_type,
        view_id=str(row.id),
        is_default=row.is_default,
    )
    return SavedViewModel.from_orm(row)


@router.patch("/{view_id}", response_model=SavedViewModel)
async def update_saved_view(
    view_id: str,
    payload: UpdateSavedViewRequest,
    user: AuthUser,
    db: TenantDBSession,
) -> SavedViewModel:
    """Patch a saved view in place.

    Sending only ``is_default=True`` is the canonical "make this my
    default" path. We demote the existing default first inside the
    same transaction.
    """
    view_uuid = _coerce_uuid(view_id)
    row = await _load_owned_view(db, view_uuid, user)

    fields_set = payload.model_fields_set
    if not fields_set:
        return SavedViewModel.from_orm(row)

    if "filters" in fields_set:
        _validate_payload_size(payload.filters, field="filters", limit=_MAX_FILTERS_BYTES)
        row.filters = dict(payload.filters or {})

    if "columns" in fields_set:
        _validate_payload_size(payload.columns, field="columns", limit=_MAX_COLUMNS_BYTES)
        row.columns = payload.columns  # may be explicit None — clears it.

    if "name" in fields_set and payload.name is not None:
        new_name = payload.name.strip()
        if not new_name:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="name must not be blank",
            )
        row.name = new_name

    if "is_default" in fields_set and payload.is_default is not None:
        if payload.is_default and not row.is_default:
            await _demote_existing_default(
                db,
                tenant_id=user.tenant_id,
                user_id=user.user_id,
                view_type=row.view_type,
                except_id=row.id,
            )
        row.is_default = bool(payload.is_default)

    row.updated_at = datetime.now(UTC)

    try:
        await db.flush()
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=("A saved view with this name already exists for this user and view type"),
        ) from exc

    await db.refresh(row)

    logger.info(
        "saved_view.update",
        tenant_id=str(user.tenant_id),
        user_id=str(user.user_id),
        view_id=str(row.id),
        is_default=row.is_default,
    )
    return SavedViewModel.from_orm(row)


@router.delete("/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_view(
    view_id: str,
    user: AuthUser,
    db: TenantDBSession,
) -> None:
    """Delete a saved view owned by the caller."""
    view_uuid = _coerce_uuid(view_id)

    result = await db.execute(
        delete(SavedView).where(
            and_(
                SavedView.id == view_uuid,
                SavedView.tenant_id == user.tenant_id,
                SavedView.user_id == user.user_id,
            )
        )
    )
    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved view not found",
        )
    await db.commit()

    logger.info(
        "saved_view.delete",
        tenant_id=str(user.tenant_id),
        user_id=str(user.user_id),
        view_id=str(view_uuid),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved view not found",
        ) from exc


async def _load_owned_view(
    db: Any,  # noqa: ANN401 — TenantDBSession is an Annotated alias.
    view_id: uuid.UUID,
    user: Any,  # noqa: ANN401 — CurrentUser; avoiding the import cycle.
) -> SavedView:
    row = await db.scalar(
        select(SavedView).where(
            SavedView.id == view_id,
            SavedView.tenant_id == user.tenant_id,
            SavedView.user_id == user.user_id,
        )
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Saved view not found",
        )
    return row


async def _demote_existing_default(
    db: Any,  # noqa: ANN401
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    view_type: str,
    except_id: uuid.UUID | None = None,
) -> None:
    """Flip any existing default off so a new one can be promoted.

    Without this dance, the partial unique index
    ``saved_views_one_default_idx`` in migration 037 would reject the
    promotion. We could have written this as a single
    ``UPDATE ... WHERE is_default`` SQL statement; we keep it
    surgical (clearing only the matching row's flag) so we never
    accidentally clobber unrelated defaults if RLS or the
    ``user_id`` predicate ever drift.
    """
    conditions = [
        SavedView.tenant_id == tenant_id,
        SavedView.user_id == user_id,
        SavedView.view_type == view_type,
        SavedView.is_default.is_(True),
    ]
    if except_id is not None:
        conditions.append(SavedView.id != except_id)

    await db.execute(update(SavedView).where(and_(*conditions)).values(is_default=False, updated_at=datetime.now(UTC)))
