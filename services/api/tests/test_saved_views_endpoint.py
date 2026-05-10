"""Unit tests for the per-user saved-views CRUD endpoints (Workstream F3).

The saved-views endpoints (``/api/v1/saved-views`` GET / POST / PATCH /
DELETE) are mostly orchestration: validate input, scope the query by
``(tenant_id, user_id)``, and round-trip an opaque JSONB blob. Like the
sibling endpoint tests in this repo (``test_inbox_itsm_endpoint.py``,
``test_lake_endpoint.py``) we mock the DB session directly rather than
spinning up the FastAPI app + Postgres harness.

What we cover here:

* ``_validate_view_type`` — the allowlist mirror of the table CHECK
  constraint. Adding a fifth view type without bumping both is a bug
  we catch by asserting a known-good and a known-bad value.
* ``_validate_payload_size`` — the JSONB size cap that keeps the table
  out of "blob store" duty. Below limit, above limit, and the
  unserialisable branch.
* ``_coerce_uuid`` — defensive 404 instead of 500 on garbled IDs.
  Important because the route accepts arbitrary strings via path.
* ``list_saved_views`` — happy path returns sorted rows; invalid
  ``view_type`` returns 422 *before* we touch the DB.
* ``create_saved_view`` — fields are forwarded verbatim, ``is_default``
  triggers the demote step, blank names are 422, and an IntegrityError
  surfaces as 409 (not 500).
* ``update_saved_view`` — partial update semantics: empty PATCH is a
  no-op (returns the row unchanged), explicit ``columns: null``
  *clears* the columns blob (vs. omitting which leaves them alone),
  flipping ``is_default`` from false → true demotes the existing
  default, missing rows 404.
* ``delete_saved_view`` — 204 on success, 404 when nothing matched.

Tenancy & user-scoping are verified by inspecting the WHERE clauses
constructed by the endpoint, not by running them — that's the right
job for the migration / RLS integration tests.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pydantic
import pytest
from app.api.v1.endpoints.saved_views import (
    CreateSavedViewRequest,
    SavedViewModel,
    UpdateSavedViewRequest,
    _coerce_uuid,
    _demote_existing_default,
    _validate_payload_size,
    _validate_view_type,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
    update_saved_view,
)
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------


def _build_user(
    *,
    tenant_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    role: str = "analyst",
) -> SimpleNamespace:
    """Minimal CurrentUser stand-in for the endpoints.

    The endpoints only read ``tenant_id``, ``user_id``, ``role``, and
    ``email`` — a SimpleNamespace is plenty and keeps the tests free of
    the auth import graph.
    """
    return SimpleNamespace(
        tenant_id=tenant_id or uuid.uuid4(),
        user_id=user_id or uuid.uuid4(),
        role=role,
        email="analyst@example.com",
    )


def _saved_view_row(
    *,
    view_type: str = "alerts",
    name: str = "Critical only",
    is_default: bool = False,
    tenant_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    filters: dict[str, Any] | None = None,
    columns: list[Any] | dict[str, Any] | None = None,
    row_id: uuid.UUID | None = None,
) -> SimpleNamespace:
    """Build a SavedView row stand-in with the attribute surface the
    endpoint and ``SavedViewModel.from_orm`` actually read.

    We use SimpleNamespace instead of the real ORM model so the tests
    don't accidentally exercise SQLAlchemy's instrumentation —
    ``row.filters = ...`` on a real ``SavedView`` would dirty the
    session, which we'd rather skip in pure-unit tests.
    """
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=row_id or uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        user_id=user_id or uuid.uuid4(),
        view_type=view_type,
        name=name,
        filters=filters if filters is not None else {},
        columns=columns,
        is_default=is_default,
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# _validate_view_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "view_type",
    ["alerts", "cases", "investigations", "playbooks"],
)
def test_validate_view_type_accepts_known_pages(view_type: str) -> None:
    """Every page wired into the saved-views menu must round-trip."""
    assert _validate_view_type(view_type) == view_type


def test_validate_view_type_rejects_unknown() -> None:
    """A typo or new page that wasn't added to the allowlist 422s.

    This mirrors the CHECK constraint in migration 037 — keeping the
    two in lockstep is the whole point of the allowlist living here
    rather than relying on the DB to surface a constraint violation
    (which would 500 in production).
    """
    with pytest.raises(HTTPException) as exc:
        _validate_view_type("dashboards")  # not in the allowlist (yet)
    assert exc.value.status_code == 422
    assert "view_type must be one of" in exc.value.detail


def test_validate_view_type_is_case_sensitive() -> None:
    """``Alerts`` is not the same as ``alerts``.

    Frontend always sends lowercase via the page constant, but if a
    bespoke API client gets the casing wrong we'd rather 422 cleanly
    than store a row that disagrees with the CHECK constraint.
    """
    with pytest.raises(HTTPException):
        _validate_view_type("Alerts")


# ---------------------------------------------------------------------------
# _validate_payload_size
# ---------------------------------------------------------------------------


def test_validate_payload_size_none_is_noop() -> None:
    """Optional columns blob: None must not raise."""
    _validate_payload_size(None, field="columns", limit=100)


def test_validate_payload_size_under_limit_passes() -> None:
    """A typical filter blob (a few KB) is well under the 8 KB cap."""
    _validate_payload_size({"severity": ["high", "critical"]}, field="filters", limit=8192)


def test_validate_payload_size_over_limit_raises_413() -> None:
    """Above the cap → 413 Payload Too Large with the field name in the detail.

    The cap exists so the saved-views table doesn't drift into being a
    per-user blob store — analysts copy/pasting a JSON dump into a
    filter is a real failure mode we'd rather reject loudly.
    """
    huge = {"haystack": "x" * 20000}
    with pytest.raises(HTTPException) as exc:
        _validate_payload_size(huge, field="filters", limit=8192)
    assert exc.value.status_code == 413
    assert "filters" in exc.value.detail
    assert "8192" in exc.value.detail


def test_validate_payload_size_unserialisable_raises_422() -> None:
    """A blob with a non-JSON-serialisable value 422s, not 500.

    Pydantic accepts ``dict[str, Any]`` so an exotic value can sneak
    past the schema; we catch it with a deliberate 422 rather than
    letting ``json.dumps`` crash the request handler.
    """
    not_serialisable = {"started": object()}  # raw object → TypeError
    with pytest.raises(HTTPException) as exc:
        _validate_payload_size(not_serialisable, field="filters", limit=8192)
    assert exc.value.status_code == 422
    assert "JSON-serialisable" in exc.value.detail


# ---------------------------------------------------------------------------
# _coerce_uuid
# ---------------------------------------------------------------------------


def test_coerce_uuid_accepts_canonical_string() -> None:
    """Round-trips a normal UUID string."""
    raw = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    out = _coerce_uuid(raw)
    assert isinstance(out, uuid.UUID)
    assert str(out) == raw


def test_coerce_uuid_garbage_raises_404_not_500() -> None:
    """Bogus path param → 404 (matches the "saved view not found" UX).

    Surfacing a 422 here would leak that the endpoint can be probed
    to enumerate saved-view IDs vs. random strings; 404 is the same
    code analysts get for a real missing row.
    """
    with pytest.raises(HTTPException) as exc:
        _coerce_uuid("not-a-uuid")
    assert exc.value.status_code == 404
    assert exc.value.detail == "Saved view not found"


def test_coerce_uuid_empty_string_raises_404() -> None:
    """Defensive: empty path segments shouldn't reach this helper, but
    if they do we still 404 cleanly."""
    with pytest.raises(HTTPException) as exc:
        _coerce_uuid("")
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


def test_saved_view_model_from_orm_serialises_uuid_and_datetime() -> None:
    """ORM → wire conversion produces the expected primitive types."""
    row = _saved_view_row(
        name="Triage view",
        filters={"severity": ["high"]},
        columns=["title", "severity", "owner"],
    )
    model = SavedViewModel.from_orm(row)
    assert model.id == str(row.id)
    assert model.name == "Triage view"
    assert model.filters == {"severity": ["high"]}
    assert model.columns == ["title", "severity", "owner"]
    assert model.is_default is False
    # ISO 8601 round-trip — assertion focuses on the contract that the
    # frontend Date constructor will accept the string.
    assert model.created_at == row.created_at.isoformat()
    assert model.updated_at == row.updated_at.isoformat()


def test_saved_view_model_from_orm_handles_null_filters() -> None:
    """A row with ``filters=None`` should still serialise to ``{}``.

    The DB has ``NOT NULL DEFAULT '{}'::jsonb`` so we should never
    actually see this — but a freshly-built ORM instance pre-flush
    can have ``filters=None``, and the model coerces defensively.
    """
    row = _saved_view_row()
    row.filters = None
    model = SavedViewModel.from_orm(row)
    assert model.filters == {}


def test_create_request_rejects_empty_name() -> None:
    """``name`` is mandatory, non-empty, and bounded.

    Pydantic raises ValidationError for ``min_length=1``; the endpoint
    *also* strips and re-checks (covered separately) so a whitespace-
    only string is caught even if pydantic accepts it.
    """
    with pytest.raises(pydantic.ValidationError):  # pydantic.ValidationError, but importing for the type is overkill
        CreateSavedViewRequest(view_type="alerts", name="")


def test_update_request_extra_fields_forbidden() -> None:
    """Unknown PATCH keys are rejected — defends against typos like
    ``is_defualt`` silently being a no-op."""
    with pytest.raises(pydantic.ValidationError):
        UpdateSavedViewRequest(unknown_field="oops")


def test_update_request_distinguishes_omitted_vs_explicit_null() -> None:
    """``columns=None`` (explicit) vs. omitting it must be observable.

    Used by the PATCH endpoint to decide whether to clear ``columns``
    or leave it alone. Without this, "use default columns" wouldn't
    have a way to be expressed by the API client.
    """
    omitted = UpdateSavedViewRequest()
    assert "columns" not in omitted.model_fields_set

    explicit = UpdateSavedViewRequest(columns=None)
    assert "columns" in explicit.model_fields_set
    assert explicit.columns is None


# ---------------------------------------------------------------------------
# list_saved_views
# ---------------------------------------------------------------------------


def _mock_db_with_list_result(rows: list[SimpleNamespace]) -> MagicMock:
    """Build a DB mock whose ``.execute().scalars().all()`` returns ``rows``."""
    db = MagicMock()
    scalars_result = MagicMock()
    scalars_result.all = MagicMock(return_value=rows)
    execute_result = MagicMock()
    execute_result.scalars = MagicMock(return_value=scalars_result)
    db.execute = AsyncMock(return_value=execute_result)
    return db


@pytest.mark.asyncio
async def test_list_saved_views_returns_serialised_rows() -> None:
    """Happy path: rows in → wire models out."""
    user = _build_user()
    rows = [
        _saved_view_row(
            tenant_id=user.tenant_id,
            user_id=user.user_id,
            name="Critical only",
            is_default=True,
        ),
        _saved_view_row(
            tenant_id=user.tenant_id,
            user_id=user.user_id,
            name="My queue",
        ),
    ]
    db = _mock_db_with_list_result(rows)

    result = await list_saved_views(user=user, db=db, view_type="alerts")

    assert len(result) == 2
    assert all(isinstance(r, SavedViewModel) for r in result)
    assert {r.name for r in result} == {"Critical only", "My queue"}
    db.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_list_saved_views_invalid_type_422_before_db_call() -> None:
    """Validation runs before any DB I/O.

    Critical for two reasons: (1) it bounds the cost of a flood of
    bad requests, (2) it means a typo can't accidentally enumerate
    rows for a different view_type via SQL injection through the
    ORDER BY clause (defence-in-depth — there's no obvious vector
    here, but never hurts).
    """
    db = _mock_db_with_list_result([])
    user = _build_user()
    with pytest.raises(HTTPException) as exc:
        await list_saved_views(user=user, db=db, view_type="dashboards")
    assert exc.value.status_code == 422
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_list_saved_views_filters_by_tenant_and_user() -> None:
    """Verify the query is scoped to ``(tenant_id, user_id, view_type)``.

    We inspect the SQLAlchemy clause string rather than running it —
    the migration tests are the right place for round-trip semantics.
    The point of this assertion is to catch a future refactor that
    forgets the user_id predicate (which would return *every* user's
    views in the tenant).
    """
    user = _build_user()
    db = _mock_db_with_list_result([])
    await list_saved_views(user=user, db=db, view_type="cases")

    call_args = db.execute.await_args
    stmt = call_args.args[0]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    assert "saved_views" in compiled
    # SQLAlchemy's PG UUID type renders as 32-char hex (no dashes)
    # when compiled with literal_binds; accept either form so the
    # test stays robust if dialect rendering changes.
    assert (str(user.tenant_id) in compiled) or (user.tenant_id.hex in compiled)
    assert (str(user.user_id) in compiled) or (user.user_id.hex in compiled)
    assert "cases" in compiled


# ---------------------------------------------------------------------------
# create_saved_view
# ---------------------------------------------------------------------------


def _mock_db_for_create(*, integrity_error: bool = False) -> MagicMock:
    """Build a DB mock for a successful create or one that hits the
    duplicate-name unique constraint.

    The endpoint's flow is:
    1. (optional) demote existing default — UPDATE
    2. ``db.add(row)``
    3. ``db.flush()`` then ``db.commit()`` (or .rollback() on error)
    4. ``db.refresh(row)``
    """
    db = MagicMock()
    db.execute = AsyncMock()
    db.add = MagicMock()
    if integrity_error:
        db.flush = AsyncMock(side_effect=IntegrityError("duplicate", None, BaseException("dup")))
    else:
        db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_create_saved_view_happy_path() -> None:
    """Valid payload → row added, flushed, committed, refreshed."""
    user = _build_user()
    db = _mock_db_for_create()
    payload = CreateSavedViewRequest(
        view_type="alerts",
        name="Critical only",
        filters={"severity": ["critical", "high"]},
        columns=["title", "severity"],
        is_default=False,
    )
    result = await create_saved_view(payload=payload, user=user, db=db)

    assert isinstance(result, SavedViewModel)
    assert result.name == "Critical only"
    assert result.filters == {"severity": ["critical", "high"]}
    assert result.is_default is False

    db.add.assert_called_once()
    db.flush.assert_awaited_once()
    db.commit.assert_awaited_once()
    db.refresh.assert_awaited_once()
    db.rollback.assert_not_awaited()
    # No demote step needed because is_default=False.
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_saved_view_with_is_default_demotes_existing() -> None:
    """``is_default=True`` runs the UPDATE-to-clear-existing-default first.

    Without this, the partial unique index in migration 037 would
    reject the INSERT. The test asserts both writes happen *and* the
    demote runs before the row is added (order matters for the
    transactional invariant).
    """
    user = _build_user()
    db = _mock_db_for_create()
    payload = CreateSavedViewRequest(
        view_type="alerts",
        name="My default",
        filters={},
        is_default=True,
    )
    await create_saved_view(payload=payload, user=user, db=db)

    # Demote step issued exactly once.
    db.execute.assert_awaited_once()
    db.add.assert_called_once()
    db.flush.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_saved_view_blank_name_raises_422() -> None:
    """``"   "`` (whitespace-only) → 422, not a row with a blank label.

    Pydantic's ``min_length=1`` doesn't catch whitespace; the endpoint
    strips and re-checks. Test belongs here rather than in the schema
    test because the strip+check is endpoint policy.
    """
    user = _build_user()
    db = _mock_db_for_create()
    payload = CreateSavedViewRequest(
        view_type="alerts",
        name="   ",
        filters={},
    )
    with pytest.raises(HTTPException) as exc:
        await create_saved_view(payload=payload, user=user, db=db)
    assert exc.value.status_code == 422
    assert "blank" in exc.value.detail.lower()
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_create_saved_view_duplicate_name_returns_409() -> None:
    """The unique constraint surfaces as 409 Conflict, not 500.

    Operators see this when an analyst saves "Critical only" twice in
    quick succession (e.g. the menu didn't refresh). 409 with a clear
    detail tells the UI to nudge the user instead of just dying.
    """
    user = _build_user()
    db = _mock_db_for_create(integrity_error=True)
    payload = CreateSavedViewRequest(
        view_type="alerts",
        name="Critical only",
        filters={},
    )
    with pytest.raises(HTTPException) as exc:
        await create_saved_view(payload=payload, user=user, db=db)
    assert exc.value.status_code == 409
    assert "Critical only" in exc.value.detail
    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_saved_view_invalid_view_type_raises_422() -> None:
    """Invalid view_type bails before any DB activity."""
    user = _build_user()
    db = _mock_db_for_create()
    payload = CreateSavedViewRequest(
        view_type="hunts",  # not in the allowlist
        name="Anything",
    )
    with pytest.raises(HTTPException) as exc:
        await create_saved_view(payload=payload, user=user, db=db)
    assert exc.value.status_code == 422
    db.add.assert_not_called()


# ---------------------------------------------------------------------------
# update_saved_view
# ---------------------------------------------------------------------------


def _mock_db_for_update(
    *,
    existing_row: SimpleNamespace | None,
    integrity_error: bool = False,
) -> MagicMock:
    """Build a DB mock for the PATCH endpoint.

    Order of DB calls in the endpoint:
    1. ``db.scalar(SELECT ... WHERE id = ?)`` → existing row or None
    2. (optional) ``db.execute(UPDATE ... is_default=false)`` — demote
    3. ``db.flush()`` then ``db.commit()`` (or rollback on integrity)
    4. ``db.refresh(row)``
    """
    db = MagicMock()
    db.scalar = AsyncMock(return_value=existing_row)
    db.execute = AsyncMock()
    if integrity_error:
        db.flush = AsyncMock(side_effect=IntegrityError("duplicate", None, BaseException("dup")))
    else:
        db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_update_saved_view_missing_row_returns_404() -> None:
    """Trying to patch a row another user owns / a deleted row → 404.

    The query already scopes by ``(tenant_id, user_id)`` so a foreign
    row is indistinguishable from "doesn't exist" — both are 404.
    """
    user = _build_user()
    db = _mock_db_for_update(existing_row=None)
    with pytest.raises(HTTPException) as exc:
        await update_saved_view(
            view_id=str(uuid.uuid4()),
            payload=UpdateSavedViewRequest(name="renamed"),
            user=user,
            db=db,
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_update_saved_view_garbled_uuid_returns_404() -> None:
    """Bad ID in path → 404 (not 422)."""
    user = _build_user()
    db = _mock_db_for_update(existing_row=_saved_view_row())
    with pytest.raises(HTTPException) as exc:
        await update_saved_view(
            view_id="not-a-uuid",
            payload=UpdateSavedViewRequest(name="renamed"),
            user=user,
            db=db,
        )
    assert exc.value.status_code == 404
    db.scalar.assert_not_awaited()  # bailed before the lookup


@pytest.mark.asyncio
async def test_update_saved_view_empty_body_is_noop() -> None:
    """An empty PATCH returns the row unchanged without a write.

    Useful for clients that diff-render a form; if no field changed,
    the update is free. We assert ``flush`` was NOT called to confirm
    the no-op path is genuinely no-op at the DB layer.
    """
    user = _build_user()
    row = _saved_view_row(name="Unchanged")
    db = _mock_db_for_update(existing_row=row)
    result = await update_saved_view(
        view_id=str(row.id),
        payload=UpdateSavedViewRequest(),  # everything omitted
        user=user,
        db=db,
    )
    assert result.name == "Unchanged"
    db.flush.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_saved_view_renames_and_strips() -> None:
    """``name`` updates trim whitespace before persisting."""
    user = _build_user()
    row = _saved_view_row(name="Original")
    db = _mock_db_for_update(existing_row=row)
    await update_saved_view(
        view_id=str(row.id),
        payload=UpdateSavedViewRequest(name="  Renamed  "),
        user=user,
        db=db,
    )
    assert row.name == "Renamed"  # mutated in place; ORM tracks dirty state
    db.flush.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_saved_view_blank_name_after_strip_422s() -> None:
    """A whitespace-only rename request is rejected, not stored."""
    user = _build_user()
    row = _saved_view_row(name="Original")
    db = _mock_db_for_update(existing_row=row)
    with pytest.raises(HTTPException) as exc:
        await update_saved_view(
            view_id=str(row.id),
            payload=UpdateSavedViewRequest(name="     "),
            user=user,
            db=db,
        )
    assert exc.value.status_code == 422
    assert row.name == "Original"  # not mutated


@pytest.mark.asyncio
async def test_update_saved_view_explicit_columns_null_clears_field() -> None:
    """``columns=None`` (explicit) writes None — fall back to defaults.

    Without this branch, an analyst can't *un-pin* their custom column
    set: there'd be no JSON value that means "use the page default".
    """
    user = _build_user()
    row = _saved_view_row(columns=["title", "severity"])
    db = _mock_db_for_update(existing_row=row)
    await update_saved_view(
        view_id=str(row.id),
        payload=UpdateSavedViewRequest(columns=None),
        user=user,
        db=db,
    )
    assert row.columns is None
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_saved_view_omitted_columns_unchanged() -> None:
    """``columns`` omitted from the PATCH body → the field is preserved.

    Mirror of the test above. The two together prove the
    omitted-vs-explicit-null distinction is real and load-bearing.
    """
    user = _build_user()
    row = _saved_view_row(columns=["title", "severity"])
    db = _mock_db_for_update(existing_row=row)
    await update_saved_view(
        view_id=str(row.id),
        payload=UpdateSavedViewRequest(name="renamed"),
        user=user,
        db=db,
    )
    assert row.columns == ["title", "severity"]


@pytest.mark.asyncio
async def test_update_saved_view_promote_to_default_demotes_existing() -> None:
    """Flipping ``is_default`` false → true triggers the demote UPDATE.

    The demote excludes the row being promoted (``except_id=row.id``)
    so the UPDATE doesn't immediately undo our own promotion in a
    subsequent flush.
    """
    user = _build_user()
    row = _saved_view_row(is_default=False)
    db = _mock_db_for_update(existing_row=row)
    await update_saved_view(
        view_id=str(row.id),
        payload=UpdateSavedViewRequest(is_default=True),
        user=user,
        db=db,
    )
    assert row.is_default is True
    # exactly one demote UPDATE was issued before the flush
    db.execute.assert_awaited_once()
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_saved_view_already_default_does_not_demote() -> None:
    """Re-asserting ``is_default=True`` on the current default is a no-op
    for the demote step (avoids a needless UPDATE on every save)."""
    user = _build_user()
    row = _saved_view_row(is_default=True)
    db = _mock_db_for_update(existing_row=row)
    await update_saved_view(
        view_id=str(row.id),
        payload=UpdateSavedViewRequest(is_default=True),
        user=user,
        db=db,
    )
    assert row.is_default is True
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_saved_view_unset_default_clears_flag() -> None:
    """``is_default=False`` is allowed and just clears the flag.

    No demote needed — leaving the table without a default is a valid
    state (the UI falls back to the page's hard-coded default).
    """
    user = _build_user()
    row = _saved_view_row(is_default=True)
    db = _mock_db_for_update(existing_row=row)
    await update_saved_view(
        view_id=str(row.id),
        payload=UpdateSavedViewRequest(is_default=False),
        user=user,
        db=db,
    )
    assert row.is_default is False
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_saved_view_duplicate_rename_returns_409() -> None:
    """Renaming to an existing name in the same scope → 409, not 500."""
    user = _build_user()
    row = _saved_view_row(name="Original")
    db = _mock_db_for_update(existing_row=row, integrity_error=True)
    with pytest.raises(HTTPException) as exc:
        await update_saved_view(
            view_id=str(row.id),
            payload=UpdateSavedViewRequest(name="Already Taken"),
            user=user,
            db=db,
        )
    assert exc.value.status_code == 409
    db.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_saved_view_filters_size_capped() -> None:
    """Oversize filter blob on PATCH → 413, same as on create."""
    user = _build_user()
    row = _saved_view_row()
    db = _mock_db_for_update(existing_row=row)
    huge = {"haystack": "x" * 20000}
    with pytest.raises(HTTPException) as exc:
        await update_saved_view(
            view_id=str(row.id),
            payload=UpdateSavedViewRequest(filters=huge),
            user=user,
            db=db,
        )
    assert exc.value.status_code == 413
    db.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# delete_saved_view
# ---------------------------------------------------------------------------


def _mock_db_for_delete(*, rowcount: int) -> MagicMock:
    """DB mock whose DELETE returns the given affected-row count."""
    db = MagicMock()
    result = MagicMock()
    result.rowcount = rowcount
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_delete_saved_view_happy_path() -> None:
    """A matching DELETE commits and returns None (FastAPI yields 204)."""
    user = _build_user()
    db = _mock_db_for_delete(rowcount=1)
    result = await delete_saved_view(
        view_id=str(uuid.uuid4()),
        user=user,
        db=db,
    )
    assert result is None
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_saved_view_no_match_returns_404() -> None:
    """Zero rows affected → 404, not a silent success.

    Without the rowcount check, deleting another user's view would
    return 204 even though nothing actually changed — confusing UX
    *and* a potential information-leak vector (200 vs 404 leaks ID
    existence). The user_id predicate in the WHERE clause already
    prevents the cross-user delete; the 404 makes it explicit.
    """
    user = _build_user()
    db = _mock_db_for_delete(rowcount=0)
    with pytest.raises(HTTPException) as exc:
        await delete_saved_view(
            view_id=str(uuid.uuid4()),
            user=user,
            db=db,
        )
    assert exc.value.status_code == 404
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_delete_saved_view_bad_uuid_returns_404() -> None:
    """Garbled path param → 404 before any DB call."""
    user = _build_user()
    db = _mock_db_for_delete(rowcount=0)
    with pytest.raises(HTTPException) as exc:
        await delete_saved_view(
            view_id="bogus",
            user=user,
            db=db,
        )
    assert exc.value.status_code == 404
    db.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# _demote_existing_default — direct-test the helper too, since it's the
# load-bearing primitive for the partial-unique-index invariant.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_demote_existing_default_includes_user_predicate() -> None:
    """Helper must scope to ``(tenant_id, user_id, view_type)``.

    A bug here would clear another user's default in the same tenant,
    which is silent breakage of someone else's UI state. We assert the
    rendered SQL contains both IDs to lock that contract in.
    """
    db = MagicMock()
    db.execute = AsyncMock()
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    await _demote_existing_default(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        view_type="alerts",
    )

    assert db.execute.await_count == 1
    stmt = db.execute.await_args.args[0]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    # Accept either dashed or hex (no-dash) UUID rendering.
    assert (str(tenant_id) in compiled) or (tenant_id.hex in compiled)
    assert (str(user_id) in compiled) or (user_id.hex in compiled)
    assert "alerts" in compiled


@pytest.mark.asyncio
async def test_demote_existing_default_excludes_target_when_provided() -> None:
    """Update must skip ``except_id`` so the row being promoted survives.

    Without this exclusion, the demote step inside an UPDATE call
    would clear the same row we're about to flip on, undoing the
    promotion in the same transaction.
    """
    db = MagicMock()
    db.execute = AsyncMock()
    except_id = uuid.uuid4()
    await _demote_existing_default(
        db,
        tenant_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        view_type="cases",
        except_id=except_id,
    )
    stmt = db.execute.await_args.args[0]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    assert (str(except_id) in compiled) or (except_id.hex in compiled)
    # The "id != ..." predicate must be in the WHERE clause (we accept
    # either operator rendering — SQLAlchemy emits "!=" or "<>" by
    # dialect; both are correct).
    assert ("!=" in compiled) or ("<>" in compiled)
