"""Tests for the saved-hunts CRUD + scheduler — Track 3, T3.4.

The saved-hunts surface backs the ``/hunt`` page. Like the sibling
``test_saved_views_endpoint`` tests in this folder, we mock the DB
session directly rather than spinning up the full FastAPI app +
Postgres harness — the goal is to keep these checks fast (sub-second)
and pinned to the endpoint's *contract* (validation, scoping,
translator integration, status codes) rather than the SQL emitted.

Coverage map
~~~~~~~~~~~~

* ``_validate_cron`` — accepts known-good cadences, rejects garbage
  before we hit the DB.
* ``CreateSavedHuntRequest`` — schema-level validation (name length,
  nl_query length, language enum).
* ``create_saved_hunt`` — translates server-side, persists with the
  caller's ``tenant_id``/``created_by``, surfaces IntegrityError as
  409, blank inputs return 422.
* ``list_saved_hunts`` — scopes by tenant, returns sorted ORM rows.
* ``get_saved_hunt`` — 404 on garbled id, 404 on cross-tenant id.
* ``delete_saved_hunt`` — 204 on hit, 404 on miss.
* ``run_saved_hunt`` — re-translates, stamps ``last_run_at``, returns
  the fresh envelope.
* ``hunt_scheduler.run_once`` — schedule registration: a row with a
  ``schedule`` is picked up, the executor + hit-callback are invoked
  with the right arguments, and ``last_run_at`` is stamped. Mocks the
  executor so no Elasticsearch is required.

Author: Track 3 / T3.4 (`/hunt` NL surface).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pydantic
import pytest
from app.api.v1.endpoints.saved_hunts import (
    CreateSavedHuntRequest,
    SavedHuntModel,
    TranslatedQueryEnvelope,
    _coerce_uuid,
    _validate_cron,
    create_saved_hunt,
    delete_saved_hunt,
    get_saved_hunt,
    list_saved_hunts,
    run_saved_hunt,
)
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _build_user(
    *,
    tenant_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    role: str = "analyst",
) -> SimpleNamespace:
    """Minimal AuthUser stand-in for the endpoints.

    The endpoints only read ``tenant_id`` and ``user_id`` — a
    SimpleNamespace keeps the tests free of the real auth import graph
    (which pulls in JWT decoding + DB-backed user lookup).
    """
    return SimpleNamespace(
        tenant_id=tenant_id or uuid.uuid4(),
        user_id=user_id or uuid.uuid4(),
        role=role,
        email="analyst@example.com",
    )


def _saved_hunt_row(
    *,
    name: str = "Iran inbound",
    nl_query: str = "Did we get any new attacks from Iran?",
    language: str = "esql",
    schedule: str | None = None,
    last_run_at: datetime | None = None,
    tenant_id: uuid.UUID | None = None,
    created_by: uuid.UUID | None = None,
    row_id: uuid.UUID | None = None,
    translated: dict[str, Any] | None = None,
) -> SimpleNamespace:
    """Build a SavedHunt-shaped ORM stand-in.

    SimpleNamespace keeps SQLAlchemy's instrumentation out of the test
    path — assigning to ``row.last_run_at`` on a real ORM instance
    would dirty the session, which is irrelevant for unit checks.
    """
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=row_id or uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        created_by=created_by,
        name=name,
        nl_query=nl_query,
        translated_query=translated or {"esql": "FROM logs-* | LIMIT 10", "kql": "", "spl": "", "explanation": ""},
        language=language,
        schedule=schedule,
        last_run_at=last_run_at,
        created_at=now,
        updated_at=now,
    )


def _mock_scalar_db(value: Any) -> MagicMock:
    """DB session whose ``.scalar()`` returns *value*."""
    db = MagicMock()
    db.scalar = AsyncMock(return_value=value)
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.rollback = AsyncMock()
    db.execute = AsyncMock()
    return db


def _mock_list_db(rows: list[SimpleNamespace]) -> MagicMock:
    """DB session whose ``execute().scalars().all()`` returns *rows*."""
    db = MagicMock()
    scalars_result = MagicMock()
    scalars_result.all = MagicMock(return_value=rows)
    execute_result = MagicMock()
    execute_result.scalars = MagicMock(return_value=scalars_result)
    execute_result.rowcount = len(rows)
    db.execute = AsyncMock(return_value=execute_result)
    db.commit = AsyncMock()
    db.scalar = AsyncMock(return_value=None)
    return db


# ---------------------------------------------------------------------------
# _validate_cron
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "schedule",
    [
        "0 */6 * * *",
        "*/15 * * * *",
        "0 0 * * 1",
        "30 9 * * 1-5",
        "0 0,12 * * *",
    ],
)
def test_validate_cron_accepts_common_cadences(schedule: str) -> None:
    """Every cadence the worker can parse must round-trip through validation.

    These five strings exercise the common SOC schedules (every N
    minutes, every N hours, top of the hour, weekday-only, twice
    daily). If we tighten this whitelist later we should bump
    :mod:`app.workers.hunt_scheduler` in lockstep.
    """
    assert _validate_cron(schedule) == schedule


def test_validate_cron_strips_surrounding_whitespace() -> None:
    """``"  0 * * * *  "`` is normalised to ``"0 * * * *"`` rather than 422."""
    assert _validate_cron("  0 * * * *  ") == "0 * * * *"


@pytest.mark.parametrize(
    "schedule",
    [
        "* * * *",  # 4 fields
        "* * * * * *",  # 6 fields (cron-with-seconds)
        "0 0 0 0",  # 4 fields
        "",  # empty
    ],
)
def test_validate_cron_rejects_wrong_field_count(schedule: str) -> None:
    """Anything that isn't exactly 5 fields 422s before we hit the DB."""
    with pytest.raises(HTTPException) as exc:
        _validate_cron(schedule)
    assert exc.value.status_code == 422


def test_validate_cron_rejects_unsupported_characters() -> None:
    """``? L W`` and friends from extended cron dialects 422.

    Keeping the character set tight stops a typo from being persisted
    as a "schedule" the worker silently never fires.
    """
    with pytest.raises(HTTPException) as exc:
        _validate_cron("0 * ? * *")
    assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


def test_create_request_rejects_blank_name() -> None:
    """``name`` is mandatory and non-empty (Pydantic-level)."""
    with pytest.raises(pydantic.ValidationError):
        CreateSavedHuntRequest(name="", nl_query="failed logins")


def test_create_request_rejects_short_nl_query() -> None:
    """A two-character question is below the floor."""
    with pytest.raises(pydantic.ValidationError):
        CreateSavedHuntRequest(name="x", nl_query="ok")


def test_create_request_rejects_unknown_language() -> None:
    """Language is restricted to ``esql | kql | spl``."""
    with pytest.raises(pydantic.ValidationError):
        CreateSavedHuntRequest(
            name="x",
            nl_query="failed logins",
            language="xquery",  # type: ignore[arg-type]
        )


def test_create_request_accepts_all_known_languages() -> None:
    for lang in ("esql", "kql", "spl"):
        req = CreateSavedHuntRequest(name="x", nl_query="failed logins", language=lang)  # type: ignore[arg-type]
        assert req.language == lang


def test_saved_hunt_model_serialises_translator_envelope() -> None:
    """``SavedHuntModel.from_orm`` returns the wire shape the frontend expects."""
    row = _saved_hunt_row(
        translated={
            "esql": "FROM logs-* | LIMIT 10",
            "kql": "SecurityEvent | take 10",
            "spl": "index=* | head 10",
            "explanation": "Translates the question by limited to 10 rows.",
        }
    )
    model = SavedHuntModel.from_orm(row)
    assert model.id == str(row.id)
    assert model.translated_query.esql.startswith("FROM logs-*")
    assert model.translated_query.kql == "SecurityEvent | take 10"
    assert model.translated_query.spl == "index=* | head 10"
    assert model.created_at == row.created_at.isoformat()
    assert model.last_run_at is None


def test_saved_hunt_model_handles_missing_translation_keys() -> None:
    """Defensive: a row mid-migration with a sparse JSONB still serialises."""
    row = _saved_hunt_row(translated={"esql": "FROM x"})
    model = SavedHuntModel.from_orm(row)
    assert model.translated_query.esql == "FROM x"
    assert model.translated_query.kql == ""
    assert model.translated_query.spl == ""


def test_saved_hunt_model_handles_null_translation() -> None:
    """A freshly-built ORM row can have ``translated_query=None`` pre-flush.

    The ``from_orm`` helper coerces to an empty envelope rather than
    crashing — important because the list endpoint streams whatever
    the DB returns and we don't want one bad row to 500 the whole
    response.
    """
    row = _saved_hunt_row()
    row.translated_query = None  # simulate the pre-flush None case directly
    model = SavedHuntModel.from_orm(row)
    assert model.translated_query.model_dump() == TranslatedQueryEnvelope().model_dump()


# ---------------------------------------------------------------------------
# _coerce_uuid
# ---------------------------------------------------------------------------


def test_coerce_uuid_accepts_canonical_string() -> None:
    raw = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    out = _coerce_uuid(raw)
    assert isinstance(out, uuid.UUID)
    assert str(out) == raw


def test_coerce_uuid_garbage_is_404_not_500() -> None:
    """Bogus path param → 404 (matches the "saved hunt not found" UX)."""
    with pytest.raises(HTTPException) as exc:
        _coerce_uuid("not-a-uuid")
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# list_saved_hunts
# ---------------------------------------------------------------------------


def test_list_saved_hunts_scopes_by_tenant() -> None:
    """Endpoint returns one row per match, scoped to the caller's tenant."""
    user = _build_user()
    rows = [_saved_hunt_row(name=f"Hunt {i}", tenant_id=user.tenant_id) for i in range(3)]
    db = _mock_list_db(rows)

    out = asyncio.run(list_saved_hunts(user, db))

    assert len(out) == 3
    assert {h.name for h in out} == {"Hunt 0", "Hunt 1", "Hunt 2"}
    db.execute.assert_awaited_once()


def test_list_saved_hunts_empty_returns_empty_list() -> None:
    user = _build_user()
    db = _mock_list_db([])
    out = asyncio.run(list_saved_hunts(user, db))
    assert out == []


# ---------------------------------------------------------------------------
# create_saved_hunt
# ---------------------------------------------------------------------------


def test_create_saved_hunt_translates_and_persists(monkeypatch: pytest.MonkeyPatch) -> None:
    """Happy path: translator runs, row is added, ``201`` payload is correct."""
    user = _build_user()

    # Stub the translator so the test doesn't depend on the live grammar
    # (the actual translator is exercised separately in nl_query tests).
    fake_envelope = TranslatedQueryEnvelope(
        esql='FROM logs-* | WHERE source.geo.country_iso_code == "IR" | LIMIT 500',
        kql='SecurityEvent | where source_geo_country_iso_code == "IR" | take 500',
        spl='index=* source_geo_country_iso_code="IR"',
        explanation="Translates the question by filtering on country code IR.",
    )
    monkeypatch.setattr("app.api.v1.endpoints.saved_hunts._translate", lambda _q: fake_envelope)

    captured: dict[str, Any] = {}

    def _fake_add(row: Any) -> None:
        captured["row"] = row

    db = _mock_scalar_db(None)
    db.add = MagicMock(side_effect=_fake_add)

    async def _refresh(row: Any) -> None:
        # Simulate the DB-side defaults that ``refresh`` would populate.
        row.created_at = row.created_at or datetime.now(UTC)
        row.updated_at = row.updated_at or datetime.now(UTC)

    db.refresh = AsyncMock(side_effect=_refresh)

    payload = CreateSavedHuntRequest(
        name="Iran inbound",
        nl_query="Did we get any new attacks from Iran?",
    )

    out = asyncio.run(create_saved_hunt(payload, user, db))

    assert out.name == "Iran inbound"
    assert out.translated_query.esql.startswith("FROM logs-*")
    assert "IR" in out.translated_query.esql

    persisted = captured["row"]
    assert persisted.tenant_id == user.tenant_id
    assert persisted.created_by == user.user_id
    assert persisted.nl_query == "Did we get any new attacks from Iran?"
    db.commit.assert_awaited_once()


def test_create_saved_hunt_blank_name_returns_422(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only names slip past Pydantic but the endpoint rejects them.

    Pydantic ``min_length=1`` accepts ``" "`` because length is computed
    pre-strip. The endpoint strips and re-checks so the DB never sees a
    blank ``name`` (and the unique constraint isn't gamed by spaces).
    """
    user = _build_user()
    monkeypatch.setattr(
        "app.api.v1.endpoints.saved_hunts._translate",
        lambda _q: TranslatedQueryEnvelope(),
    )
    db = _mock_scalar_db(None)
    payload = CreateSavedHuntRequest(name="    ", nl_query="failed logins")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(create_saved_hunt(payload, user, db))
    assert exc.value.status_code == 422


def test_create_saved_hunt_duplicate_name_returns_409(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two saved hunts with the same name in one tenant collide on the unique
    index — the endpoint surfaces that as 409 (not 500)."""
    user = _build_user()
    monkeypatch.setattr(
        "app.api.v1.endpoints.saved_hunts._translate",
        lambda _q: TranslatedQueryEnvelope(),
    )
    db = _mock_scalar_db(None)
    db.flush = AsyncMock(side_effect=IntegrityError("INSERT", {}, Exception("dup")))
    payload = CreateSavedHuntRequest(name="Iran inbound", nl_query="failed logins")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(create_saved_hunt(payload, user, db))
    assert exc.value.status_code == 409
    db.rollback.assert_awaited()


def test_create_saved_hunt_with_invalid_schedule_422s_before_db(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad cron payload bails before we touch the translator or the DB."""
    user = _build_user()
    translate_calls = {"n": 0}

    def _spy(_q: str) -> TranslatedQueryEnvelope:
        translate_calls["n"] += 1
        return TranslatedQueryEnvelope()

    monkeypatch.setattr("app.api.v1.endpoints.saved_hunts._translate", _spy)
    db = _mock_scalar_db(None)
    payload = CreateSavedHuntRequest(name="Iran inbound", nl_query="failed logins", schedule="not a cron")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(create_saved_hunt(payload, user, db))
    assert exc.value.status_code == 422
    # Translator must not have been invoked — bail early on schema errors.
    assert translate_calls["n"] == 0


# ---------------------------------------------------------------------------
# get_saved_hunt
# ---------------------------------------------------------------------------


def test_get_saved_hunt_returns_row_for_owner() -> None:
    user = _build_user()
    row = _saved_hunt_row(tenant_id=user.tenant_id, created_by=user.user_id)
    db = _mock_scalar_db(row)
    out = asyncio.run(get_saved_hunt(str(row.id), user, db))
    assert out.id == str(row.id)


def test_get_saved_hunt_garbled_id_404s() -> None:
    user = _build_user()
    db = _mock_scalar_db(None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(get_saved_hunt("not-a-uuid", user, db))
    assert exc.value.status_code == 404


def test_get_saved_hunt_other_tenant_404s() -> None:
    """A row exists, but in another tenant → 404 (not 403, to avoid leaking
    that the ID is real)."""
    user = _build_user()
    db = _mock_scalar_db(None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(get_saved_hunt(str(uuid.uuid4()), user, db))
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# delete_saved_hunt
# ---------------------------------------------------------------------------


def test_delete_saved_hunt_204_when_row_existed() -> None:
    user = _build_user()
    db = _mock_list_db([_saved_hunt_row(tenant_id=user.tenant_id)])
    db.execute.return_value.rowcount = 1
    out = asyncio.run(delete_saved_hunt(str(uuid.uuid4()), user, db))
    assert out is None
    db.commit.assert_awaited_once()


def test_delete_saved_hunt_404_when_row_missing() -> None:
    user = _build_user()
    db = _mock_list_db([])
    db.execute.return_value.rowcount = 0
    with pytest.raises(HTTPException) as exc:
        asyncio.run(delete_saved_hunt(str(uuid.uuid4()), user, db))
    assert exc.value.status_code == 404


def test_delete_saved_hunt_garbled_id_404() -> None:
    user = _build_user()
    db = _mock_scalar_db(None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(delete_saved_hunt("not-a-uuid", user, db))
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# run_saved_hunt
# ---------------------------------------------------------------------------


def test_run_saved_hunt_re_translates_and_stamps(monkeypatch: pytest.MonkeyPatch) -> None:
    """Manual run re-translates and updates ``last_run_at`` so the
    scheduler doesn't immediately re-fire the same hunt on the next tick."""
    user = _build_user()
    row = _saved_hunt_row(tenant_id=user.tenant_id)
    db = _mock_scalar_db(row)
    fresh = TranslatedQueryEnvelope(
        esql='FROM logs-* | WHERE source.geo.country_iso_code == "IR" | LIMIT 500',
    )
    monkeypatch.setattr("app.api.v1.endpoints.saved_hunts._translate", lambda _q: fresh)

    out = asyncio.run(run_saved_hunt(str(row.id), user, db))

    assert out.id == str(row.id)
    assert out.translated_query.esql == fresh.esql
    # The endpoint issues a single update — both ``translated_query`` and
    # ``last_run_at`` are bundled into one statement.
    db.execute.assert_awaited_once()
    db.commit.assert_awaited_once()


def test_run_saved_hunt_missing_404s() -> None:
    user = _build_user()
    db = _mock_scalar_db(None)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(run_saved_hunt(str(uuid.uuid4()), user, db))
    assert exc.value.status_code == 404


# ---------------------------------------------------------------------------
# Scheduler — schedule registration + fire callback (mocked)
# ---------------------------------------------------------------------------


def test_scheduler_picks_up_due_hunt_and_fires_callback() -> None:
    """End-to-end scheduler tick using mocks for the executor + callback.

    Verifies the contract the scheduler promises the rest of the
    platform: any saved hunt with a ``schedule`` whose interval has
    elapsed since ``last_run_at`` is fired exactly once per tick, with
    the executor's hit count handed to the case-open callback. We don't
    touch Elasticsearch or the case lifecycle — those live in their own
    unit tests.
    """
    from app.workers import hunt_scheduler

    fired_hunt = _saved_hunt_row(
        schedule="*/5 * * * *",
        last_run_at=datetime.now(UTC) - timedelta(hours=1),
    )

    db = _mock_list_db([fired_hunt])

    captured: dict[str, Any] = {"executor": [], "callback": []}

    async def _fake_executor(_db: Any, hunt: Any) -> int:  # noqa: ANN401
        captured["executor"].append(hunt.id)
        return 7

    async def _fake_callback(
        _db: Any,  # noqa: ANN401
        hunt: Any,  # noqa: ANN401
        hits: int,
    ) -> None:
        captured["callback"].append((hunt.id, hits))

    fired = asyncio.run(
        hunt_scheduler.run_once(
            db=db,
            now=datetime.now(UTC),
            hit_callback=_fake_callback,
            executor=_fake_executor,
        )
    )

    assert fired == 1
    assert captured["executor"] == [fired_hunt.id]
    assert captured["callback"] == [(fired_hunt.id, 7)]
    db.commit.assert_awaited()


def test_scheduler_skips_hunt_without_schedule() -> None:
    """Hunts with ``schedule=None`` are ignored — the SELECT filters them
    out and even a row that slipped through gets skipped by ``_is_due``."""
    from app.workers import hunt_scheduler

    not_scheduled = _saved_hunt_row(schedule=None)
    db = _mock_list_db([not_scheduled])

    async def _executor(*_a: Any, **_k: Any) -> int:
        raise AssertionError("executor must not run for unscheduled hunts")

    async def _callback(*_a: Any, **_k: Any) -> None:
        raise AssertionError("callback must not run for unscheduled hunts")

    fired = asyncio.run(
        hunt_scheduler.run_once(
            db=db,
            now=datetime.now(UTC),
            hit_callback=_callback,
            executor=_executor,
        )
    )
    assert fired == 0


def test_scheduler_skips_hunt_within_cadence() -> None:
    """A scheduled hunt that ran 30 seconds ago on a 5-minute cron is *not*
    due yet — the worker leaves it alone until the interval elapses."""
    from app.workers import hunt_scheduler

    recent = _saved_hunt_row(
        schedule="*/5 * * * *",
        last_run_at=datetime.now(UTC) - timedelta(seconds=30),
    )
    db = _mock_list_db([recent])

    async def _exploding(*_a: Any, **_k: Any) -> int:
        raise AssertionError("must not fire — within cadence")

    fired = asyncio.run(
        hunt_scheduler.run_once(
            db=db,
            now=datetime.now(UTC),
            hit_callback=AsyncMock(),
            executor=_exploding,
        )
    )
    assert fired == 0


def test_scheduler_interval_parser_recognises_common_cadences() -> None:
    """Sanity-check the cron interval helper.

    The Phase 4.5 work swapped the bespoke 5-field parser for a
    croniter-first implementation. The common cadences still produce
    their familiar interval-in-seconds; truly invalid strings still
    return ``None``; and grammar the bespoke parser used to reject
    (day-of-month, day-of-week #-modifiers, etc.) is now classified
    correctly by croniter rather than rejected as garbage.
    """
    from app.workers.hunt_scheduler import _CRONITER_AVAILABLE, _interval_seconds_for

    assert _interval_seconds_for("* * * * *") == 60
    assert _interval_seconds_for("*/5 * * * *") == 300
    assert _interval_seconds_for("0 * * * *") == 3600
    assert _interval_seconds_for("0 */6 * * *") == 6 * 3600
    assert _interval_seconds_for("0 0 * * *") == 24 * 3600
    assert _interval_seconds_for("0 0 * * 1") == 7 * 24 * 3600
    # Unrecognised — returns None so the worker skips rather than guesses.
    assert _interval_seconds_for("garbage") is None
    # Day-of-month: the bespoke parser returned None, croniter
    # returns a real "next - first" delta. Either is fine; the
    # contract the worker depends on is "positive interval OR None",
    # never a negative or zero number.
    monthly = _interval_seconds_for("0 0 1 * *")
    if _CRONITER_AVAILABLE:
        assert monthly is not None and monthly > 0
    else:
        assert monthly is None
