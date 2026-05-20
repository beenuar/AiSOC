"""Tenant-isolation tests for the /threat-intel API (Issue #159 / F013).

Sibling of ``test_cases_tenant_isolation.py`` and
``test_hunts_tenant_isolation.py``: call the endpoint functions directly
with a mocked :class:`AsyncSession` and assert that **every** SQL
statement touching ``threat_intel_iocs``, ``threat_actors`` or
``threat_intel_feeds`` filters on ``tenant_id`` *and* binds the caller's
tenant id, and that cross-tenant reads/writes either 404 or write under
the caller's tenant id (never the other tenant's).

These endpoints use the SQLAlchemy ORM (``select(Model).where(...)``)
rather than raw SQL text — that means SQLAlchemy generates bound
parameter names like ``tenant_id_1`` instead of ``tenant_id``. The
``_assert_tenant_scoped`` helper below accepts both shapes so the test
is robust across the project's mixed ORM/text-SQL endpoints.

The contract being protected
----------------------------
* No authenticated caller should be able to read another tenant's
  IOC / actor / feed.
* No authenticated caller should be able to delete another tenant's
  IOC / actor / feed (cross-tenant DELETE must 404, not silently
  succeed against the wrong row).
* Writes (POST) must always carry the caller's tenant id — never
  allow caller-supplied ``tenant_id`` to override.

RBAC coverage lives in :mod:`tests.test_threat_intel_rbac`; this file
focuses purely on *data isolation* once the RBAC gate has passed.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.threat_intel import (
    FeedCreate,
    IOCCreate,
    ThreatActorCreate,
    create_actor,
    create_feed,
    create_ioc,
    delete_feed,
    delete_ioc,
    get_ioc,
    list_actors,
    list_feeds,
    list_iocs,
)
from app.models.threat_intel import ThreatActor, ThreatIntelFeed, ThreatIntelIOC
from fastapi import HTTPException

# ────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ────────────────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    """Construct a CurrentUser without touching the DB or JWT plumbing."""
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="threat_hunter",
        email="hunter@example.com",
    )


def _ioc(tenant_id: uuid.UUID, **overrides: Any) -> ThreatIntelIOC:
    """Build a ThreatIntelIOC ORM row in memory (no DB)."""
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "ioc_type": "domain",
        "value": "evil.example.com",
        "confidence": 80,
        "severity": "high",
        "tlp": "amber",
        "source": "internal",
        "is_active": True,
        "false_positive": False,
        "context": {},
        "first_seen": datetime.now(UTC),
        "last_seen": datetime.now(UTC),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    ioc = ThreatIntelIOC()
    for k, v in defaults.items():
        setattr(ioc, k, v)
    return ioc


def _actor(tenant_id: uuid.UUID, **overrides: Any) -> ThreatActor:
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "name": "APT-Example",
        "is_active": True,
        "context": {},
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    actor = ThreatActor()
    for k, v in defaults.items():
        setattr(actor, k, v)
    return actor


def _feed(tenant_id: uuid.UUID, **overrides: Any) -> ThreatIntelFeed:
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "name": "internal-feed",
        "feed_type": "stix",
        "poll_interval": 3600,
        "is_enabled": True,
        "config": {},
        "created_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    feed = ThreatIntelFeed()
    for k, v in defaults.items():
        setattr(feed, k, v)
    return feed


def _mk_db(rows: list[Any]) -> MagicMock:
    """Mock AsyncSession that returns queued rows one execute() at a time.

    Captures every executed SQL statement and its compiled bind
    parameters so the assertion helper can verify tenant scoping. ``rows``
    is the queue of results returned by ``execute()`` — list values are
    treated as ``scalars().all()`` payloads, scalar values as
    ``scalar_one_or_none()`` payloads, and ``None`` as "no row".

    Also tracks every object passed to ``db.add()`` so we can assert
    INSERTs carry the caller's tenant_id (ORM ``db.add(...)`` doesn't
    issue SQL until flush, so we can't capture it from ``execute()``).
    """
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    db.added: list[Any] = []
    db.deleted: list[Any] = []
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:  # pragma: no cover — defensive: never crash the mock.
            params = {}
        db.executed.append((sql, params))
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        result = MagicMock()
        scalars = MagicMock()
        if isinstance(payload, list):
            scalars.all = MagicMock(return_value=payload)
            scalars.first = MagicMock(return_value=payload[0] if payload else None)
            result.scalar_one_or_none = MagicMock(return_value=payload[0] if payload else None)
        else:
            scalars.all = MagicMock(return_value=[payload] if payload else [])
            scalars.first = MagicMock(return_value=payload)
            result.scalar_one_or_none = MagicMock(return_value=payload)
        result.scalars = MagicMock(return_value=scalars)
        return result

    async def _get(model: Any, pk: Any) -> Any:
        # Used by GET/DELETE endpoints that call ``await db.get(Model, id)``.
        # We capture the lookup so the assertion helper can confirm it
        # happened, and pop the next queued row.
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        db.executed.append((f"GET {model.__tablename__} id={pk}", {"pk": pk}))
        return payload

    def _add(obj: Any) -> None:
        db.added.append(obj)

    async def _delete(obj: Any) -> None:
        db.deleted.append(obj)

    db.execute = AsyncMock(side_effect=_execute)
    db.get = AsyncMock(side_effect=_get)
    db.add = MagicMock(side_effect=_add)
    db.delete = AsyncMock(side_effect=_delete)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.rollback = AsyncMock()
    return db


_TENANT_TABLES = ("threat_intel_iocs", "threat_actors", "threat_intel_feeds")


def _assert_tenant_scoped(executed: list[tuple[str, dict[str, Any]]], tenant_id: uuid.UUID) -> None:
    """Every executed SELECT against a tenant-owned table must filter on tenant_id.

    ORM ``select(Model).where(Model.tenant_id == ...)`` produces a bound
    parameter that SQLAlchemy names ``tenant_id_1`` (or
    ``tenant_id_N`` if there are multiple). Raw text SQL with
    ``:tenant_id`` keeps that literal name. This helper accepts both
    shapes — what matters is that *some* bound parameter equal to the
    caller's tenant id appears, and that the SQL string references
    ``tenant_id``.
    """
    assert executed, "expected at least one DB call"
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if any(table in normalized for table in _TENANT_TABLES):
            assert "tenant_id" in normalized, f"tenant_id missing from SQL: {sql}"
            # Find any bound parameter whose value matches the caller's
            # tenant_id. ORM uses tenant_id_1, text SQL uses tenant_id.
            matching = [
                (name, value)
                for name, value in params.items()
                if (name == "tenant_id" or name.startswith("tenant_id_")) and value == tenant_id
            ]
            assert matching, (
                f"no bound tenant_id parameter matches caller's tenant in SQL: {sql}; " f"params={params}; expected_tenant={tenant_id}"
            )


# ────────────────────────────────────────────────────────────────────────────
# IOC endpoints — list / get / create / delete
# ────────────────────────────────────────────────────────────────────────────


# NOTE on signatures: ``list_iocs`` and friends declare ``limit``/``offset``
# with ``fastapi.Query(...)`` defaults. Those defaults only resolve to real
# ints inside a real FastAPI request; called directly from a test, they're
# ``Query`` objects which trip SQLAlchemy's ``int()`` coercion in
# ``.limit(...)``. So we always pass explicit ``limit`` / ``offset`` ints.


@pytest.mark.asyncio
async def test_list_iocs_scopes_by_tenant() -> None:
    """SELECT for /iocs must include tenant_id = current_user.tenant_id."""
    user = _user()
    db = _mk_db([[_ioc(user.tenant_id), _ioc(user.tenant_id)]])
    result = await list_iocs(current_user=user, db=db, limit=50, offset=0)
    assert len(result) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_iocs_with_filters_keeps_tenant_scope() -> None:
    """Adding ioc_type/severity filters does not relax the tenant filter."""
    user = _user()
    db = _mk_db([[]])
    await list_iocs(
        current_user=user,
        db=db,
        ioc_type="domain",
        severity="high",
        is_active=True,
        limit=50,
        offset=0,
    )
    _assert_tenant_scoped(db.executed, user.tenant_id)
    sql, _params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "threat_intel_iocs" in normalized
    assert "ioc_type" in normalized
    assert "severity" in normalized


@pytest.mark.asyncio
async def test_get_ioc_cross_tenant_returns_404() -> None:
    """An IOC owned by tenant B must 404 for tenant A even when the UUID matches."""
    tenant_a = _user()
    tenant_b_id = uuid.uuid4()
    other_tenant_ioc = _ioc(tenant_b_id)
    db = _mk_db([other_tenant_ioc])  # ``db.get`` will return tenant B's row.
    with pytest.raises(HTTPException) as exc:
        await get_ioc(ioc_id=other_tenant_ioc.id, current_user=tenant_a, db=db)
    assert exc.value.status_code == 404
    # Sanity: the db.get call was issued (so the tenant-id post-check
    # is the only thing preventing the cross-tenant read).
    assert db.executed and db.executed[0][0].startswith("GET threat_intel_iocs")


@pytest.mark.asyncio
async def test_get_ioc_missing_returns_404() -> None:
    """A non-existent IOC also 404s (not 500)."""
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await get_ioc(ioc_id=uuid.uuid4(), current_user=user, db=db)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_get_ioc_same_tenant_returns_row() -> None:
    """Same-tenant read returns the row (positive control)."""
    user = _user()
    ioc = _ioc(user.tenant_id)
    db = _mk_db([ioc])
    result = await get_ioc(ioc_id=ioc.id, current_user=user, db=db)
    assert result is ioc


@pytest.mark.asyncio
async def test_create_ioc_binds_caller_tenant_id() -> None:
    """Newly-created IOCs carry the *caller's* tenant_id, not body-supplied."""
    user = _user()
    db = _mk_db([])
    body = IOCCreate(ioc_type="ip", value="1.2.3.4", severity="critical")
    await create_ioc(body=body, current_user=user, db=db)
    assert len(db.added) == 1
    created = db.added[0]
    assert isinstance(created, ThreatIntelIOC)
    assert created.tenant_id == user.tenant_id
    assert created.ioc_type == "ip"
    assert created.value == "1.2.3.4"


@pytest.mark.asyncio
async def test_create_ioc_ignores_extra_tenant_id_in_payload() -> None:
    """Even if some future bug let tenant_id sneak into the payload, the
    endpoint must use the caller's tenant_id. Pydantic strips unknown
    fields by default, so this primarily pins the **behavioural** contract:
    the IOC ORM object's tenant_id is set from ``current_user.tenant_id``,
    not from body data.
    """
    user = _user()
    db = _mk_db([])
    body = IOCCreate(ioc_type="hash", value="deadbeef")
    await create_ioc(body=body, current_user=user, db=db)
    assert db.added[0].tenant_id == user.tenant_id


@pytest.mark.asyncio
async def test_delete_ioc_cross_tenant_returns_404() -> None:
    """Cross-tenant DELETE must 404; the wrong row must NEVER be removed."""
    tenant_a = _user()
    tenant_b_ioc = _ioc(uuid.uuid4())
    db = _mk_db([tenant_b_ioc])  # db.get returns the other tenant's row
    with pytest.raises(HTTPException) as exc:
        await delete_ioc(ioc_id=tenant_b_ioc.id, current_user=tenant_a, db=db)
    assert exc.value.status_code == 404
    # Critical: db.delete must NOT have been called for the other tenant's row.
    assert db.deleted == [], "cross-tenant DELETE leaked: row was actually deleted"


@pytest.mark.asyncio
async def test_delete_ioc_same_tenant_succeeds() -> None:
    """Same-tenant DELETE actually removes the row (positive control)."""
    user = _user()
    ioc = _ioc(user.tenant_id)
    db = _mk_db([ioc])
    await delete_ioc(ioc_id=ioc.id, current_user=user, db=db)
    assert db.deleted == [ioc]


@pytest.mark.asyncio
async def test_delete_ioc_missing_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await delete_ioc(ioc_id=uuid.uuid4(), current_user=user, db=db)
    assert exc.value.status_code == 404
    assert db.deleted == []


# ────────────────────────────────────────────────────────────────────────────
# Threat actor endpoints — list / create
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_actors_scopes_by_tenant() -> None:
    user = _user()
    db = _mk_db([[_actor(user.tenant_id)]])
    result = await list_actors(current_user=user, db=db, limit=50, offset=0)
    assert len(result) == 1
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_actors_with_is_active_filter_keeps_tenant_scope() -> None:
    user = _user()
    db = _mk_db([[]])
    await list_actors(current_user=user, db=db, is_active=True, limit=50, offset=0)
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_create_actor_binds_caller_tenant_id() -> None:
    user = _user()
    db = _mk_db([])
    body = ThreatActorCreate(name="APT-Test", motivation="financial")
    await create_actor(body=body, current_user=user, db=db)
    assert len(db.added) == 1
    created = db.added[0]
    assert isinstance(created, ThreatActor)
    assert created.tenant_id == user.tenant_id
    assert created.name == "APT-Test"


# ────────────────────────────────────────────────────────────────────────────
# Feed endpoints — list / create / delete
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_feeds_scopes_by_tenant() -> None:
    user = _user()
    db = _mk_db([[_feed(user.tenant_id)]])
    result = await list_feeds(current_user=user, db=db)
    assert len(result) == 1
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_create_feed_binds_caller_tenant_id() -> None:
    user = _user()
    db = _mk_db([])
    body = FeedCreate(name="otx", feed_type="stix")
    await create_feed(body=body, current_user=user, db=db)
    assert len(db.added) == 1
    created = db.added[0]
    assert isinstance(created, ThreatIntelFeed)
    assert created.tenant_id == user.tenant_id


@pytest.mark.asyncio
async def test_delete_feed_cross_tenant_returns_404() -> None:
    """Cross-tenant DELETE on /feeds must 404 without removing the row."""
    tenant_a = _user()
    other_tenant_feed = _feed(uuid.uuid4())
    db = _mk_db([other_tenant_feed])
    with pytest.raises(HTTPException) as exc:
        await delete_feed(feed_id=other_tenant_feed.id, current_user=tenant_a, db=db)
    assert exc.value.status_code == 404
    assert db.deleted == [], "cross-tenant DELETE leaked: feed was actually deleted"


@pytest.mark.asyncio
async def test_delete_feed_same_tenant_succeeds() -> None:
    user = _user()
    feed = _feed(user.tenant_id)
    db = _mk_db([feed])
    await delete_feed(feed_id=feed.id, current_user=user, db=db)
    assert db.deleted == [feed]


@pytest.mark.asyncio
async def test_delete_feed_missing_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await delete_feed(feed_id=uuid.uuid4(), current_user=user, db=db)
    assert exc.value.status_code == 404
    assert db.deleted == []
