"""`GET /api/v1/alerts` search and disposition filters do what they say (#1877).

The `search` query parameter was declared on `list_alerts` and consumed by
nothing: the console sent it, the endpoint accepted it, and the result set
ignored it — a filter that looks applied and is not is the same honesty
defect as a zero that looks measured. #1877 wired it (ILIKE over the
analyst-pasteable columns, the idiom `admin_users`/`audit`/`tenant_provision`
already use) and added an exact-match `disposition` filter; these pins keep
both real.

Run against live Postgres: the defect is a WHERE clause, and a fake session
that answers any query cannot tell a filtered read from an unfiltered one.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0c100000-0000-0000-0000-000000001877")


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(
                "MSSP_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the search-filter proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")
        return

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _reset(session)
        try:
            yield session
        finally:
            await _reset(session)
    await engine.dispose()


async def _reset(session) -> None:
    await session.rollback()
    await session.execute(text("DELETE FROM alerts WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.execute(text("DELETE FROM tenants WHERE id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()


async def _seed(session, rows) -> None:
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Search', 'search-filter-test') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )
    now = datetime.now(UTC)
    for row in rows:
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, description, severity, status, disposition, created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, :de, 'medium', :st, :di, :c, :c)
                """
            ),
            {
                "i": str(row["id"]),
                "t": str(TENANT),
                "ti": row["title"],
                "de": row.get("description", ""),
                "st": row.get("status", "new"),
                "di": row.get("disposition"),
                "c": now,
            },
        )
    await session.commit()


def _principal():
    from app.api.v1.deps import CurrentUser

    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="admin", email="search@example.com")


async def _list_ids(db, **overrides) -> set[str]:
    """Every parameter explicit — a FastAPI handler called as a plain function
    receives the `Query(...)` objects, not the values they declare."""
    from app.api.v1.endpoints.alerts import list_alerts

    kwargs = {
        "http_request": None,
        "page": 1,
        "page_size": 25,
        "limit": None,
        "severity": None,
        "status": None,
        "disposition": None,
        "category": None,
        "assigned_to_me": False,
        "search": None,
        "min_confidence": None,
        "confidence_label": None,
        "sort": "newest",
        **overrides,
    }
    result = await list_alerts(current_user=_principal(), db=db, **kwargs)
    return {str(alert.id) for alert in result.alerts}


@pytest.mark.asyncio
async def test_search_and_disposition_filter_the_result_set(db) -> None:
    a1, a2, a3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await _seed(
        db,
        [
            {"id": a1, "title": "Impossible travel for priya"},
            {
                "id": a2,
                "title": "Beacon to known C2",
                "description": "cobalt strike jitter",
                "status": "resolved",
                "disposition": "false_positive",
            },
            {"id": a3, "title": "Scheduled scan completed"},
        ],
    )

    assert await _list_ids(db) == {str(a1), str(a2), str(a3)}, "no filters must return everything"
    assert await _list_ids(db, search="impossible TRAVEL") == {str(a1)}, "title substring (any case) did not filter"
    assert await _list_ids(db, search="cobalt strike") == {str(a2)}, "description substring did not filter"
    assert await _list_ids(db, search=str(a3)[:13]) == {str(a3)}, "a pasted id fragment did not filter"
    assert await _list_ids(db, disposition="false_positive") == {str(a2)}, "disposition did not exact-match"
    assert await _list_ids(db, search="no-such-string-anywhere") == set(), "a miss must be empty, not everything"
