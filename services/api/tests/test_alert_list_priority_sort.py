"""An analyst can ask the alert list for the dangerous ones first.

The defect
----------
`GET /api/v1/alerts` ordered by `Alert.created_at.desc()` and nothing else.
A noisy low-severity source emitting faster than the analyst pages pushes a
critical off page one and keeps it off: the only alert that mattered was on
page nine, sorted behind 200 informational ones that arrived after it.

Why a parameter rather than a new default
-----------------------------------------
`GET /api/v1/alerts` is a published endpoint with generated SDK clients, and
"page one is the newest rows" is part of what callers built on. Changing the
ordering silently would alter what every existing integration reads without
altering the schema — so `openapi-breaking.yml` would not catch it, which
makes it a worse change to make quietly, not a safer one.

`sort` therefore defaults to `newest`, preserving the contract exactly, and
the console asks for `priority` because the console is where the defect was
observed. A script paging for export keeps the order it had.

`/alerts/queue` already prioritises, but it is a different response model with
its own owner/period/SLA semantics and it does not accept the severity,
status, category, search or confidence filters the grid relies on, so the
grid cannot simply move to it.

Run against live Postgres: the defect is an `ORDER BY`, and a fake session
that answers any query cannot tell one ordering from another.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0c100000-0000-0000-0000-00000000503f")


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
                f"the alert-ordering proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

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


async def _seed_flood(session) -> None:
    """One critical, then a flood of newer low-severity noise on top of it."""
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Flood', 'flood-test') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )
    base = datetime.now(UTC) - timedelta(hours=6)
    rows = [("critical", "Ransomware encryption behaviour", base)]
    rows += [("low", f"Noise {i}", base + timedelta(minutes=i + 1)) for i in range(40)]
    for severity, title, created in rows:
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, :s, 'new', :c, :c)
                """
            ),
            {"i": str(uuid.uuid4()), "t": str(TENANT), "ti": title, "s": severity, "c": created},
        )
    await session.commit()


def _principal():
    from app.api.v1.deps import CurrentUser

    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="admin", email="flood@example.com")


async def _list(db, **overrides):
    """Every parameter explicit — a FastAPI handler called as a plain function
    receives the `Query(...)` objects, not the values they declare."""
    from app.api.v1.endpoints.alerts import list_alerts

    kwargs = {
        "page": 1,
        "page_size": 25,
        "severity": None,
        "status": None,
        "category": None,
        "assigned_to_me": False,
        "search": None,
        "min_confidence": None,
        "confidence_label": None,
        "sort": "newest",
        **overrides,
    }
    return await list_alerts(current_user=_principal(), db=db, **kwargs)


@pytest.mark.asyncio
class TestAFloodDoesNotBuryACritical:
    async def test_the_critical_is_first_under_priority_sort(self, db) -> None:
        """The reproduction: 40 newer low alerts on top of one critical."""
        await _seed_flood(db)

        page = await _list(db, sort="priority")

        assert page.items[0].severity == "critical", f"page one opens with a {page.items[0].severity} alert — the critical is buried"

    async def test_the_critical_is_not_on_page_one_by_default(self, db) -> None:
        """What the console used to show, and still shows to any caller that
        does not ask for the other order. Pinning it proves the default is
        genuinely unchanged rather than accidentally fixed."""
        await _seed_flood(db)

        page = await _list(db)

        assert {a.severity for a in page.items} == {"low"}

    async def test_priority_still_breaks_ties_by_recency(self, db) -> None:
        """Within one severity the newest first, so the order is total and
        paging is stable."""
        await _seed_flood(db)

        page = await _list(db, sort="priority")
        lows = [a for a in page.items if a.severity == "low"]

        assert lows == sorted(lows, key=lambda a: a.created_at, reverse=True)

    async def test_priority_changes_the_order_and_not_the_rows(self, db) -> None:
        """The negative control. A sort that also filtered would hide work."""
        await _seed_flood(db)

        newest = await _list(db, page_size=200)
        priority = await _list(db, page_size=200, sort="priority")

        assert {a.id for a in newest.items} == {a.id for a in priority.items}
        assert newest.total == priority.total == 41

    async def test_an_unknown_sort_is_refused(self, db) -> None:
        """Not silently ignored: a caller that misspells the value should be
        told, not served an order it did not ask for."""
        from fastapi import HTTPException

        await _seed_flood(db)

        with pytest.raises(HTTPException) as caught:
            await _list(db, sort="most-critical")

        assert caught.value.status_code == 400


class TestTheContract:
    def test_sort_is_published_with_newest_as_the_default(self) -> None:
        from app.main import app

        spec = app.openapi()
        params = {p["name"]: p for p in spec["paths"]["/api/v1/alerts"]["get"]["parameters"]}

        assert "sort" in params, "the console cannot request an order the spec does not declare"
        assert params["sort"]["schema"].get("default") == "newest", (
            "changing the default ordering of a published list endpoint is a contract change "
            "the OpenAPI breaking-change detector cannot see"
        )

    def test_the_severity_ladder_has_one_definition(self) -> None:
        """`build_queue` already ranks severity. A second copy in `alerts.py`
        would drift the day a tier is added."""
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints" / "alerts.py").read_text(encoding="utf-8")

        assert "severity_rank" in source

        # A single `Alert.severity == "critical"` is a legitimate filter —
        # `get_alert_stats` counts open criticals that way. A *ladder* is the
        # thing to refuse, and its signature is the mid tiers appearing as
        # comparisons, which only a ranking needs.
        ladder_tiers = [t for t in ("high", "medium", "low") if f'Alert.severity == "{t}"' in source]
        assert len(ladder_tiers) < 2, (
            f"alerts.py ranks severity itself (tiers {ladder_tiers}) instead of importing "
            "severity_rank_expr — two ladders drift the day a tier is added"
        )
