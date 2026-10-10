"""The Alerts page tiles describe the whole result set, not the loaded page.

The defect
----------
`AlertsView` computed its Critical / High / Unresolved tiles in the browser::

    const alerts = data?.alerts || [];          // one page
    const critCount = alerts.filter(a => a.severity === 'critical').length;

`pageSize` is 25, so the three tiles were arithmetically capped at 25 and sat
beside a **Total** read straight from the server-side `total`. A tenant with
522 alerts saw "Total 522 / Critical 7" where 7 was however many criticals
happened to land on page one -- and paging changed the tiles.

The fix is a server-side aggregate over the *same* `WHERE` clause that
produces `total`, returned on the list response so the four tiles describe one
set. Computing it over the whole tenant instead would have traded one
inconsistency for another: filter to `severity=high` and a whole-tenant
critical count would contradict a filtered total sitting next to it.

`unresolved` is resolved through `app.services.alert_status` rather than
counting `status == 'new'`, which is what the tile labelled *Unresolved* was
actually doing -- `triaging` and `in_progress` are outstanding work too.

Run against live Postgres: the defect is about which rows an aggregate covers,
and a fake session that answers any query cannot tell a page from a result
set. Skips when no database answers so a local run stays green, but **cannot**
skip where it is meant to run -- `integration.yml` sets
`MSSP_ISOLATION_REQUIRED=1` and an unreachable database is then a failure.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

# Fixed so a failure names something greppable.
TENANT = uuid.UUID("0c100000-0000-0000-0000-00000000f1ce")
OTHER_TENANT = uuid.UUID("0c100000-0000-0000-0000-00000000f1cf")


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
                f"the alert-facet proof did not run: {type(exc).__name__}: {exc}"
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
    for tenant in (TENANT, OTHER_TENANT):
        await session.execute(
            text("DELETE FROM alerts WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(tenant)}
        )
        await session.execute(
            text("DELETE FROM tenants WHERE id = CAST(:t AS uuid)"), {"t": str(tenant)}
        )
    await session.commit()


async def _seed(session, tenant: uuid.UUID, slug: str, pairs: list[tuple[str, str]]) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), :n, :s)"
            " ON CONFLICT (id) DO NOTHING"
        ),
        {"t": str(tenant), "n": f"Facet {slug}", "s": slug},
    )
    for severity, status in pairs:
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, :s, :st, NOW(), NOW())
                """
            ),
            {
                "i": str(uuid.uuid4()),
                "t": str(tenant),
                "ti": f"{severity} alert in {status}",
                "s": severity,
                "st": status,
            },
        )
    await session.commit()


def _principal(tenant: uuid.UUID):
    from app.api.v1.deps import CurrentUser

    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant,
        role="admin",
        email="facet-test@example.com",
    )


async def _list(db, tenant: uuid.UUID, **overrides):
    """Call the real handler.

    Every parameter is passed explicitly: calling a FastAPI handler as a plain
    function hands it the `Query(...)` *objects* as defaults rather than the
    values they declare, and `confidence_label` then fails its own validation.
    """
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
        **overrides,
    }
    return await list_alerts(current_user=_principal(tenant), db=db, **kwargs)


# A queue far larger than one page, so a page-local count cannot accidentally
# equal the real one: 30 criticals against a `page_size` of 25.
BIG_QUEUE: list[tuple[str, str]] = (
    [("critical", "new")] * 30 + [("high", "triaging")] * 8 + [("low", "resolved")] * 4
)


@pytest.mark.asyncio
class TestTheTilesAreNotCappedByThePage:
    async def test_the_critical_facet_counts_past_the_end_of_the_page(self, db) -> None:
        """The reproduction. 30 criticals, 25 to a page: the tile must read 30."""
        await _seed(db, TENANT, "facet-big", BIG_QUEUE)

        page = await _list(db, TENANT)

        assert len(page.items) == 25, "fixture no longer exceeds one page"
        assert page.facets.by_severity.get("critical") == 30, (
            f"the critical tile reads {page.facets.by_severity.get('critical')} — "
            "it is counting the loaded page, not the result set"
        )

    async def test_the_facets_do_not_move_when_the_analyst_pages(self, db) -> None:
        """A count that changes because you clicked 'next' is not a count."""
        await _seed(db, TENANT, "facet-big", BIG_QUEUE)

        first = await _list(db, TENANT, page=1)
        second = await _list(db, TENANT, page=2)

        assert first.facets == second.facets

    async def test_the_facets_describe_the_same_rows_as_total(self, db) -> None:
        """The tiles sit beside `total`. Filtering must move both together, or
        the page shows a critical count larger than the total above it."""
        await _seed(db, TENANT, "facet-big", BIG_QUEUE)

        page = await _list(db, TENANT, severity="high")

        assert page.total == 8
        assert page.facets.by_severity == {"high": 8}
        assert sum(page.facets.by_severity.values()) == page.total

    async def test_unresolved_means_unresolved_and_not_merely_new(self, db) -> None:
        """The tile is labelled *Unresolved* and counted `status == 'new'`.
        `triaging` and `in_progress` are outstanding work too."""
        await _seed(
            db,
            TENANT,
            "facet-status",
            [
                ("critical", "new"),
                ("high", "triaging"),
                ("medium", "in_progress"),
                ("low", "resolved"),
                ("low", "closed"),
            ],
        )

        page = await _list(db, TENANT)

        assert page.facets.unresolved == 3
        assert page.total == 5

    async def test_a_worked_queue_reports_zero_unresolved(self, db) -> None:
        """The negative control for the test above: a count that always
        returned the total would pass it."""
        await _seed(db, TENANT, "facet-done", [("critical", "resolved"), ("high", "closed")])

        page = await _list(db, TENANT)

        assert page.facets.unresolved == 0
        assert page.total == 2

    async def test_another_tenants_alerts_are_not_counted(self, db) -> None:
        """A whole-result-set aggregate is exactly the shape that leaks across
        tenants if the predicate is dropped."""
        await _seed(db, TENANT, "facet-mine", [("critical", "new")])
        await _seed(db, OTHER_TENANT, "facet-theirs", [("critical", "new")] * 9)

        page = await _list(db, TENANT)

        assert page.facets.by_severity == {"critical": 1}
        assert page.total == 1


class TestTheContractCarriesTheFacets:
    """No database needed, so these hold wherever the suite runs."""

    def test_the_list_response_declares_facets(self) -> None:
        from app.api.v1.endpoints.alerts import AlertListResponse

        assert "facets" in AlertListResponse.model_fields

    def test_the_published_spec_exposes_them(self) -> None:
        """Read off `app.openapi()`, not `app.routes`: on FastAPI 0.141.x
        `include_router` leaves an opaque object there and an enumeration
        silently compares nothing."""
        from app.main import app

        spec = app.openapi()
        schema = spec["paths"]["/api/v1/alerts"]["get"]["responses"]["200"]
        assert "AlertListResponse" in str(schema["content"]["application/json"]["schema"])

        properties = spec["components"]["schemas"]["AlertListResponse"]["properties"]
        assert "facets" in properties, "the console cannot read a facet the spec does not publish"

    def test_unresolved_uses_the_shared_definition(self) -> None:
        """Five hand-written copies of one rule drift one at a time."""
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints" / "alerts.py"
        ).read_text(encoding="utf-8")

        assert "alert_status" in source, "alerts.py does not import the shared status definition"
