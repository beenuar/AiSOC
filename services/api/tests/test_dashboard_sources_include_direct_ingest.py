"""A source that is demonstrably delivering events is a connected source.

The defect
----------
`GET /api/v1/metrics/dashboard` built its `sources` list by iterating rows of
the `connectors` table and looking each one up in a `GROUP BY
Alert.connector_type` map::

    for row in connectors_rows:
        sources.append(SourceStat(name=row.name, count=source_count_map.get(...)))

The map was never iterated. Events pushed through `POST /v1/ingest/batch` or a
tenant inbox webhook create no connector instance, so a tenant with 522 alerts
arriving from three distinct `connector_type` values saw **Connected Sources
0** and an empty panel telling them to go and connect a source.

The fix adds the delivering-but-unregistered types to the list. It does not
invent a connector row: an entry appears only because alerts carrying that
`connector_type` exist inside the selected window, which is the same evidence
the count itself rests on. Their status is `ingesting` rather than `active` —
`active` is a connector *health* value reported by the poller, and nothing is
polling these.

Run against live Postgres: the defect is which rows an aggregate iterates.
Skips when no database answers, but cannot skip where it is meant to run.
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

TENANT = uuid.UUID("0c100000-0000-0000-0000-0000000005c3")


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
                f"the source-visibility proof did not run: {type(exc).__name__}: {exc}"
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
    for table in ("alerts", "connectors"):
        await session.execute(text(f"DELETE FROM {table} WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.execute(text("DELETE FROM tenants WHERE id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()


async def _tenant(session) -> None:
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Sources', 'sources-test') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )


async def _alerts(session, connector_type: str, count: int) -> None:
    for _ in range(count):
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, connector_type,
                                    created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, 'medium', 'new', :ct, NOW(), NOW())
                """
            ),
            {"i": str(uuid.uuid4()), "t": str(TENANT), "ti": f"from {connector_type}", "ct": connector_type},
        )
    await session.commit()


async def _connector(session, name: str, connector_type: str, health: str) -> None:
    await session.execute(
        text(
            """
            INSERT INTO connectors (id, tenant_id, name, connector_type, health_status,
                                    created_at, updated_at)
            VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :n, :ct, :h, NOW(), NOW())
            """
        ),
        {"i": str(uuid.uuid4()), "t": str(TENANT), "n": name, "ct": connector_type, "h": health},
    )
    await session.commit()


async def _sources(db):
    from app.api.v1.endpoints.metrics import get_dashboard_metrics

    metrics = await get_dashboard_metrics(user=_principal(), db=db, period="30d")
    return {s.name: s for s in metrics.sources}


def _principal():
    from app.api.v1.deps import CurrentUser

    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role="admin", email="sources@example.com")


@pytest.mark.asyncio
class TestWebhookIngestIsVisible:
    async def test_a_delivering_source_with_no_connector_row_is_listed(self, db) -> None:
        """The reproduction. 522 events, zero connector rows, panel read empty."""
        await _tenant(db)
        await _alerts(db, "splunk_notable", 7)

        sources = await _sources(db)

        assert "splunk_notable" in sources, f"a source delivering 7 alerts is invisible; the panel lists {sorted(sources)}"
        assert sources["splunk_notable"].count == 7

    async def test_it_is_not_labelled_as_a_healthy_connector(self, db) -> None:
        """`active` is a health value the poller reports. Nothing polls these,
        and claiming otherwise would be inventing a connector."""
        await _tenant(db)
        await _alerts(db, "generic_webhook", 3)

        assert (await _sources(db))["generic_webhook"].status == "ingesting"

    async def test_a_registered_connector_still_wins_its_own_row(self, db) -> None:
        """The negative control for the two above: a connector row must keep
        its configured name and its real health, not be duplicated by a
        second entry named after its type."""
        await _tenant(db)
        await _connector(db, "Prod CrowdStrike", "crowdstrike", "active")
        await _alerts(db, "crowdstrike", 5)

        sources = await _sources(db)

        assert "Prod CrowdStrike" in sources
        assert sources["Prod CrowdStrike"].count == 5
        assert sources["Prod CrowdStrike"].status == "active"
        assert "crowdstrike" not in sources, "the connector is listed twice"

    async def test_nothing_is_invented_for_a_tenant_with_no_events(self, db) -> None:
        """The honesty control. No alerts means no sources — the panel's empty
        state is correct there and must not be papered over."""
        await _tenant(db)

        assert await _sources(db) == {}

    async def test_another_tenants_traffic_does_not_appear(self, db) -> None:
        other = uuid.UUID("0c100000-0000-0000-0000-0000000005c4")
        await _tenant(db)
        await _alerts(db, "okta", 2)

        from app.api.v1.deps import CurrentUser
        from app.api.v1.endpoints.metrics import get_dashboard_metrics

        metrics = await get_dashboard_metrics(
            user=CurrentUser(user_id=uuid.uuid4(), tenant_id=other, role="admin", email="other@example.com"),
            db=db,
            period="30d",
        )

        assert metrics.sources == []
