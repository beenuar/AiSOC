"""KEV exposure answers from scanner data, end to end, against real Postgres.

Fix pass item 5.2. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`asset_vulnerabilities` had one writer: `POST /api/v1/assets/vulnerabilities`,
a route a human calls by hand. The Tenable connector -- the only vulnerability
scanner AiSOC integrates -- modelled its findings as alerts, so for any tenant
whose vulnerability data came from a scanner the table was empty.

`_tenant_has_vulnerability_data` exists precisely to tell "you are not exposed"
apart from "nobody has told me what you run". With an empty table it returned
the second, so KEV exposure reported **no data forever**, however many findings
had been polled.

What this file asserts
----------------------
The whole chain against real Postgres with every migration applied: a tenant
starts with no vulnerability data and `check_exposure` says so; the connector's
findings are synced; and the same call now reports the tenant exposed to the
KEV CVE, naming the asset.

The negative control is the half that makes the result mean anything: a tenant
with data who is *not* running the vulnerable thing must come back **not
exposed**, which is a different answer from "no data" and the whole reason the
distinction exists.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_KEV_DSN", "").strip(),
        reason="ISOLATION_KEV_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn(driver: str = "postgresql+asyncpg://") -> str:
    value = os.environ.get("ISOLATION_KEV_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_KEV_DSN is not set")
    return value.replace("postgresql://", driver, 1) if value.startswith("postgresql://") else value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(loop_scope="module")
async def tenant(engine):
    from sqlalchemy import text

    tid = uuid.uuid4()
    slug = f"kev-{tid.hex[:8]}"
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
            {"id": tid, "n": slug, "s": slug},
        )
    try:
        yield tid
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tid})


def _findings() -> list[dict]:
    """The shape `TenableConnector.fetch_vulnerability_findings` returns."""
    return [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "critical",
            "hostname": "web-01.corp.example",
            "ip_address": "198.51.100.10",
            "title": "Log4Shell",
            "plugin_id": 12345,
            "source": "tenable_io",
        },
        {
            # No CVE: must be skipped rather than written as an anonymous row.
            "cve_id": "",
            "severity": "high",
            "hostname": "web-01.corp.example",
            "title": "Something without a CVE",
            "source": "tenable_io",
        },
    ]


def _load_connectors_vulnerabilities():
    """Load the connectors module by path, under its own module name.

    Both services package their code as `app`, so whichever is imported first
    wins `sys.modules["app"]` and the other's submodules resolve to
    `ModuleNotFoundError`. This test is the one place that legitimately needs
    both at once -- it is asserting that what the connectors service writes is
    what the API service reads -- so the connectors half is loaded off disk
    under a name that cannot collide.
    """
    import importlib.util

    path = REPO_ROOT / "services" / "connectors" / "app" / "vulnerabilities.py"
    spec = importlib.util.spec_from_file_location("aisoc_connectors_vulnerabilities", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def _sync(engine, tenant_id):
    sync_findings = _load_connectors_vulnerabilities().sync_findings
    return await sync_findings(engine, tenant_id=tenant_id, findings=_findings())


async def _exposure(engine, tenant_id, cve: str):
    sys.path.insert(0, str(REPO_ROOT / "services" / "api"))
    from app.services.retro_hunt.kev_exposure import check_exposure
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as session:
        return await check_exposure(
            session,
            tenant_id=tenant_id,
            cve_id=cve,
            feed_source="cisa-kev",
        )


class TestBeforeAnyScannerData:
    async def test_the_tenant_reports_no_vulnerability_data(self, engine, tenant) -> None:
        """Not "not exposed". The distinction is the point of the feature: a
        tenant nobody has scanned is not a tenant that is safe."""
        result = await _exposure(engine, tenant, "CVE-2021-44228")

        assert result.checked is False, f"expected 'no data' for an unscanned tenant, got {result!r}"
        assert "no vulnerability data" in (result.unavailable_reason or "")


class TestAfterTheConnectorSyncs:
    async def test_the_findings_become_rows(self, engine, tenant) -> None:
        counts = await _sync(engine, tenant)

        assert counts["findings_inserted"] == 1, counts
        assert counts["assets_created"] == 1, counts
        assert counts["skipped"] == 1, "the finding with no CVE should have been skipped, not written"

    async def test_exposure_now_names_the_asset(self, engine, tenant) -> None:
        await _sync(engine, tenant)

        result = await _exposure(engine, tenant, "CVE-2021-44228")

        assert result.checked is True, f"still reporting no data: {result!r}"
        assert result.exposed_asset_count == 1, f"not reported exposed: {result!r}"
        assert result.exposed_asset_names == ["web-01.corp.example"]

    async def test_a_cve_the_tenant_does_not_run_is_not_exposed(self, engine, tenant) -> None:
        """The negative control. A tenant with data who is not running the
        vulnerable thing must come back *not exposed*, which is a different
        answer from "no data" -- and a check that said "exposed" to everything
        would pass the test above while being useless."""
        await _sync(engine, tenant)

        result = await _exposure(engine, tenant, "CVE-2014-0160")

        assert result.checked is True, "a tenant with data must be checkable"
        assert result.exposed_asset_count == 0, f"falsely exposed: {result!r}"

    async def test_a_re_poll_touches_rather_than_duplicating(self, engine, tenant) -> None:
        """A 5-minute schedule must not write a row every 5 minutes."""
        from sqlalchemy import text

        await _sync(engine, tenant)
        second = await _sync(engine, tenant)

        assert second["findings_inserted"] == 0
        assert second["findings_touched"] == 1

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    text("SELECT count(*) FROM asset_vulnerabilities WHERE tenant_id = :t"),
                    {"t": tenant},
                )
            ).scalar_one()
        assert rows == 1, f"{rows} rows after two polls of one finding"

    async def test_first_found_survives_a_re_poll(self, engine, tenant) -> None:
        """`first_found` is what an exposure window is measured against, so a
        re-poll resetting it would silently make every finding look new."""
        from sqlalchemy import text

        await _sync(engine, tenant)
        async with engine.connect() as conn:
            before = (
                await conn.execute(
                    text("SELECT first_found FROM asset_vulnerabilities WHERE tenant_id = :t"),
                    {"t": tenant},
                )
            ).scalar_one()

        await _sync(engine, tenant)
        async with engine.connect() as conn:
            after = (
                await conn.execute(
                    text("SELECT first_found FROM asset_vulnerabilities WHERE tenant_id = :t"),
                    {"t": tenant},
                )
            ).scalar_one()

        assert before == after, "a re-poll moved first_found"


class TestTenantScoping:
    async def test_one_tenants_findings_are_invisible_to_another(self, engine, tenant) -> None:
        from sqlalchemy import text

        await _sync(engine, tenant)
        other = uuid.uuid4()
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": other, "n": f"kev-o-{other.hex[:8]}", "s": f"kev-o-{other.hex[:8]}"},
            )
        try:
            result = await _exposure(engine, other, "CVE-2021-44228")
            assert result.checked is False, "the other tenant can see these findings"
        finally:
            async with engine.begin() as conn:
                await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": other})
