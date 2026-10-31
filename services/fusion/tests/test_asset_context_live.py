"""The asset-context resolver's real SQL, against live Postgres.

Split from ``test_asset_context.py`` (the engine-wiring half, which runs in
the offline fusion job) so this file's import closure stays tiny — pydantic,
structlog, asyncpg — and ``integration.yml``'s migrations job can run it
without fusion's full dependency set. The name/FQDN/IP match, the
highest-criticality tie-break and the tenant predicate are schema facts a
fake pool would invent.

Skips without a database rather than passing without one.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest
import pytest_asyncio
from app.models.alert import AlertSeverity, RawAlert
from app.services.asset_context import AssetContextResolver

DSN = (os.environ.get("DATABASE_URL", "") or "").replace("postgresql+asyncpg://", "postgresql://")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000000e1")
OTHER = uuid.UUID("0e700000-0000-0000-0000-0000000000e2")


def _alert(**over: Any) -> RawAlert:
    base: dict[str, Any] = {
        "tenant_id": TENANT,
        "source": "edr",
        "title": "Suspicious PowerShell",
        "severity": AlertSeverity.HIGH,
        "hostname": "prod-dc-01",
    }
    base.update(over)
    return RawAlert(**base)


@pytest_asyncio.fixture
async def seeded_pg():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    try:
        import asyncpg

        conn = await asyncpg.connect(DSN, timeout=5.0)
    except Exception as exc:
        if REQUIRED:
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    try:
        for tid, slug in ((TENANT, "asset-ctx-a"), (OTHER, "asset-ctx-b")):
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
                tid,
                f"Asset ctx {slug}",
                slug,
            )
        await conn.execute("DELETE FROM assets WHERE tenant_id IN ($1, $2)", TENANT, OTHER)
        await conn.execute(
            """
            INSERT INTO assets (id, tenant_id, name, fqdn, ip_addresses, criticality)
            VALUES
              ($1, $3, 'prod-dc-01', 'prod-dc-01.corp.example', ARRAY['10.0.0.5'], 'critical'),
              ($2, $3, 'prod-dc-01-replica', NULL, ARRAY['10.0.0.5'], 'low'),
              ($4, $5, 'prod-dc-01', NULL, NULL, 'low')
            """,
            uuid.uuid4(),
            uuid.uuid4(),
            TENANT,
            uuid.uuid4(),
            OTHER,
        )
        yield conn
        await conn.execute("DELETE FROM assets WHERE tenant_id IN ($1, $2)", TENANT, OTHER)
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_resolver_matches_name_fqdn_and_ip_live(seeded_pg) -> None:
    resolver = AssetContextResolver(DSN)
    try:
        by_name = await resolver.resolve(_alert(hostname="PROD-DC-01"))
        assert by_name == {"criticality": "critical", "matched": "prod-dc-01"}

        by_fqdn = await resolver.resolve(_alert(hostname="prod-dc-01.corp.example"))
        assert by_fqdn is not None and by_fqdn["criticality"] == "critical"

        # IP matches two assets (critical + low): highest criticality wins,
        # failing toward attention.
        by_ip = await resolver.resolve(_alert(hostname=None, src_ip="10.0.0.5"))
        assert by_ip is not None and by_ip["criticality"] == "critical"
    finally:
        await resolver.close()


@pytest.mark.asyncio
async def test_resolver_is_tenant_scoped_live(seeded_pg) -> None:
    """Tenant B owns an identically-named asset; tenant A's alert must not
    see it — and vice versa, B's own alert resolves B's low-criticality row."""
    resolver = AssetContextResolver(DSN)
    try:
        theirs = await resolver.resolve(_alert(tenant_id=OTHER, hostname="prod-dc-01"))
        assert theirs == {"criticality": "low", "matched": "prod-dc-01"}
    finally:
        await resolver.close()


@pytest.mark.asyncio
async def test_resolver_unknown_host_is_none_live(seeded_pg) -> None:
    resolver = AssetContextResolver(DSN)
    try:
        assert await resolver.resolve(_alert(hostname="never-imported")) is None
    finally:
        await resolver.close()
