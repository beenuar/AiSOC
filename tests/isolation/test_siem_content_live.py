"""The SIEM content inventory's Postgres truths (WS1.2–1.3).

Why live: the versioning rule is the upsert's own CASE (unchanged hash
advances ``last_seen``; changed hash bumps ``version`` and keeps
``previous_hash``), per-tenant isolation is RLS under the NOBYPASSRLS
role, and the health view's denominators come from a real join against
attributed alert rows. Against the pre-change tree every test fails at
setup: the table does not exist.

Environment: ISOLATION_SIEM_CONTENT_DSN (aisoc_app) +
ISOLATION_SIEM_CONTENT_ADMIN_DSN (owner, fixtures).
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_SIEM_CONTENT_DSN", "").strip(),
        reason="ISOLATION_SIEM_CONTENT_DSN is not set; this suite needs a live Postgres",
    ),
]

_API = Path(__file__).resolve().parents[2] / "services" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()
CONNECTOR_ID = uuid.uuid4()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pools():
    import asyncpg

    admin = await asyncpg.connect(os.environ["ISOLATION_SIEM_CONTENT_ADMIN_DSN"].strip())
    app = await asyncpg.connect(os.environ["ISOLATION_SIEM_CONTENT_DSN"].strip())
    suffix = uuid.uuid4().hex[:8]
    for tenant, label in ((TENANT_A, f"sc-a-{suffix}"), (TENANT_B, f"sc-b-{suffix}")):
        await admin.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT DO NOTHING",
            tenant,
            label,
        )
    yield admin, app
    for tenant in (TENANT_A, TENANT_B):
        await admin.execute("DELETE FROM alerts WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM siem_content_rules WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM tenants WHERE id = $1", tenant)
    await admin.close()
    await app.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    dsn = os.environ["ISOLATION_SIEM_CONTENT_ADMIN_DSN"].strip().replace("postgresql://", "postgresql+asyncpg://")
    engine = create_async_engine(dsn, poolclass=None)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _connector() -> SimpleNamespace:
    return SimpleNamespace(
        id=CONNECTOR_ID,
        tenant_id=TENANT_A,
        connector_type="splunk",
        auth_config={},
        connector_config={},
    )


def _http_post(rules: list[dict]):
    async def _post(url: str, payload: dict, tenant_id) -> dict:
        assert url.endswith("/connectors/splunk/content")
        return {"rules": rules}

    return _post


async def test_sweep_upserts_versions_and_keeps_the_prior_hash(pools, session_factory, monkeypatch):
    from app.services import siem_content as svc

    monkeypatch.setattr(svc, "get_vault", lambda: SimpleNamespace(decrypt_dict=lambda d: dict(d or {})))
    admin, _ = pools
    rule_v1 = {
        "vendor_rule_id": "Threat - Brute Force - Rule",
        "name": "Brute Force",
        "kind": "correlation",
        "enabled": True,
        "severity": "high",
        "query": "index=auth action=failure | stats count by user",
        "attack": ["T1110"],
    }
    async with session_factory() as db:
        report = await svc.sweep_tenant(db, tenant_id=TENANT_A, connectors=[_connector()], http_post=_http_post([rule_v1]))
        await db.commit()
    assert report["sources"][0]["status"] == "ok" and report["sources"][0]["rules"] == 1

    row = await admin.fetchrow(
        "SELECT version, previous_hash, content_sha256 FROM siem_content_rules WHERE tenant_id = $1",
        TENANT_A,
    )
    assert row["version"] == 1 and row["previous_hash"] is None

    # Same content again: last_seen advances, version does not.
    async with session_factory() as db:
        await svc.sweep_tenant(db, tenant_id=TENANT_A, connectors=[_connector()], http_post=_http_post([rule_v1]))
        await db.commit()
    row2 = await admin.fetchrow("SELECT version FROM siem_content_rules WHERE tenant_id = $1", TENANT_A)
    assert row2["version"] == 1, "an unchanged rule is 'still there', not a new version"

    # The SPL changes: version bumps, the prior hash is kept.
    rule_v2 = dict(rule_v1, query="index=auth action=failure earliest=-15m | stats count by user")
    async with session_factory() as db:
        await svc.sweep_tenant(db, tenant_id=TENANT_A, connectors=[_connector()], http_post=_http_post([rule_v2]))
        await db.commit()
    row3 = await admin.fetchrow(
        "SELECT version, previous_hash, content_sha256 FROM siem_content_rules WHERE tenant_id = $1",
        TENANT_A,
    )
    assert row3["version"] == 2, "drift is a fact: the hash moved, so the version must"
    assert row3["previous_hash"] == row["content_sha256"]
    assert row3["content_sha256"] != row["content_sha256"]


async def test_rls_isolates_the_inventory_per_tenant(pools):
    admin, app = pools
    bypass = await app.fetchval("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
    assert bypass is False
    await admin.execute(
        """
        INSERT INTO siem_content_rules (tenant_id, connector_id, connector_type, vendor_rule_id, name, content_sha256)
        VALUES ($1, $2, 'elastic', 'other-tenant-rule', 'theirs', 'x')
        """,
        TENANT_B,
        uuid.uuid4(),
    )
    await app.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(TENANT_A))
    rows = await app.fetch("SELECT tenant_id FROM siem_content_rules")
    assert {r["tenant_id"] for r in rows} == {TENANT_A}, "the inventory leaked across tenants"


async def test_health_carries_denominators_or_not_measured(pools, session_factory):
    from app.services.siem_content import rule_health

    admin, _ = pools
    # Three alerts attribute to the Splunk rule: two disposed (one FP), one open.
    for disposition in ("false_positive", "true_positive", None):
        await admin.execute(
            """
            INSERT INTO alerts (id, tenant_id, title, severity, status, connector_type, rule_name, disposition, created_at)
            VALUES ($1, $2, 'attributed', 'high', 'resolved', 'splunk', 'Brute Force', $3, NOW())
            """,
            uuid.uuid4(),
            TENANT_A,
            disposition,
        )
    async with session_factory() as db:
        health = await rule_health(db, tenant_id=TENANT_A)
    assert health, "the inventory row must appear"
    rule = next(r for r in health if r["name"] == "Brute Force")
    assert rule["alerts_attributed"] == 3
    assert rule["false_positive"] == {"rate": 0.5, "denominator": 2}, (
        "the FP rate is 1 of 2 DISPOSED alerts — the open one is not in the denominator"
    )
    assert rule["last_fired"] is not None
    assert rule["vendor_execution_state"] == {"enabled": True}

    # A rule nothing attributes to reads 'not measured', never 0.0.
    await admin.execute(
        """
        INSERT INTO siem_content_rules (tenant_id, connector_id, connector_type, vendor_rule_id, name, content_sha256)
        VALUES ($1, $2, 'splunk', 'silent-rule', 'Never Fired', 'y')
        """,
        TENANT_A,
        CONNECTOR_ID,
    )
    async with session_factory() as db:
        health = await rule_health(db, tenant_id=TENANT_A)
    silent = next(r for r in health if r["name"] == "Never Fired")
    assert silent["false_positive"]["rate"] is None
    assert silent["false_positive"]["denominator"] == 0
    assert "not measured" in silent["false_positive"]["note"]
    assert silent["vendor_execution_state"] == {"could_not_check": "the vendor listing did not expose an enabled state"}
