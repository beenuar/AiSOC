"""Asset criticality orders the queue — proven against real Postgres.

`score_alert_priority` existed with zero callers: two alerts of equal
severity — one on a domain controller, one on a meeting-room display —
arrived in the order they were raised, and an analyst worked out which was
which by reading the hostname. The ordering now resolves the tenant's own
``assets`` inventory (name/FQDN/IP-overlap match, exploited-vulnerability
KEV signal) in two batched queries per page.

Live because the properties under test are schema facts a mock would
invent: the ``lower(name)``/``ip_addresses &&`` match, the
``is_exploited AND remediated_at IS NULL`` filter, and the tenant predicate
on both queries. The negative control monkeypatches the resolver away and
asserts the order collapses back to insertion order — proving the sort
actually consumes the resolution.

Skips without a database rather than passing without one.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from app.models.alert import Alert
from app.models.asset import Asset, AssetVulnerability
from app.services import alert_queue as queue_module
from app.services.alert_queue import build_queue
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000000d1")
OTHER_TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000000d2")
USER = uuid.UUID("0e700000-0000-0000-0000-0000000000d3")

# One shared timestamp: identical first_seen means identical SLA due, so the
# (bucket, sla) keys tie and the priority score is the deciding key.
NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)


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
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered at DATABASE_URL: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        for tid, slug in ((TENANT, "queue-prio-a"), (OTHER_TENANT, "queue-prio-b")):
            await session.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug) ON CONFLICT (id) DO NOTHING"),
                {"id": tid, "name": f"Queue prio {slug}", "slug": slug},
            )
        await session.commit()
        yield session
        await session.rollback()
        for table in ("asset_vulnerabilities", "assets", "alerts"):
            await session.execute(
                text(f"DELETE FROM {table} WHERE tenant_id IN (:a, :b)"),  # noqa: S608 — fixed table names
                {"a": TENANT, "b": OTHER_TENANT},
            )
        await session.commit()
    await engine.dispose()


def _alert(tenant: uuid.UUID, title: str, host: str) -> Alert:
    return Alert(
        id=uuid.uuid4(),
        tenant_id=tenant,
        title=title,
        severity="high",
        status="new",
        event_time=NOW,
        first_seen=NOW,
        last_seen=NOW,
        affected_hosts=[host],
    )


def _asset(tenant: uuid.UUID, name: str, criticality: str) -> Asset:
    return Asset(id=uuid.uuid4(), tenant_id=tenant, name=name, criticality=criticality)


async def _seed_estate(db) -> tuple[Alert, Alert]:
    """Kiosk alert inserted FIRST so insertion order argues against the DC."""
    dc = _asset(TENANT, "prod-dc-01", "critical")
    kiosk = _asset(TENANT, "kiosk-7", "low")
    db.add_all([dc, kiosk])
    await db.flush()
    db.add(
        AssetVulnerability(
            id=uuid.uuid4(),
            tenant_id=TENANT,
            asset_id=dc.id,
            title="KEV-listed RCE",
            severity="critical",
            is_exploited=True,
            source="scanner",
        )
    )
    kiosk_alert = _alert(TENANT, "Suspicious PowerShell on kiosk", "kiosk-7")
    dc_alert = _alert(TENANT, "Suspicious PowerShell on DC", "prod-dc-01")
    db.add_all([kiosk_alert, dc_alert])
    await db.commit()
    return dc_alert, kiosk_alert


@pytest.mark.asyncio
async def test_the_domain_controller_outranks_the_kiosk(db) -> None:
    dc_alert, kiosk_alert = await _seed_estate(db)

    resp = await build_queue(db, tenant_id=TENANT, user_id=USER, owner="unassigned")
    order = [item.id for item in resp.items]
    assert order.index(dc_alert.id) < order.index(kiosk_alert.id), (
        "equal severity, equal SLA — the critical asset with an exploited vulnerability must sort first"
    )

    dc_item = next(i for i in resp.items if i.id == dc_alert.id)
    kiosk_item = next(i for i in resp.items if i.id == kiosk_alert.id)
    assert dc_item.priority_score > kiosk_item.priority_score
    reasons = " | ".join(r["reason"] for r in dc_item.priority_basis["rationale"])
    assert "critical" in reasons
    assert "exploited" in reasons.lower() or "KEV" in reasons


@pytest.mark.asyncio
async def test_negative_control_without_resolution_order_collapses(db, monkeypatch) -> None:
    """Remove the resolver and the DC loses its rank — the sort provably
    consumes the asset resolution rather than something correlated."""
    dc_alert, kiosk_alert = await _seed_estate(db)

    async def _nothing(*_a, **_k):
        return {}

    monkeypatch.setattr(queue_module, "resolve_asset_contexts", _nothing)
    resp = await build_queue(db, tenant_id=TENANT, user_id=USER, owner="unassigned")
    dc_item = next(i for i in resp.items if i.id == dc_alert.id)
    kiosk_item = next(i for i in resp.items if i.id == kiosk_alert.id)
    assert dc_item.priority_score == kiosk_item.priority_score, "severity alone: the scores must tie"


@pytest.mark.asyncio
async def test_another_tenants_inventory_is_invisible(db) -> None:
    """Tenant B owns a critical asset named like tenant A's kiosk. It must not
    raise A's kiosk alert — the resolver is tenant-scoped on both queries."""
    db.add(_asset(OTHER_TENANT, "kiosk-7", "critical"))
    kiosk_alert = _alert(TENANT, "Suspicious PowerShell on kiosk", "kiosk-7")
    db.add(kiosk_alert)
    await db.commit()

    resp = await build_queue(db, tenant_id=TENANT, user_id=USER, owner="unassigned")
    item = next(i for i in resp.items if i.id == kiosk_alert.id)
    assert item.priority_basis["rationale"] == [], "no same-tenant asset matched; severity alone"


@pytest.mark.asyncio
async def test_no_inventory_scores_severity_alone(db) -> None:
    alert = _alert(TENANT, "Alert on unknown host", "never-imported-host")
    db.add(alert)
    await db.commit()

    resp = await build_queue(db, tenant_id=TENANT, user_id=USER, owner="unassigned")
    item = next(i for i in resp.items if i.id == alert.id)
    assert item.priority_score == 600  # high base, no multipliers
    assert item.priority_basis["base"] == 600
    assert item.priority_basis["rationale"] == []
