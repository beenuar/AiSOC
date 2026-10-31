"""The rail's business-context leg reads real ledger rows, tenant-scoped.

`fetch_business_context` joins `investigation_events` through
`investigation_runs` (the events table has no alert column of its own;
`case_id` is TEXT holding the alert id for auto-triage runs). Those are
properties of the real schema — a session double would answer any query and
prove none of them, which is the exact boundary the defect class lives at.

Skips without a database rather than passing without one.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from app.models.alert import Alert
from app.services.alert_rail import fetch_business_context
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000000bc")
OTHER_TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000000bd")

PAYLOAD = {
    "verdict": "true_positive",
    "confidence": 0.9,
    "rationale": "r",
    "business_context": {
        "matched_rule_ids": ["dc-critical"],
        "severity_before": "medium",
        "severity_after": "critical",
    },
    "business_impact": {"statement": "Payment path at risk", "citations": ["dc-critical"]},
}


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
        for tid, slug in ((TENANT, "rail-bc-a"), (OTHER_TENANT, "rail-bc-b")):
            await session.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug) ON CONFLICT (id) DO NOTHING"),
                {"id": tid, "name": f"Rail BC {slug}", "slug": slug},
            )
        await session.commit()
        yield session
        # Ledger rows are immutable by trigger — DELETE on investigation_events
        # raises, which is the schema doing its job. Every test seeds a fresh
        # alert id and asserts through it, so accumulated ledger rows from
        # prior runs are invisible to the assertions. Alerts are deletable.
        await session.rollback()
        await session.execute(text("DELETE FROM alerts WHERE tenant_id IN (:a, :b)"), {"a": TENANT, "b": OTHER_TENANT})
        await session.commit()
    await engine.dispose()


def _alert(tenant: uuid.UUID) -> Alert:
    now = datetime.now(UTC)
    return Alert(
        id=uuid.uuid4(),
        tenant_id=tenant,
        title="Encoded PowerShell on FIN-APP-03",
        severity="critical",
        event_time=now,
        first_seen=now,
        last_seen=now,
    )


async def _seed_run_and_event(db, *, tenant: uuid.UUID, alert_id: uuid.UUID, payload: dict, kind: str = "auto_triage:fast") -> None:
    run_id = uuid.uuid4()
    await db.execute(
        text(
            """
            INSERT INTO investigation_runs (id, tenant_id, case_id, alert_summary, raw_alert, model_used, status, started_at, created_at)
            VALUES (:id, :tenant_id, :case_id, 'summary', CAST(:raw AS jsonb), 'kafka:auto_triage:fast', 'completed', now(), now())
            """
        ),
        {"id": run_id, "tenant_id": tenant, "case_id": str(alert_id), "raw": "{}"},
    )
    await db.execute(
        text(
            """
            INSERT INTO investigation_events (id, run_id, tenant_id, seq, ts, kind, agent, summary, payload, created_at)
            VALUES (:id, :run_id, :tenant_id, 1, now(), :kind, 'auto_triage', 'verdict', CAST(:payload AS jsonb), now())
            """
        ),
        {"id": uuid.uuid4(), "run_id": run_id, "tenant_id": tenant, "kind": kind, "payload": json.dumps(payload)},
    )
    await db.commit()


@pytest.mark.asyncio
async def test_the_leg_reads_the_real_rows(db) -> None:
    alert = _alert(TENANT)
    db.add(alert)
    await db.commit()
    await _seed_run_and_event(db, tenant=TENANT, alert_id=alert.id, payload=PAYLOAD)

    rail = await fetch_business_context(db, alert)
    assert rail is not None
    assert rail.matched_rule_ids == ["dc-critical"]
    assert rail.severity_before == "medium"
    assert rail.severity_after == "critical"
    assert rail.impact_statement == "Payment path at risk"
    assert rail.impact_citations == ["dc-critical"]


@pytest.mark.asyncio
async def test_no_event_means_none_not_zero(db) -> None:
    alert = _alert(TENANT)
    db.add(alert)
    await db.commit()
    assert await fetch_business_context(db, alert) is None


@pytest.mark.asyncio
async def test_an_event_without_the_keys_is_not_surfaced(db) -> None:
    alert = _alert(TENANT)
    db.add(alert)
    await db.commit()
    await _seed_run_and_event(
        db,
        tenant=TENANT,
        alert_id=alert.id,
        payload={"verdict": "benign", "confidence": 0.8, "rationale": "r"},
    )
    assert await fetch_business_context(db, alert) is None


@pytest.mark.asyncio
async def test_another_tenants_event_is_invisible(db) -> None:
    """The query filters by tenant on both tables; an alert id collision across
    tenants must never leak the other tenant's context."""
    alert = _alert(TENANT)
    db.add(alert)
    await db.commit()
    # Same case_id string, other tenant's run+event.
    await _seed_run_and_event(db, tenant=OTHER_TENANT, alert_id=alert.id, payload=PAYLOAD)
    assert await fetch_business_context(db, alert) is None
