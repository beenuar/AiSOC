"""Four vendors reporting one bucket is one finding, against real Postgres.

Wave 2, Phase 3.3, second half.

Why this has to be live
-----------------------
The three statements behind this feature are the kind a stub connection
accepts happily and Postgres does not:

* the `ON CONFLICT (tenant_id, resource, technique, principal)` upsert, whose
  whole behaviour is the unique index;
* the recount, a correlated subquery that orders severity by the five-tier
  ladder explicitly — because alphabetical order puts `critical` below
  `low`, which a stub would never reveal;
* `COUNT(DISTINCT connector_type)`, which is the number that makes the
  finding worth having and is recomputed rather than incremented so a
  redelivery cannot turn two vendors into three.

And the RLS policy, which a superuser silently bypasses — so this suite runs
as the DML-only `aisoc_app` role, the same role that revealed migration
151's `WITH CHECK` defect.

Against the pre-change tree every test here fails at setup: neither
`root_cause_findings` nor `alert_root_cause_members` exists.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_ROOT_CAUSE_DSN", "").strip(),
        reason="ISOLATION_ROOT_CAUSE_DSN is not set; this suite needs a live Postgres",
    ),
]

_FUSION = Path(__file__).resolve().parents[2] / "services" / "fusion"

#: Four real cloud-security connector types. Real ids because the vendor
#: count is the claim, and a fake vendor would inflate it.
VENDORS = ("aws_security_hub", "azure_defender_cloud", "wiz", "aws_guardduty")


def _dsn() -> str:
    value = os.environ.get("ISOLATION_ROOT_CAUSE_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_ROOT_CAUSE_DSN is not set")
    return value


def _admin_dsn() -> str:
    value = os.environ.get("ISOLATION_ROOT_CAUSE_ADMIN_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_ROOT_CAUSE_ADMIN_DSN is not set")
    return value


@pytest.fixture(scope="module", autouse=True)
def _fusion_importable() -> None:
    import sys

    if str(_FUSION) not in sys.path:
        sys.path.insert(0, str(_FUSION))


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pool():
    import asyncpg

    created = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)
    assert created is not None
    try:
        yield created
    finally:
        await created.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def admin_pool():
    import asyncpg

    created = await asyncpg.create_pool(_admin_dsn(), min_size=1, max_size=2)
    assert created is not None
    try:
        yield created
    finally:
        await created.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def make_tenant(admin_pool):
    async def _make(label: str) -> uuid.UUID:
        new_id = uuid.uuid4()
        async with admin_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
                new_id,
                f"laneF {label} {new_id.hex[:8]}",
                f"lanef-{label}-{new_id.hex[:8]}",
            )
        return new_id

    return _make


def _fused(tenant: uuid.UUID, *, vendor: str, resource: str, principal: str, severity, when: datetime):
    from app.models.alert import FusedAlert, FusionDecision, RawAlert

    raw = RawAlert(
        tenant_id=tenant,
        source=vendor,
        # Different titles per vendor on purpose: that is what makes the
        # fingerprints differ, and therefore what every existing dedup layer
        # correctly leaves standing.
        title=f"{vendor}: public access on {resource}",
        severity=severity,
        hostname=resource,
        username=principal,
        mitre_techniques=["T1530"],
        connector_type=vendor,
        event_time=when,
    )
    raw.id = raw.deterministic_id()
    return FusedAlert(id=raw.id, tenant_id=tenant, fusion_decision=FusionDecision.NEW_ALERT, alert=raw)


async def _sink(pool):
    from app.services.alert_sink import AlertSink

    sink = AlertSink(_dsn())
    sink._pool = pool
    return sink


async def _finding(pool, tenant: uuid.UUID):
    async with pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM root_cause_findings WHERE tenant_id = $1", tenant)


@pytest.mark.asyncio(loop_scope="module")
async def test_four_vendors_on_one_resource_become_one_finding(pool, make_tenant) -> None:
    from app.models.alert import AlertSeverity
    from app.services.alert_sink import PersistOutcome

    tenant = await make_tenant("rc")
    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)

    for n, vendor in enumerate(VENDORS):
        result = await sink.persist(
            _fused(
                tenant,
                vendor=vendor,
                resource="storage-001",
                principal="deployer-01",
                severity=AlertSeverity.CRITICAL if vendor == "wiz" else AlertSeverity.MEDIUM,
                when=base + timedelta(minutes=n),
            )
        )
        # Every original is kept. Collapsing is an added record, never a
        # replaced one.
        assert result.outcome is PersistOutcome.INSERTED, f"{vendor} was not inserted as its own alert"

    row = await _finding(pool, tenant)
    assert row is not None, "four vendors reported one root cause and no finding was formed"
    assert row["vendor_count"] == 4
    assert row["member_count"] == 4
    assert row["resource"] == "storage-001"
    assert row["technique"] == "T1530"
    assert row["principal"] == "deployer-01"
    assert row["first_seen"] == base
    assert row["last_seen"] == base + timedelta(minutes=3)


@pytest.mark.asyncio(loop_scope="module")
async def test_the_finding_takes_the_worst_severity_not_an_average(pool, make_tenant) -> None:
    """One critical report makes a critical finding.

    Averaging would let three low reports bury it, and ordering severity
    alphabetically puts `critical` below `medium` — exactly the kind of
    error only a real `ORDER BY` reveals.

    **Its own tenant, and its own assertion scoped to it.** The first cut of
    this test read `WHERE vendor_count = 4 LIMIT 1` with no tenant
    predicate, so against a database that already held a correct row from an
    earlier test it passed while the severity ordering was reverted to
    alphabetical — a negative control that could not fail. A live suite that
    does not scope its reads measures whatever ran before it.
    """
    from app.models.alert import AlertSeverity

    tenant = await make_tenant("rcsev")
    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 14, 0, tzinfo=UTC)
    # Deliberately: `critical` is alphabetically *below* `medium`, so an
    # alphabetical ORDER BY picks the wrong one and this goes red.
    severities = (AlertSeverity.MEDIUM, AlertSeverity.CRITICAL, AlertSeverity.MEDIUM)
    for n, (vendor, severity) in enumerate(zip(VENDORS[:3], severities, strict=True)):
        await sink.persist(
            _fused(
                tenant,
                vendor=vendor,
                resource="storage-sev",
                principal="deployer-sev",
                severity=severity,
                when=base + timedelta(minutes=n),
            )
        )

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT severity, vendor_count FROM root_cause_findings WHERE tenant_id = $1",
            tenant,
        )
    assert row is not None, "no finding was formed for this tenant"
    assert row["vendor_count"] == 3
    assert str(row["severity"]).lower() == "critical", (
        f"the finding reports {row['severity']!r}; one critical report among three makes a "
        "critical finding, and alphabetical ordering puts 'critical' below 'medium'"
    )


@pytest.mark.asyncio(loop_scope="module")
async def test_every_original_still_resolves_to_its_finding(pool, make_tenant) -> None:
    """Deduplicated evidence must still resolve to its retained record.

    The eval-honesty rule, as a join rather than a promise: a finding that
    could not name its members would be a reduction nobody can audit.
    """
    from app.models.alert import AlertSeverity

    tenant = await make_tenant("rcmembers")
    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 11, 0, tzinfo=UTC)
    for n, vendor in enumerate(VENDORS[:3]):
        await sink.persist(
            _fused(
                tenant,
                vendor=vendor,
                resource="storage-777",
                principal="deployer-09",
                severity=AlertSeverity.MEDIUM,
                when=base + timedelta(minutes=n),
            )
        )

    async with pool.acquire() as conn:
        members = await conn.fetch(
            """
            SELECT m.alert_id, m.connector_type, a.title
              FROM alert_root_cause_members m
              JOIN alerts a ON a.id = m.alert_id AND a.tenant_id = m.tenant_id
              JOIN root_cause_findings f ON f.id = m.finding_id
             WHERE m.tenant_id = $1
             ORDER BY m.added_at
            """,
            tenant,
        )
    assert len(members) == 3
    assert {m["connector_type"] for m in members} == set(VENDORS[:3])
    # Each member is a real alert row that still exists and is still its
    # own vendor's finding.
    assert all(m["title"].startswith(m["connector_type"]) for m in members)


@pytest.mark.asyncio(loop_scope="module")
async def test_a_different_technique_on_one_resource_is_a_different_finding(pool, make_tenant) -> None:
    """Resource alone over-collapses — the lesson v21 paid for."""
    from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert

    tenant = await make_tenant("rctech")
    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)

    for technique in ("T1530", "T1087"):
        raw = RawAlert(
            tenant_id=tenant,
            source="wiz",
            title=f"wiz: {technique} on storage-555",
            severity=AlertSeverity.MEDIUM,
            hostname="storage-555",
            username="deployer-02",
            mitre_techniques=[technique],
            connector_type="wiz",
            event_time=base,
        )
        raw.id = raw.deterministic_id()
        await sink.persist(FusedAlert(id=raw.id, tenant_id=tenant, fusion_decision=FusionDecision.NEW_ALERT, alert=raw))

    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM root_cause_findings WHERE tenant_id = $1", tenant)
    assert count == 2, "two techniques on one resource collapsed into one finding"


@pytest.mark.asyncio(loop_scope="module")
async def test_an_alert_with_an_incomplete_key_forms_no_finding(pool, make_tenant) -> None:
    """A NULL does not match another NULL.

    Treating absence as agreement is how a conservative key becomes a wide
    one, and a finding keyed on two unknowns would collapse an entire
    tenant's unattributed alerts into a single record.
    """
    from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert

    tenant = await make_tenant("rcpartial")
    sink = await _sink(pool)
    for n in range(3):
        raw = RawAlert(
            tenant_id=tenant,
            source="wiz",
            title=f"no principal {n}",
            severity=AlertSeverity.MEDIUM,
            hostname="storage-888",
            mitre_techniques=["T1530"],
            connector_type="wiz",
        )
        raw.id = raw.deterministic_id()
        await sink.persist(FusedAlert(id=raw.id, tenant_id=tenant, fusion_decision=FusionDecision.NEW_ALERT, alert=raw))

    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT count(*) FROM root_cause_findings WHERE tenant_id = $1", tenant)
    assert count == 0


@pytest.mark.asyncio(loop_scope="module")
async def test_findings_are_tenant_isolated_under_forced_rls(pool, make_tenant) -> None:
    tenant = await make_tenant("rcrls")
    from app.models.alert import AlertSeverity

    sink = await _sink(pool)
    await sink.persist(
        _fused(
            tenant,
            vendor="wiz",
            resource="storage-999",
            principal="deployer-03",
            severity=AlertSeverity.HIGH,
            when=datetime(2026, 11, 1, 13, 0, tzinfo=UTC),
        )
    )

    async with pool.acquire() as conn:
        role = await conn.fetchval("SELECT current_user")
        bypasses = await conn.fetchval("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
        assert not bypasses, f"connected as {role}, which bypasses RLS; this would pass for the wrong reason"

        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant))
        assert await conn.fetchval("SELECT count(*) FROM root_cause_findings") >= 1
        assert await conn.fetchval("SELECT count(*) FROM alert_root_cause_members") >= 1

        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(uuid.uuid4()))
        assert await conn.fetchval("SELECT count(*) FROM root_cause_findings") == 0
        assert await conn.fetchval("SELECT count(*) FROM alert_root_cause_members") == 0
        await conn.execute("SELECT set_config('app.current_tenant_id', '', false)")
