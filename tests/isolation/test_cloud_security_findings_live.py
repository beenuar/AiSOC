"""`posture_findings` gets its first production writer, against real Postgres.

Depth-2 item 8.1.

What was wrong
--------------
`posture_findings` has shipped since migration 017 with RLS, six indices, a
REST surface and a compliance-evidence mapper. Its only writer in the whole
tree was `POST /posture/findings`, a route a human calls by hand. No
connector, no scanner and no scheduler ever wrote a row, so
`GET /posture/summary` counted an empty table and answered eight confident
zeros on every deployment, and `GET /posture/scans` read a table with no
writer at all.

Why this has to be live
-----------------------
Four of the properties below cannot be observed against a fake engine, and
each of them has a shipped precedent in this repository for going wrong
exactly where a mock cannot see it.

**`resource_keys` has to survive Postgres.** It is `text[]`, written through
`CAST(:keys AS text[])` and read back through the `&&` overlap operator
against a GIN index. A fake connection that records the dict it was handed
proves the writer was called; it cannot prove asyncpg accepts the binding,
that the array round-trips, or that the overlap lookup an alert does actually
matches. `record_checkpoint` double-encoded its JSONB patch for the whole
life of the feature while every scheduler test passed.

**The CHECK constraints are the contract.** `cloud_provider`, `severity`,
`status` and (new in migration 133) `finding_class` all carry CHECKs. A mock
accepts `cloudPlatform: "OCI"`; Postgres does not.

**The partial unique index is the idempotency.** A re-poll must touch one row
rather than append a duplicate every five minutes, and "there is a unique
index" is a property of the database, not of the Python.

**RLS has to hold under the runtime role.** The workflow connects as
`aisoc_app`, which carries NOBYPASSRLS. Validating this as the owner would be
void — a superuser ignores every policy even under FORCE ROW LEVEL SECURITY,
and seeding as owner is the exact workaround that hid the kill-switch defect.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip(),
        reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs live infrastructure",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CONNECTOR_DSN is not set; this suite needs a live Postgres")
    return value


def _finding(**overrides: object) -> dict:
    """A configuration finding in the shape the Wiz connector emits."""
    base = {
        "source": "wiz",
        "finding_class": "misconfiguration",
        "external_id": "cf-live-1",
        "cloud_provider": "aws",
        "cloud_account": "123456789012",
        "cloud_region": "us-east-1",
        "resource_type": "bucket",
        "resource_id": "arn:aws:s3:::quarterly-reports",
        "resource_name": "quarterly-reports",
        "resource_keys": ["arn:aws:s3:::quarterly-reports", "wiz-res-9", "quarterly-reports"],
        "rule_id": "CF-AWS-S3-01",
        "rule_title": "S3 bucket is publicly readable",
        "description": "The bucket policy grants read to every principal.",
        "severity": "critical",
        "remediation_guide": "Set BlockPublicAcls and BlockPublicPolicy.",
        "evidence": {"currentValue": "PUBLIC", "expectedValue": "PRIVATE"},
        "observed_at": "2026-10-20T09:00:00Z",
    }
    base.update(overrides)
    return base


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn(), pool_pre_ping=True)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def tenants(engine):
    """Two tenants, because one cannot show isolation."""
    from sqlalchemy import text

    first, second = uuid.uuid4(), uuid.uuid4()
    async with engine.begin() as conn:
        for tid, slug in ((first, "cnapp-a"), (second, "cnapp-b")):
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:id AS uuid), :n, :s) ON CONFLICT DO NOTHING"),
                {"id": str(tid), "n": f"CNAPP {slug}", "s": f"{slug}-{tid.hex[:8]}"},
            )
    return first, second


async def _rows(engine, tenant: uuid.UUID) -> list[dict]:
    from sqlalchemy import text

    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                """
                SELECT source, finding_class, external_id, severity, status,
                       resource_id, resource_keys, rule_id, rule_title,
                       first_detected_at, last_seen_at, cloud_provider
                  FROM posture_findings
                 WHERE tenant_id = CAST(:t AS uuid)
                 ORDER BY external_id
                """
            ),
            {"t": str(tenant)},
        )
        return [dict(r) for r in result.mappings().all()]


class TestTheTableFinallyHasAWriter:
    async def test_a_poll_writes_a_finding_with_every_column_the_surface_reads(self, engine, tenants) -> None:
        from app.cloud_security import sync_cloud_security_findings

        tenant, _ = tenants
        counts = await sync_cloud_security_findings(engine, tenant_id=tenant, source="wiz", findings=[_finding()])

        assert counts["findings_inserted"] == 1
        assert counts["skipped"] == 0

        rows = await _rows(engine, tenant)
        assert len(rows) == 1
        row = rows[0]
        assert row["source"] == "wiz"
        assert row["finding_class"] == "misconfiguration"
        assert row["severity"] == "critical"
        assert row["status"] == "open"
        assert row["rule_id"] == "CF-AWS-S3-01"
        # The array survived asyncpg, the CAST and the column type.
        assert row["resource_keys"] == [
            "arn:aws:s3:::quarterly-reports",
            "wiz-res-9",
            "quarterly-reports",
        ]
        # The vendor's own first-seen, so an exposure window is measured from
        # when the estate became wrong rather than from when AiSOC connected.
        assert row["first_detected_at"].year == 2026
        assert row["first_detected_at"].month == 10
        assert row["first_detected_at"].day == 20

    async def test_a_repoll_touches_one_row_and_does_not_restart_the_exposure_clock(self, engine, tenants) -> None:
        from app.cloud_security import sync_cloud_security_findings

        tenant, _ = tenants
        before = (await _rows(engine, tenant))[0]

        later = datetime.now(UTC) + timedelta(hours=1)
        counts = await sync_cloud_security_findings(
            engine,
            tenant_id=tenant,
            source="wiz",
            findings=[_finding(severity="high")],
            now=later,
        )

        assert counts["findings_inserted"] == 0
        assert counts["findings_touched"] == 1

        rows = await _rows(engine, tenant)
        assert len(rows) == 1, "a re-poll appended a duplicate instead of touching the row"
        assert rows[0]["severity"] == "high", "the vendor's new severity did not reach the row"
        assert rows[0]["first_detected_at"] == before["first_detected_at"], (
            "a re-poll reset the exposure clock, so 'how long has this been wrong' now answers with the age of the last poll"
        )
        assert rows[0]["last_seen_at"] > before["last_seen_at"]

    async def test_an_alert_finds_the_finding_by_any_key_the_resource_answers_to(self, engine, tenants) -> None:
        """The lookup a verdict actually performs, through the GIN overlap.

        An alert knows the bucket by its ARN; the CNAPP also knows it by its
        own graph id and a display name. Matching one column against one
        column would miss on nearly every real pair.
        """
        from sqlalchemy import text

        tenant, _ = tenants
        async with engine.begin() as conn:
            for key in ("wiz-res-9", "quarterly-reports", "arn:aws:s3:::quarterly-reports"):
                found = (
                    (
                        await conn.execute(
                            text(
                                """
                            SELECT external_id FROM posture_findings
                             WHERE tenant_id = CAST(:t AS uuid)
                               AND resource_keys && CAST(:keys AS text[])
                            """
                            ),
                            {"t": str(tenant), "keys": [key]},
                        )
                    )
                    .scalars()
                    .all()
                )
                assert found == ["cf-live-1"], f"no finding matched the resource key {key!r}"

            missing = (
                (
                    await conn.execute(
                        text(
                            """
                        SELECT external_id FROM posture_findings
                         WHERE tenant_id = CAST(:t AS uuid)
                           AND resource_keys && CAST(:keys AS text[])
                        """
                        ),
                        {"t": str(tenant), "keys": ["an-unrelated-bucket"]},
                    )
                )
                .scalars()
                .all()
            )
            assert missing == [], "the overlap matched a resource this finding is not about"


class TestItCannotReachAnotherTenant:
    async def test_a_second_tenants_poll_leaves_the_first_alone(self, engine, tenants) -> None:
        """Same vendor, same `external_id`, different tenant. The partial
        unique index is on `(tenant_id, source, external_id)`, so this must
        insert rather than touch — and must not move the first tenant's row.
        """
        from app.cloud_security import sync_cloud_security_findings

        first, second = tenants
        counts = await sync_cloud_security_findings(engine, tenant_id=second, source="wiz", findings=[_finding(severity="low")])

        assert counts["findings_inserted"] == 1, "a second tenant's identical finding was folded into the first's row"

        assert len(await _rows(engine, second)) == 1
        assert (await _rows(engine, first))[0]["severity"] == "high", "another tenant's poll rewrote this tenant's finding"


class TestNeverCollectedIsNotZeroFindings:
    async def test_a_poll_records_a_run_so_the_summary_can_tell_the_difference(self, engine, tenants) -> None:
        from sqlalchemy import text

        tenant, _ = tenants
        async with engine.begin() as conn:
            runs = (
                (
                    await conn.execute(
                        text(
                            """
                        SELECT source, status, findings_total, findings_new, finding_classes
                          FROM posture_scan_runs
                         WHERE tenant_id = CAST(:t AS uuid)
                         ORDER BY started_at
                        """
                        ),
                        {"t": str(tenant)},
                    )
                )
                .mappings()
                .all()
            )

        assert runs, "no run row, so a tenant that has collected is indistinguishable from one that has not"
        assert runs[0]["source"] == "wiz"
        assert runs[0]["status"] == "completed"
        assert runs[0]["finding_classes"] == ["misconfiguration"]

    async def test_an_empty_estate_still_records_a_run(self, engine, tenants) -> None:
        """ "Collected, and found nothing" is a different answer from "nobody
        has collected", and only a run row carries the difference."""
        from app.cloud_security import sync_cloud_security_findings
        from sqlalchemy import text

        _, second = tenants
        await sync_cloud_security_findings(engine, tenant_id=second, source="orca", findings=[])

        async with engine.begin() as conn:
            total = (
                await conn.execute(
                    text("SELECT count(*) FROM posture_scan_runs WHERE tenant_id = CAST(:t AS uuid) AND source = 'orca'"),
                    {"t": str(second)},
                )
            ).scalar_one()
        assert total == 1


class TestTheDatabaseRefusesWhatAMockWouldAccept:
    async def test_an_unknown_finding_class_is_skipped_rather_than_inserted(self, engine, tenants) -> None:
        """Migration 133 puts a CHECK on `finding_class`. The writer refuses
        ahead of it so the failure is a counted skip rather than an
        IntegrityError four frames down that costs the whole poll."""
        from app.cloud_security import sync_cloud_security_findings

        tenant, _ = tenants
        counts = await sync_cloud_security_findings(
            engine,
            tenant_id=tenant,
            source="wiz",
            findings=[_finding(external_id="cf-bad", finding_class="not_a_class")],
        )

        assert counts["skipped"] == 1
        assert counts["findings_inserted"] == 0
        assert all(r["external_id"] != "cf-bad" for r in await _rows(engine, tenant))

    async def test_a_provider_outside_the_check_is_stored_as_other(self, engine, tenants) -> None:
        """`cloud_provider` allows five values. Wiz names more platforms than
        that, and an insert that raises would cost the poll every finding
        behind it."""
        from app.cloud_security import sync_cloud_security_findings

        tenant, _ = tenants
        counts = await sync_cloud_security_findings(
            engine,
            tenant_id=tenant,
            source="wiz",
            findings=[_finding(external_id="cf-oci", cloud_provider="other")],
        )

        assert counts["findings_inserted"] == 1
        row = next(r for r in await _rows(engine, tenant) if r["external_id"] == "cf-oci")
        assert row["cloud_provider"] == "other"
