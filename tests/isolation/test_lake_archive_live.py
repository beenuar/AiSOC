"""The archive tier against live ClickHouse + MinIO + Postgres (WS2).

Why this has to be live
-----------------------
* The export, the count read-back and the SHA-256 all run **inside
  ClickHouse** (`INSERT INTO FUNCTION s3`, `s3(...,'Parquet')`,
  `s3(...,'RawBLOB')`) — a stub proves none of them, and the parameter
  binding into table-function arguments is exactly the kind of claim that
  only a real engine can confirm.
* Corruption detection is the point of verification: this suite flips one
  byte in the bucket and the verifier must FAIL naming the checksum — a
  verifier that stays green over a corrupted object is worse than none.
* Portability means **no AiSOC code**: DuckDB (a third-party reader) opens
  the exported Parquet and the row count matches the signed manifest.
* The rehydrated scratch table must be queryable through the explorer's
  own rewriter, under the same tenant predicate raw_events gets.
* The scoped-hold purge narrowing is SQL the unit tests can only shape-check:
  here a held user's aged alerts survive the purge while the rest delete.

Environment (all required; the CI step provisions them):
    LAKE_ARCHIVE_LIVE_CH_HOST / _CH_PORT / _CH_USER / _CH_PASSWORD
    LAKE_ARCHIVE_LIVE_S3_ENDPOINT_FOR_CH   (what ClickHouse can reach)
    LAKE_ARCHIVE_LIVE_S3_ENDPOINT          (what this process can reach)
    LAKE_ARCHIVE_LIVE_S3_ACCESS / _S3_SECRET
    LAKE_ARCHIVE_LIVE_PG_ADMIN_DSN         (owner, fixtures)
    LAKE_ARCHIVE_LIVE_PG_DSN               (aisoc_app, assertions)
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("LAKE_ARCHIVE_LIVE_CH_HOST", "").strip(),
        reason="LAKE_ARCHIVE_LIVE_CH_HOST is not set; this suite needs live ClickHouse + MinIO + Postgres",
    ),
]

_API = Path(__file__).resolve().parents[2] / "services" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

TENANT = uuid.uuid4()
OTHER_TENANT = uuid.uuid4()
MONTH = date(2026, 9, 1)
SIGNING_KEY = "live-archive-signing-key"


def _env(name: str) -> str:
    return os.environ[name].strip()


def _configure_clickhouse_settings() -> None:
    """Point the API's lake client at the harness ClickHouse.

    Must run before `app.db.clickhouse` builds its client; the fixture
    imports app modules only after this."""
    os.environ.setdefault("CLICKHOUSE_HOST", _env("LAKE_ARCHIVE_LIVE_CH_HOST"))
    os.environ.setdefault("CLICKHOUSE_PORT", os.environ.get("LAKE_ARCHIVE_LIVE_CH_PORT", "9000"))
    os.environ.setdefault("CLICKHOUSE_USER", os.environ.get("LAKE_ARCHIVE_LIVE_CH_USER", "aisoc"))
    os.environ.setdefault("CLICKHOUSE_PASSWORD", os.environ.get("LAKE_ARCHIVE_LIVE_CH_PASSWORD", ""))
    os.environ.setdefault("CLICKHOUSE_DATABASE", "aisoc")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def harness():
    _configure_clickhouse_settings()
    import asyncpg
    from app.db.clickhouse import execute_lake_query
    from app.services import lake_archive

    dest_for_ch = lake_archive.Destination(
        endpoint=_env("LAKE_ARCHIVE_LIVE_S3_ENDPOINT_FOR_CH"),
        bucket="tenant-archive",
        access_key=_env("LAKE_ARCHIVE_LIVE_S3_ACCESS"),
        secret_key=_env("LAKE_ARCHIVE_LIVE_S3_SECRET"),
    )

    # Seed one closed month for the tenant (plus noise: another tenant and
    # a newer month) through the lake's own insert path.
    rows = []
    for day in (3, 12, 21):
        rows.append((str(TENANT), datetime(2026, 9, day, 10, 0, tzinfo=UTC), "mallory@example.com"))
    rows.append((str(TENANT), datetime(2026, 10, 2, 10, 0, tzinfo=UTC), "mallory@example.com"))
    rows.append((str(OTHER_TENANT), datetime(2026, 9, 5, 10, 0, tzinfo=UTC), "bystander@example.com"))
    for tenant_id, ts, user in rows:
        await execute_lake_query(
            """
            INSERT INTO aisoc.raw_events (event_id, tenant_id, event_time, ingest_time, user_name,
                                          connector_type, action, severity, severity_id, raw_payload)
            VALUES (%(eid)s, %(tid)s, %(ts)s, %(ts)s, %(user)s, 'm365_audit', 'FileUploaded', 'low', 2, '{}')
            """,
            params={"eid": str(uuid.uuid4()), "tid": tenant_id, "ts": ts, "user": user},
        )

    admin = await asyncpg.connect(_env("LAKE_ARCHIVE_LIVE_PG_ADMIN_DSN"))
    suffix = uuid.uuid4().hex[:8]
    for tenant, label in ((TENANT, f"arch-a-{suffix}"), (OTHER_TENANT, f"arch-b-{suffix}")):
        await admin.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT (id) DO NOTHING",
            tenant,
            label,
        )
    yield execute_lake_query, lake_archive, dest_for_ch, admin

    for tenant in (TENANT, OTHER_TENANT):
        await admin.execute("DELETE FROM lake_archive_partitions WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM lake_rehydrations WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM legal_holds WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM alerts WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM tenants WHERE id = $1", tenant)
    await admin.close()


async def test_export_builds_a_signed_manifest_and_verification_passes(harness):
    _execute, lake_archive, dest, _admin = harness
    manifest = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    assert manifest["row_count"] == 3  # the other tenant's row and October stayed out
    assert manifest["schema_version"] == lake_archive.ARCHIVE_SCHEMA_VERSION
    assert manifest["files"][0]["sha256"] and manifest["files"][0]["bytes"] > 0
    assert manifest["signature"], "the manifest must carry the evidence-bundle signature"

    problems = await lake_archive.verify_partition(manifest, dest)
    assert problems == [], f"verification must pass on an untouched object: {problems}"


async def test_an_open_month_is_refused(harness):
    _execute, lake_archive, dest, _admin = harness
    today = datetime.now(UTC).date()
    with pytest.raises(lake_archive.ArchiveConfigError, match="not closed"):
        await lake_archive.export_month(TENANT, date(today.year, today.month, 1), dest, signing_key=SIGNING_KEY)


async def test_corruption_is_detected_by_name(harness):
    """Flip the object's bytes; the verifier must fail on the checksum."""
    _execute, lake_archive, dest, _admin = harness
    manifest = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    key = manifest["files"][0]["path"]

    # Corrupt through the same engine that wrote it: curl's SigV4 refuses
    # keys containing '=' (the partition path), and the point is only that
    # the bytes in the bucket change under the manifest.
    from app.db.clickhouse import execute_lake_query as _elq

    await _elq(
        "INSERT INTO FUNCTION s3(%(url)s, %(ak)s, %(sk)s, 'RawBLOB', 'raw String') VALUES ('corrupted-bytes-not-parquet')",
        params={"url": dest.url(key), "ak": dest.access_key, "sk": dest.secret_key},
        extra_settings={"s3_truncate_on_insert": 1},
    )

    problems = await lake_archive.verify_partition(manifest, dest)
    assert problems, "a corrupted object must fail verification"
    assert any("sha256 differs" in p or "unreadable" in p or "row count differs" in p for p in problems), problems

    # Restore the real object for the suites below.
    restored = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    assert await lake_archive.verify_partition(restored, dest) == []


async def test_a_same_count_content_swap_is_caught_by_the_checksum_alone(harness):
    """The sharper corruption: a VALID Parquet object with the SAME row
    count but different bytes (re-written with a different compression
    codec). The count read-back passes; only the SHA-256 leg can refuse it
    — which is why the manifest carries one."""
    execute_lake_query, lake_archive, dest, _admin = harness
    manifest = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    key = manifest["files"][0]["path"]
    start, end = lake_archive.month_bounds(MONTH)

    # Same rows, different bytes: recompress the object in place.
    await execute_lake_query(
        """
        INSERT INTO FUNCTION s3(%(url)s, %(ak)s, %(sk)s, 'Parquet')
        SELECT * REPLACE (toString(event_id) AS event_id, toString(tenant_id) AS tenant_id,
                          toString(source_ip) AS source_ip, toString(dest_ip) AS dest_ip)
        FROM aisoc.raw_events
        WHERE tenant_id = %(tenant_id)s AND event_time >= %(start)s AND event_time < %(end)s
        """,
        params={
            "url": dest.url(key),
            "ak": dest.access_key,
            "sk": dest.secret_key,
            "tenant_id": str(TENANT),
            "start": start,
            "end": end,
        },
        extra_settings={
            "s3_truncate_on_insert": 1,
            "output_format_parquet_compression_method": "gzip",
        },
    )

    problems = await lake_archive.verify_partition(manifest, dest)
    assert problems, "a content swap with an unchanged row count must still fail"
    assert any("sha256 differs" in p for p in problems), problems
    assert not any("row count differs" in p for p in problems), (
        "this case must isolate the checksum leg; the counts are equal by construction"
    )

    restored = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    assert await lake_archive.verify_partition(restored, dest) == []


async def test_rehydration_loads_a_queryable_tenant_scoped_table(harness):
    execute_lake_query, lake_archive, dest, _admin = harness
    from app.services.lake_sql import rewrite_for_tenant

    manifest = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    rid = uuid.uuid4()
    table, loaded = await lake_archive.load_rehydration(rid, TENANT, [manifest], dest)
    try:
        assert loaded == 3
        # The explorer's own rewriter accepts the scratch table and injects
        # the tenant predicate; the other tenant reads zero rows from it.
        mine = await execute_lake_query(rewrite_for_tenant(f"SELECT count() FROM {table}", TENANT).sql)
        assert int(mine.rows[0][0]) == 3
        theirs = await execute_lake_query(rewrite_for_tenant(f"SELECT count() FROM {table}", OTHER_TENANT).sql)
        assert int(theirs.rows[0][0]) == 0
    finally:
        await lake_archive.drop_rehydration_table(table)


async def test_estimate_reports_real_bytes_and_null_cost_without_a_price(harness):
    _execute, lake_archive, dest, _admin = harness
    manifest = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    os.environ.pop("AISOC_ARCHIVE_RETRIEVAL_PRICE_PER_GB", None)
    estimate = lake_archive.estimate_from_manifests([manifest])
    assert estimate["bytes"] == manifest["files"][0]["bytes"]
    assert estimate["files"] == 1 and estimate["months"] == 1
    assert estimate["retrieval_cost"] is None
    assert "unknown, not zero" in estimate["retrieval_cost_note"]


async def test_portability_export_reads_with_duckdb_and_no_aisoc_code(harness):
    _execute, lake_archive, _dest, _admin = harness
    duckdb = pytest.importorskip("duckdb", reason="the portability gate needs duckdb installed")

    dest = lake_archive.Destination(
        endpoint=_env("LAKE_ARCHIVE_LIVE_S3_ENDPOINT_FOR_CH"),
        bucket="tenant-export",
        access_key=_env("LAKE_ARCHIVE_LIVE_S3_ACCESS"),
        secret_key=_env("LAKE_ARCHIVE_LIVE_S3_SECRET"),
    )
    manifest = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY, prefix="aisoc-portability")
    key = manifest["files"][0]["path"]

    host_endpoint = _env("LAKE_ARCHIVE_LIVE_S3_ENDPOINT")
    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs;")
    host = host_endpoint.removeprefix("http://").removeprefix("https://")
    con.execute(f"SET s3_endpoint='{host}'")
    con.execute("SET s3_use_ssl=false")
    con.execute("SET s3_url_style='path'")
    con.execute(f"SET s3_access_key_id='{dest.access_key}'")
    con.execute(f"SET s3_secret_access_key='{dest.secret_key}'")
    count = con.execute(f"SELECT count(*) FROM read_parquet('s3://{dest.bucket}/{key}')").fetchone()[0]
    assert count == manifest["row_count"], f"DuckDB read {count} rows; the signed manifest says {manifest['row_count']}"


async def test_scoped_hold_narrows_the_alert_purge_to_its_own_rows(harness):
    """Two aged alerts for the held user survive; three others delete —
    against real Postgres, through the worker's own purge function."""
    _execute, _lake_archive, _dest, admin = harness
    from app.workers import retention_purge
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    for n in range(3):
        await admin.execute(
            """
            INSERT INTO alerts (id, tenant_id, title, severity, status, created_at, affected_users)
            VALUES ($1, $2, $3, 'low', 'resolved', now() - interval '400 days', $4::jsonb)
            """,
            uuid.uuid4(),
            TENANT,
            f"aged unheld {n}",
            '["alice@example.com"]',
        )
    for n in range(2):
        await admin.execute(
            """
            INSERT INTO alerts (id, tenant_id, title, severity, status, created_at, affected_users)
            VALUES ($1, $2, $3, 'low', 'resolved', now() - interval '400 days', $4::jsonb)
            """,
            uuid.uuid4(),
            TENANT,
            f"aged HELD {n}",
            '["Mallory@Example.com"]',
        )
    await admin.execute(
        """
        INSERT INTO legal_holds (tenant_id, name, subject_kind, subject_value, covers_from)
        VALUES ($1, 'live matter', 'user', 'mallory@example.com', now() - interval '3 years')
        """,
        TENANT,
    )

    dsn = _env("LAKE_ARCHIVE_LIVE_PG_ADMIN_DSN").replace("postgresql://", "postgresql+asyncpg://")
    engine = create_async_engine(dsn, poolclass=None)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            posture = await retention_purge._hold_posture(db, TENANT)
            assert posture.freeze_refs == [], "a user hold must not freeze the tenant"
            assert len(posture.narrow_holds) == 1
            purged = await retention_purge._purge_alerts(db, TENANT, days=365, dry_run=False, narrow_holds=posture.narrow_holds)
            await db.commit()
        assert purged == 3, f"expected the 3 unheld aged alerts to purge, got {purged}"
    finally:
        await engine.dispose()
    survivors = await admin.fetch("SELECT title FROM alerts WHERE tenant_id = $1 ORDER BY title", TENANT)
    titles = [r["title"] for r in survivors]
    assert titles == ["aged HELD 0", "aged HELD 1"], titles


async def test_attestation_reports_each_tier_from_its_own_store(harness):
    _execute, lake_archive, dest, admin = harness
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    manifest = await lake_archive.export_month(TENANT, MONTH, dest, signing_key=SIGNING_KEY)
    import json as _json

    await admin.execute(
        """
        INSERT INTO lake_archive_partitions (tenant_id, month, status, manifest, verified_at)
        VALUES ($1, $2, 'verified', $3::jsonb, now())
        ON CONFLICT (tenant_id, month) DO UPDATE SET status='verified', manifest=EXCLUDED.manifest, verified_at=now()
        """,
        TENANT,
        MONTH,
        _json.dumps(manifest),
    )
    dsn = _env("LAKE_ARCHIVE_LIVE_PG_ADMIN_DSN").replace("postgresql://", "postgresql+asyncpg://")
    engine = create_async_engine(dsn, poolclass=None)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            attestation = await lake_archive.retention_attestation(db, TENANT, lake_days=400, worm_declared=False)
    finally:
        await engine.dispose()
    assert attestation["archive"]["partitions"] >= 1
    assert attestation["archive"]["verified"] >= 1
    assert attestation["archive"]["worm"] == "not declared"
    assert attestation["hot_and_lake"]["oldest_row"], "the lake has rows; oldest must be measured"
    holds = attestation["legal_holds"]
    assert holds and holds[0]["narrows_purge"] is True
