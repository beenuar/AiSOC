"""Archive sweep: export closed months, verify, expire rehydrations (WS2).

Three jobs on one tick, each bounded so a large estate cannot wedge the
loop:

* **Export** — for every tenant whose policy row says ``enabled``, any
  closed month still present in the lake and absent from the partition
  ledger is exported (oldest first, at most ``MAX_EXPORTS_PER_TICK`` per
  tick). The current month never exports: it is still receiving rows, and
  an object cut from it would be silently incomplete.
* **Verify** — exported-but-unverified partitions are read back (at most
  ``MAX_VERIFIES_PER_TICK``): counts from the Parquet object, SHA-256 from
  the raw bytes, both through ClickHouse. A mismatch marks the partition
  ``failed`` with the differing fact named.
* **Expire** — rehydrations past ``expires_at`` have their scratch table
  dropped and the row marked ``expired``. A scratch table that outlives
  its job is retention nobody chose.

Per-tenant opt-in does the real gating (an absent/disabled policy row means
nothing exports); the worker itself is on by default like the other
hygiene sweeps.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.clickhouse import execute_lake_query
from app.db.database import AsyncSessionLocal
from app.services import lake_archive
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.lake_archive_sweep")

MAX_EXPORTS_PER_TICK = 4
MAX_VERIFIES_PER_TICK = 8

_ENABLED_POLICIES_SQL = text(
    """
    SELECT tenant_id, s3_endpoint, s3_bucket, s3_access_key_enc, s3_secret_key_enc, archive_years
    FROM lake_archive_policies
    WHERE enabled = TRUE
    """
)

_EXPORTED_MONTHS_SQL = text("SELECT month FROM lake_archive_partitions WHERE tenant_id = :tenant_id")

_UPSERT_PARTITION_SQL = text(
    """
    INSERT INTO lake_archive_partitions (tenant_id, month, status, manifest, exported_at)
    VALUES (:tenant_id, :month, 'exported', CAST(:manifest AS jsonb), now())
    ON CONFLICT (tenant_id, month)
    DO UPDATE SET manifest = EXCLUDED.manifest, status = 'exported',
                  exported_at = now(), verified_at = NULL, failure_reason = NULL
    """
)

_UNVERIFIED_SQL = text(
    """
    SELECT p.id, p.tenant_id, p.manifest,
           pol.s3_endpoint, pol.s3_bucket, pol.s3_access_key_enc, pol.s3_secret_key_enc
    FROM lake_archive_partitions p
    JOIN lake_archive_policies pol ON pol.tenant_id = p.tenant_id AND pol.enabled = TRUE
    WHERE p.status = 'exported'
    ORDER BY p.exported_at
    LIMIT :cap
    """
)

_MARK_VERIFIED_SQL = text(
    "UPDATE lake_archive_partitions SET status = 'verified', verified_at = now(), failure_reason = NULL WHERE id = :id"
)
_MARK_FAILED_SQL = text("UPDATE lake_archive_partitions SET status = 'failed', failure_reason = :reason WHERE id = :id")

_EXPIRED_REHYDRATIONS_SQL = text(
    """
    SELECT id, table_name FROM lake_rehydrations
    WHERE status = 'ready' AND expires_at <= now()
    """
)
_MARK_EXPIRED_SQL = text("UPDATE lake_rehydrations SET status = 'expired' WHERE id = :id")


@dataclass
class SweepSummary:
    exported: int = 0
    verified: int = 0
    verify_failed: int = 0
    rehydrations_expired: int = 0
    errors: list[str] = field(default_factory=list)


async def _candidate_months(tenant_id: uuid.UUID, already: set[date]) -> list[date]:
    """Closed months still present in the lake and absent from the ledger."""
    result = await execute_lake_query(
        """
        SELECT DISTINCT toStartOfMonth(event_time) AS m
        FROM aisoc.raw_events
        WHERE tenant_id = %(tenant_id)s
        ORDER BY m
        """,
        params={"tenant_id": str(tenant_id)},
    )
    today = datetime.now(UTC).date()
    current_month = date(today.year, today.month, 1)
    months: list[date] = []
    for row in result.rows:
        value = row[0]
        month = value.date() if isinstance(value, datetime) else value
        if month < current_month and month not in already:
            months.append(month)
    return months


async def run_once(db: AsyncSession | None = None) -> SweepSummary:
    summary = SweepSummary()
    own = db is None
    if db is None:
        db = AsyncSessionLocal()
    try:
        policies = (await db.execute(_ENABLED_POLICIES_SQL)).fetchall()
        exports_left = MAX_EXPORTS_PER_TICK
        for tenant_id, endpoint, bucket, ak_enc, sk_enc, _years in policies:
            if exports_left <= 0:
                break
            try:
                dest = lake_archive.destination_from_policy(
                    {
                        "s3_endpoint": endpoint,
                        "s3_bucket": bucket,
                        "s3_access_key_enc": ak_enc,
                        "s3_secret_key_enc": sk_enc,
                    }
                )
                already = {r[0] for r in (await db.execute(_EXPORTED_MONTHS_SQL, {"tenant_id": str(tenant_id)})).fetchall()}
                for month in await _candidate_months(tenant_id, already):
                    if exports_left <= 0:
                        break
                    manifest = await lake_archive.export_month(tenant_id, month, dest, signing_key=settings.SECRET_KEY)
                    await db.execute(
                        _UPSERT_PARTITION_SQL,
                        {
                            "tenant_id": str(tenant_id),
                            "month": month,
                            "manifest": json.dumps(manifest),
                        },
                    )
                    summary.exported += 1
                    exports_left -= 1
            except Exception as exc:  # noqa: BLE001 — one tenant's bucket must not stop the fleet
                summary.errors.append(f"export {tenant_id}: {type(exc).__name__}")
                logger.warning("lake_archive_sweep.export_failed tenant=%s err=%s", tenant_id, exc)

        for pid, _tenant, manifest, endpoint, bucket, ak_enc, sk_enc in (
            await db.execute(_UNVERIFIED_SQL, {"cap": MAX_VERIFIES_PER_TICK})
        ).fetchall():
            try:
                dest = lake_archive.destination_from_policy(
                    {
                        "s3_endpoint": endpoint,
                        "s3_bucket": bucket,
                        "s3_access_key_enc": ak_enc,
                        "s3_secret_key_enc": sk_enc,
                    }
                )
                problems = await lake_archive.verify_partition(dict(manifest or {}), dest)
                if problems:
                    await db.execute(_MARK_FAILED_SQL, {"id": pid, "reason": "; ".join(problems)[:1000]})
                    summary.verify_failed += 1
                else:
                    await db.execute(_MARK_VERIFIED_SQL, {"id": pid})
                    summary.verified += 1
            except Exception as exc:  # noqa: BLE001
                summary.errors.append(f"verify {pid}: {type(exc).__name__}")

        for rid, table_name in (await db.execute(_EXPIRED_REHYDRATIONS_SQL)).fetchall():
            try:
                if table_name:
                    await lake_archive.drop_rehydration_table(table_name)
                await db.execute(_MARK_EXPIRED_SQL, {"id": rid})
                summary.rehydrations_expired += 1
            except Exception as exc:  # noqa: BLE001
                summary.errors.append(f"expire {rid}: {type(exc).__name__}")

        await db.commit()
    finally:
        if own:
            await db.close()
    if summary.exported or summary.verified or summary.verify_failed or summary.rehydrations_expired or summary.errors:
        logger.info("lake_archive_sweep %s", summary)
    return summary


async def run_forever() -> None:
    interval = max(int(getattr(settings, "LAKE_ARCHIVE_SWEEP_INTERVAL_SECONDS", 3600)), 300)
    logger.info("lake_archive_sweep started interval=%ds", interval)
    failures = TickFailures("lake_archive_sweep", logger)
    try:
        while True:
            try:
                await run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                failures.record_failure(exc)
            else:
                failures.record_success()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("lake_archive_sweep stopped")
        raise
