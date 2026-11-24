"""The archive tier: closed lake months in an open format.

The shape of the thing
----------------------
The lake (`aisoc.raw_events`) holds at most ``MAX_LAKE_DAYS`` of events —
the ClickHouse TTL is a hard ceiling nothing exempts. Everything older
exists only if it was exported first. So the archive is the only path to
multi-year retention, and it has to be trustworthy in a way a copy script
is not:

* **The database that owns the rows writes the files.** Exports run inside
  ClickHouse — ``INSERT INTO FUNCTION s3(...) ... FORMAT Parquet`` — so
  there is no second data path whose row semantics could drift from the
  lake's own. Verification re-reads through the same engine: the row count
  from the Parquet object, the SHA-256 from the raw bytes (``RawBLOB``).
  "Exported" is a claim; **"verified" means the bucket was read back and
  matched.**
* **One object per (tenant, month).** No listing API is needed to know
  what exists — the manifest names the exact path — and a partition is
  closed before it is exported, so the object never needs appending.
* **The manifest is signed** with the evidence-bundle signer (row count,
  event-time bounds, schema + OCSF version, per-file SHA-256), so a
  manifest row and a bucket object corroborate each other and neither can
  be quietly edited.
* **Portability is the same machinery pointed at the tenant's bucket**,
  plus a schema document — and the gate proves the export is readable with
  no AiSOC code by opening it with DuckDB.

Credentials
-----------
Bucket credentials are vault-encrypted at rest (`CredentialVault`) and
decrypted only at export time. They are bound into the statement by
``clickhouse-driver``'s client-side parameter escaping; ClickHouse masks
``s3()`` credential positions in ``system.query_log``, which the
deployment relies on and the docs state.

Cost honesty
------------
A rehydration estimate reports bytes, files and months from the manifests
— real numbers — and a retrieval **cost only when the deployment
configured a price** (``AISOC_ARCHIVE_RETRIEVAL_PRICE_PER_GB``). No price
configured means ``cost: null``, never an invented figure.
"""

from __future__ import annotations

import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.clickhouse import execute_lake_query
from app.security.credential_vault import get_vault
from app.services.evidence_bundle import sign_envelope

logger = logging.getLogger("aisoc.lake_archive")

#: The schema version written into every manifest. Bump when the lake's
#: column set changes shape (the manifest records what the files contain,
#: not what the current code would write).
ARCHIVE_SCHEMA_VERSION = "raw_events/v1"
OCSF_VERSION = "1.1.0"

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{2,62}$")
_ENDPOINT_RE = re.compile(r"^https?://[A-Za-z0-9.:\-]+(?::\d+)?$")


class ArchiveConfigError(ValueError):
    """A policy or request that cannot be executed, with the reason named."""


def object_path(tenant_id: uuid.UUID, month: date, *, prefix: str = "aisoc-archive") -> str:
    """The deterministic object key for a (tenant, month) partition."""
    return f"{prefix}/tenant={tenant_id}/month={month:%Y-%m}/events.parquet"


def month_bounds(month: date) -> tuple[datetime, datetime]:
    start = datetime(month.year, month.month, 1, tzinfo=UTC)
    end = datetime(month.year + 1, 1, 1, tzinfo=UTC) if month.month == 12 else datetime(month.year, month.month + 1, 1, tzinfo=UTC)
    return start, end


def validate_destination(endpoint: str, bucket: str) -> None:
    """Refuse endpoints/buckets the URL composer cannot carry safely."""
    if not _ENDPOINT_RE.match(endpoint or ""):
        raise ArchiveConfigError(
            f"s3_endpoint must be http(s)://host[:port] — got {endpoint!r}. Path-style addressing is composed from it."
        )
    if not _BUCKET_RE.match(bucket or ""):
        raise ArchiveConfigError(f"s3_bucket must be a valid bucket name — got {bucket!r}")


@dataclass(frozen=True)
class Destination:
    endpoint: str
    bucket: str
    access_key: str
    secret_key: str

    def url(self, key: str) -> str:
        return f"{self.endpoint.rstrip('/')}/{self.bucket}/{key}"


def destination_from_policy(row: dict[str, Any]) -> Destination:
    """Decrypt a policy row's credentials into a usable destination."""
    vault = get_vault()
    endpoint = str(row.get("s3_endpoint") or "")
    bucket = str(row.get("s3_bucket") or "")
    validate_destination(endpoint, bucket)
    return Destination(
        endpoint=endpoint,
        bucket=bucket,
        access_key=vault.decrypt(str(row["s3_access_key_enc"])),
        secret_key=vault.decrypt(str(row["s3_secret_key_enc"])),
    )


# ---------------------------------------------------------------------------
# Export + manifest + verification (the ClickHouse legs)
# ---------------------------------------------------------------------------


async def _partition_stats(tenant_id: uuid.UUID, month: date) -> dict[str, Any]:
    start, end = month_bounds(month)
    result = await execute_lake_query(
        """
        SELECT count() AS rows, min(event_time) AS t_min, max(event_time) AS t_max
        FROM aisoc.raw_events
        WHERE tenant_id = %(tenant_id)s
          AND event_time >= %(start)s AND event_time < %(end)s
        """,
        params={"tenant_id": str(tenant_id), "start": start, "end": end},
    )
    rows = result.rows[0] if result.rows else (0, None, None)
    return {"rows": int(rows[0]), "event_time_min": str(rows[1]), "event_time_max": str(rows[2])}


async def export_month(
    tenant_id: uuid.UUID,
    month: date,
    dest: Destination,
    *,
    signing_key: str,
    prefix: str = "aisoc-archive",
) -> dict[str, Any]:
    """Export one closed month to one Parquet object and build the manifest.

    Refuses an open month: the current month is still receiving rows, and
    an object exported from it would be silently incomplete — the
    connector-window lesson applied to archival.
    """
    today = datetime.now(UTC).date()
    if month >= date(today.year, today.month, 1):
        raise ArchiveConfigError(f"month {month:%Y-%m} is not closed yet; only strictly past months export")

    # UUID and IPv6 columns export as strings (`* REPLACE`): ClickHouse
    # cannot write UUID to Parquet (Code 50) and a string id is the more
    # portable spelling anyway. Column ORDER is preserved, so the
    # rehydration INSERT ... SELECT auto-casts them back positionally.

    stats = await _partition_stats(tenant_id, month)
    if int(stats["rows"]) == 0:  # type: ignore[arg-type]
        raise ArchiveConfigError(f"no rows in {month:%Y-%m} for this tenant; nothing to export")

    key = object_path(tenant_id, month, prefix=prefix)
    start, end = month_bounds(month)
    await execute_lake_query(
        """
        INSERT INTO FUNCTION s3(%(url)s, %(ak)s, %(sk)s, 'Parquet')
        SELECT * REPLACE (toString(event_id) AS event_id, toString(tenant_id) AS tenant_id,
                          toString(source_ip) AS source_ip, toString(dest_ip) AS dest_ip)
        FROM aisoc.raw_events
        WHERE tenant_id = %(tenant_id)s
          AND event_time >= %(start)s AND event_time < %(end)s
        """,
        params={
            "url": dest.url(key),
            "ak": dest.access_key,
            "sk": dest.secret_key,
            "tenant_id": str(tenant_id),
            "start": start,
            "end": end,
        },
        extra_settings={"s3_truncate_on_insert": 1},
        timeout_seconds=600.0,
    )

    sha256, size_bytes = await _object_sha256(dest, key)
    manifest: dict[str, Any] = {
        "tenant_id": str(tenant_id),
        "month": f"{month:%Y-%m}",
        "row_count": stats["rows"],
        "event_time_min": stats["event_time_min"],
        "event_time_max": stats["event_time_max"],
        "schema_version": ARCHIVE_SCHEMA_VERSION,
        "ocsf_version": OCSF_VERSION,
        "format": "parquet",
        "files": [{"path": key, "sha256": sha256, "bytes": size_bytes}],
        "exported_at": datetime.now(UTC).isoformat(),
    }
    # `sign_envelope` returns the integrity block alone; the manifest
    # carries its payload beside the signature so a verifier recomputes
    # the digest over exactly the payload half.
    manifest["signature"] = sign_envelope({k: v for k, v in manifest.items() if k != "signature"}, signing_key=signing_key)
    return manifest


async def _object_sha256(dest: Destination, key: str) -> tuple[str, int]:
    """SHA-256 + size of the object, computed by ClickHouse reading raw bytes.

    ``RawBLOB`` reads the whole object as a single value, so the hash is of
    the bytes in the bucket — the thing the verifier will re-hash — not of
    any local copy.
    """
    result = await execute_lake_query(
        """
        SELECT lower(hex(SHA256(raw))) AS sha, length(raw) AS bytes
        FROM s3(%(url)s, %(ak)s, %(sk)s, 'RawBLOB', 'raw String')
        """,
        params={"url": dest.url(key), "ak": dest.access_key, "sk": dest.secret_key},
        timeout_seconds=600.0,
    )
    row = result.rows[0]
    return str(row[0]), int(row[1])


async def verify_partition(manifest: dict[str, Any], dest: Destination) -> list[str]:
    """Re-read the bucket and compare with the manifest. Returns mismatches.

    Empty list means verified. Every mismatch names what differed — a count
    that moved, a checksum that moved, an object that is gone — because
    "verification failed" without the failing fact sends an operator
    hunting.
    """
    problems: list[str] = []
    files = manifest.get("files") or []
    for entry in files:  # type: ignore[union-attr]
        key = str(entry["path"])  # type: ignore[index]
        try:
            count_result = await execute_lake_query(
                "SELECT count() FROM s3(%(url)s, %(ak)s, %(sk)s, 'Parquet')",
                params={"url": dest.url(key), "ak": dest.access_key, "sk": dest.secret_key},
                timeout_seconds=600.0,
            )
            stored_rows = int(count_result.rows[0][0])
        except Exception as exc:  # noqa: BLE001 — an unreadable object is a named failure
            problems.append(f"{key}: unreadable ({type(exc).__name__})")
            continue
        if stored_rows != int(manifest["row_count"]):  # type: ignore[arg-type]
            problems.append(f"{key}: row count differs (manifest {manifest['row_count']}, bucket {stored_rows})")
        try:
            sha, _size = await _object_sha256(dest, key)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{key}: hash re-read failed ({type(exc).__name__})")
            continue
        if sha != str(entry["sha256"]):  # type: ignore[index]
            problems.append(f"{key}: sha256 differs (manifest {entry['sha256']}, bucket {sha})")
    if not files:
        problems.append("manifest lists no files")
    return problems


# ---------------------------------------------------------------------------
# Rehydration
# ---------------------------------------------------------------------------

#: The scratch-table namespace. `lake_sql.rewrite_for_tenant` recognises
#: exactly this shape and applies the same tenant predicate it applies to
#: raw_events, so a rehydrated range is queryable through the explorer
#: without widening what callers can name.
REHYDRATED_TABLE_RE = re.compile(r"^aisoc\.rehydrated_[0-9a-f]{8}$")


def rehydrated_table_name(rehydration_id: uuid.UUID) -> str:
    return f"aisoc.rehydrated_{rehydration_id.hex[:8]}"


def months_in_range(range_start: date, range_end: date) -> list[date]:
    months: list[date] = []
    cursor = date(range_start.year, range_start.month, 1)
    while cursor <= range_end:
        months.append(cursor)
        cursor = date(cursor.year + 1, 1, 1) if cursor.month == 12 else date(cursor.year, cursor.month + 1, 1)
    return months


def estimate_from_manifests(manifests: list[dict[str, Any]]) -> dict[str, Any]:
    """Bytes/files/months from the covering manifests; cost only if priced."""
    total_bytes = 0
    total_files = 0
    for m in manifests:
        for f in m.get("files") or []:  # type: ignore[union-attr]
            total_bytes += int(f.get("bytes") or 0)  # type: ignore[union-attr]
            total_files += 1
    price = os.environ.get("AISOC_ARCHIVE_RETRIEVAL_PRICE_PER_GB", "").strip()
    cost: float | None = None
    if price:
        try:
            cost = round(total_bytes / 1_000_000_000 * float(price), 4)
        except ValueError:
            cost = None
    return {
        "months": len(manifests),
        "files": total_files,
        "bytes": total_bytes,
        "retrieval_cost": cost,
        "retrieval_cost_note": (
            None
            if cost is not None
            else "no retrieval price is configured (AISOC_ARCHIVE_RETRIEVAL_PRICE_PER_GB); cost is unknown, not zero"
        ),
    }


async def load_rehydration(
    rehydration_id: uuid.UUID,
    tenant_id: uuid.UUID,
    manifests: list[dict[str, Any]],
    dest: Destination,
    *,
    connector_type: str | None = None,
) -> tuple[str, int]:
    """Load the covered months into the scratch table. Returns (table, rows).

    The table carries the lake's own schema (``AS raw_events``) so the
    explorer's column expectations hold, and the loader re-applies the
    tenant predicate on read — the object should only contain that
    tenant's rows, but trusting a bucket to enforce tenancy would make the
    bucket a tenancy boundary, which it is not.
    """
    table = rehydrated_table_name(rehydration_id)
    if not REHYDRATED_TABLE_RE.match(table):  # defence in depth; the name is ours
        raise ArchiveConfigError(f"internal: bad scratch table name {table!r}")
    await execute_lake_query(
        f"CREATE TABLE IF NOT EXISTS {table} AS aisoc.raw_events ENGINE = MergeTree ORDER BY (tenant_id, event_time)",
        timeout_seconds=60.0,
    )
    total = 0
    for manifest in manifests:
        for entry in manifest.get("files") or []:  # type: ignore[union-attr]
            key = str(entry["path"])  # type: ignore[index]
            # No WHERE on the s3 read: ClickHouse 23.8's Parquet pushdown
            # cannot compare the file's string-typed ids against the target
            # table's UUID hint in either direction (Code 169). The object
            # is tenant-pure by construction (exported under a tenant
            # predicate into a tenant-keyed path); the mutation below is
            # the belt-and-braces that refuses to TRUST that, because a
            # bucket is not a tenancy boundary.
            await execute_lake_query(  # nosemgrep — regex-pinned identifier; values are bound params
                f"INSERT INTO {table} SELECT * FROM s3(%(url)s, %(ak)s, %(sk)s, 'Parquet')",  # noqa: S608 — machine-derived, regex-pinned identifier # nosemgrep
                params={"url": dest.url(key), "ak": dest.access_key, "sk": dest.secret_key},
                timeout_seconds=600.0,
            )
    # Evict anything that is not this tenant's, and anything outside the
    # requested connector filter — after landing, where the columns carry
    # the table's own types and no pushdown is involved.
    await execute_lake_query(  # nosemgrep — regex-pinned identifier; values are bound params
        f"ALTER TABLE {table} DELETE WHERE tenant_id != toUUID(%(tenant_id)s)",  # noqa: S608 — machine-derived, regex-pinned identifier # nosemgrep
        params={"tenant_id": str(tenant_id)},
        extra_settings={"mutations_sync": 2},
        timeout_seconds=600.0,
    )
    if connector_type:
        await execute_lake_query(  # nosemgrep — regex-pinned identifier; values are bound params
            f"ALTER TABLE {table} DELETE WHERE connector_type != %(connector_type)s",  # noqa: S608 — machine-derived, regex-pinned identifier # nosemgrep
            params={"connector_type": connector_type},
            extra_settings={"mutations_sync": 2},
            timeout_seconds=600.0,
        )
    count = await execute_lake_query(  # nosemgrep — regex-pinned identifier; values are bound params
        f"SELECT count() FROM {table}",  # noqa: S608 — regex-pinned scratch table # nosemgrep
        timeout_seconds=60.0,
    )
    total = int(count.rows[0][0]) if count.rows else 0
    return table, total


async def drop_rehydration_table(table: str) -> None:
    if not REHYDRATED_TABLE_RE.match(table):
        raise ArchiveConfigError(f"refusing to drop non-scratch table {table!r}")
    await execute_lake_query(f"DROP TABLE IF EXISTS {table}", timeout_seconds=60.0)


# ---------------------------------------------------------------------------
# Attestation (scoped-holds reporting half)
# ---------------------------------------------------------------------------

_ATTESTATION_HOLDS_SQL = text(
    """
    SELECT id, subject_kind, subject_value, covers_from, covers_until, matter_ref
    FROM legal_holds
    WHERE tenant_id = :tenant_id AND released_at IS NULL
    ORDER BY placed_at
    """
)

_ATTESTATION_PARTITIONS_SQL = text(
    """
    SELECT month, status, manifest->>'row_count' AS rows, verified_at
    FROM lake_archive_partitions
    WHERE tenant_id = :tenant_id
    ORDER BY month
    """
)


async def retention_attestation(db: AsyncSession, tenant_id: uuid.UUID, *, lake_days: int, worm_declared: bool) -> dict[str, Any]:
    """What is retained per tier, oldest row per tier, manifests verified,
    holds active — each figure from its own store, 'not measured' where a
    store cannot answer."""
    lake_oldest: str | None = None
    lake_note: str | None = None
    try:
        result = await execute_lake_query(
            "SELECT min(event_time) FROM aisoc.raw_events WHERE tenant_id = %(tenant_id)s",
            params={"tenant_id": str(tenant_id)},
        )
        lake_oldest = str(result.rows[0][0]) if result.rows and result.rows[0][0] else None
    except Exception as exc:  # noqa: BLE001 — an unreachable lake is unknown, not empty
        lake_note = f"lake unreachable ({type(exc).__name__}): oldest row not measured"

    partitions = (await db.execute(_ATTESTATION_PARTITIONS_SQL, {"tenant_id": str(tenant_id)})).fetchall()
    holds = (await db.execute(_ATTESTATION_HOLDS_SQL, {"tenant_id": str(tenant_id)})).fetchall()
    verified = [p for p in partitions if p[1] == "verified"]
    return {
        "hot_and_lake": {
            "window_days": lake_days,
            "oldest_row": lake_oldest,
            "note": lake_note,
        },
        "archive": {
            "partitions": len(partitions),
            "verified": len(verified),
            "oldest_month": str(partitions[0][0]) if partitions else None,
            "newest_month": str(partitions[-1][0]) if partitions else None,
            "worm": "declared by operator, not verified by this service" if worm_declared else "not declared",
        },
        "legal_holds": [
            {
                "id": str(h[0]),
                "subject_kind": h[1],
                "subject_value": h[2],
                "covers_from": str(h[3]) if h[3] else None,
                "covers_until": str(h[4]) if h[4] else None,
                "matter_ref": h[5],
                "narrows_purge": h[1] in ("user", "host", "ip"),
            }
            for h in holds
        ],
        "generated_at": datetime.now(UTC).isoformat(),
    }


def rehydration_expiry(days: int = 7) -> datetime:
    return datetime.now(UTC) + timedelta(days=max(1, min(days, 30)))
