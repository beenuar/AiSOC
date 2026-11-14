"""Persist the provenance of a hunt drafted from a third-party report.

Migration 155 created ``hunt_source_reports`` and stated the property its
``approved_at`` column exists for: *"Nothing is hunted from a report until
this is set, so NULL must never be rendered as approved."* The producing
route computed exactly the table's columns and returned them in the HTTP
response **without persisting anything**, so the table was a pure orphan:
``approved_at`` and ``approved_by`` had no writer, there was no approve
endpoint, and the property was enforced by nobody.

The in-process half of the claim did hold — the route returns a draft and
runs no hunt — but that is a property of one function rather than a durable
gate, and it answers neither question an analyst asks six weeks later: which
report produced this indicator, and has anybody reviewed it.

Deliberately not stored: the report body. Three reasons in the migration's
own order — it is third-party prose, it is untrusted text whose only safe
handling is a fenced prompt channel, and the digest answers "is this the same
document I reviewed?" without keeping the document.

Fail-soft on the *write*, because a provenance record that cannot be stored
must not cost an analyst their draft; the draft is still returned and says
that its provenance was not recorded. Fail-**closed** on the approval read,
for the opposite reason: an unreadable approval state is not an approval.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_INSERT = """
    INSERT INTO hunt_source_reports (
        tenant_id, url, fetched_by, byte_size, content_sha256,
        truncated, indicator_count, technique_count
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING id::text
"""

_APPROVE = """
    UPDATE hunt_source_reports
       SET approved_at = NOW(), approved_by = $3
     WHERE tenant_id = $1 AND id = $2 AND approved_at IS NULL
    RETURNING id::text
"""

_SELECT_ONE = """
    SELECT id::text AS id, url, fetched_at, byte_size, content_sha256, truncated,
           indicator_count, technique_count, approved_at, approved_by
      FROM hunt_source_reports
     WHERE tenant_id = $1 AND id = $2
"""

_SELECT_FOR_TENANT = """
    SELECT id::text AS id, url, fetched_at, byte_size, content_sha256, truncated,
           indicator_count, technique_count, approved_at, approved_by
      FROM hunt_source_reports
     WHERE tenant_id = $1
     ORDER BY fetched_at DESC
     LIMIT $2
"""


def resolve_dsn() -> str | None:
    dsn = (os.environ.get("DATABASE_DSN") or os.environ.get("DATABASE_URL") or "").strip()
    if not dsn:
        return None
    return dsn.replace("postgresql+asyncpg://", "postgresql://")


async def _connect(dsn: str, tenant_id: str):  # noqa: ANN202
    import asyncpg  # noqa: PLC0415 — optional at import time

    conn = await asyncpg.connect(dsn, timeout=5.0)
    # Bind the tenant so migration 155's RLS applies to this statement. The
    # policy carries an `OR current_tenant_id() IS NULL` arm for the hunting
    # worker, which means an unbound session reads tenant-wide — the
    # fail-open shape this repository has shipped before.
    #
    # The setting is `app.current_tenant_id`, which is what
    # `current_tenant_id()` reads. `aisoc.tenant_id` is a name no policy
    # consults, and binding it would leave every statement here passing on
    # that permissive arm while looking scoped.
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", tenant_id)
    return conn


async def record_report(
    *,
    tenant_id: str,
    url: str,
    fetched_by: str | None,
    byte_size: int,
    content_sha256: str,
    truncated: bool,
    indicator_count: int,
    technique_count: int,
) -> str | None:
    """Store one draft's provenance. Returns its id, or None if not stored.

    ``None`` is a real answer and the caller renders it: a draft whose
    provenance was not recorded is still a usable draft, and saying so is
    better than implying a record exists.
    """
    dsn = resolve_dsn()
    if dsn is None:
        return None
    try:
        conn = await _connect(dsn, tenant_id)
        try:
            return str(
                await conn.fetchval(
                    _INSERT,
                    uuid.UUID(tenant_id),
                    url,
                    uuid.UUID(fetched_by) if fetched_by else None,
                    byte_size,
                    content_sha256,
                    truncated,
                    indicator_count,
                    technique_count,
                )
            )
        finally:
            await conn.close()
    except Exception as exc:  # noqa: BLE001 — a provenance write must not cost the draft
        logger.warning("hunt_source_report.record_failed", url=url, error=str(exc))
        return None


async def approve_report(*, tenant_id: str, report_id: str, approved_by: str | None) -> bool:
    """Mark a drafted report reviewed. False when there was nothing to mark.

    The ``approved_at IS NULL`` predicate makes this idempotent in the only
    direction that matters: a second approval does not move the timestamp, so
    the recorded review is the first one, which is the one that happened.
    Raises on a read failure rather than returning False, because "could not
    tell" and "not approved" must not share an answer on the write side.
    """
    dsn = resolve_dsn()
    if dsn is None:
        raise RuntimeError("no database is configured, so an approval cannot be recorded")
    conn = await _connect(dsn, tenant_id)
    try:
        row = await conn.fetchval(_APPROVE, uuid.UUID(tenant_id), uuid.UUID(report_id), uuid.UUID(approved_by) if approved_by else None)
        return row is not None
    finally:
        await conn.close()


async def get_report(*, tenant_id: str, report_id: str) -> dict[str, Any] | None:
    dsn = resolve_dsn()
    if dsn is None:
        return None
    conn = await _connect(dsn, tenant_id)
    try:
        row = await conn.fetchrow(_SELECT_ONE, uuid.UUID(tenant_id), uuid.UUID(report_id))
        return dict(row) if row is not None else None
    finally:
        await conn.close()


async def list_reports(*, tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
    dsn = resolve_dsn()
    if dsn is None:
        return []
    conn = await _connect(dsn, tenant_id)
    try:
        rows = await conn.fetch(_SELECT_FOR_TENANT, uuid.UUID(tenant_id), max(1, min(limit, 200)))
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def is_approved(*, tenant_id: str, report_id: str) -> bool:
    """Whether a person signed off this report's extracted indicators.

    **Fail-closed**: an unreadable approval state is not an approval. The
    migration says nothing is hunted from a report until ``approved_at`` is
    set, and a read failure answering "yes" would be the silent inversion of
    exactly that sentence.
    """
    report = await get_report(tenant_id=tenant_id, report_id=report_id)
    if report is None:
        return False
    return report.get("approved_at") is not None
