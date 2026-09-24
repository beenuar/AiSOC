"""Converge a table this service needs, without needing DDL rights to do it.

Two stores in this service — the per-run cost ledger and institutional memory —
opened their pool with ``CREATE TABLE IF NOT EXISTS`` and swallowed any failure
into ``logger.debug``. Both tables are already in the API migration chain
(``020_soc_metrics_h2.sql`` and ``022_institutional_memory.sql``), so the DDL
was belt-and-braces on every real deployment.

It stopped being harmless when the services moved onto a non-superuser runtime
role (``services/api/migrations/061_runtime_app_role.sql``). Postgres checks
schema ACL *before* the existence test, so ``CREATE TABLE IF NOT EXISTS`` on a
table that already exists still raises::

    ERROR:  permission denied for schema public

Measured against ``postgres:16``, not inferred. With the failure landing in a
``debug`` log and the caller returning ``None``, the observable result would
have been the agents service quietly recording no cost telemetry and no
institutional memory at all — a worker that silently stops, which is the
failure this whole change is meant not to trade the bypass for.

So: look before leaping. If the table is there, nothing is attempted and no
privilege is required. If it is genuinely absent the DDL still runs, and a
failure is reported at ``error`` with the reason spelled out, because at that
point the deployment really is missing a migration.
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


async def ensure_table(conn: Any, table: str, ddl: str) -> bool:
    """Make sure ``table`` exists, creating it only if it does not.

    Returns ``True`` when the table is usable afterwards. Never raises: the
    callers treat an unusable store as "fall back to in-memory", and turning
    that into a crash would take the agent down over telemetry. The difference
    from the previous behaviour is that an unusable store is now *loud*.
    """
    try:
        present = await conn.fetchval("SELECT to_regclass($1)", f"public.{table}")
    except Exception as exc:  # noqa: BLE001 — a dead connection is the caller's problem
        logger.error("schema_bootstrap.probe_failed", table=table, error=str(exc))
        return False

    if present is not None:
        return True

    try:
        await conn.execute(ddl)
    except Exception as exc:  # noqa: BLE001 — reported, not swallowed
        logger.error(
            "schema_bootstrap.create_failed",
            table=table,
            error=str(exc),
            hint=(
                f"{table} is absent and this role cannot create it. The runtime role holds DML only "
                "by design; apply the API migration chain as the owner role (DATABASE_MIGRATION_URL) "
                "instead of relying on this bootstrap."
            ),
        )
        return False
    return True
