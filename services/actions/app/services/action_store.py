"""Where a pending action lives between submission and approval.

It lived in a module-global dict:

    # In-memory action store (replace with DB in production)
    _actions: dict[str, dict[str, Any]] = {}

Which means a restart lost every action awaiting approval, and a second
replica could not see the first one's. Both matter more here than for most
caches, because the thing being lost is a *pending containment*: an analyst
receives a Slack card, the pod is rescheduled, and the approve button returns
"Action not found" for an incident that is still live. There is no retry for
that — the agent already decided, and the record of what it wanted is gone.

Postgres when a DSN is configured, the in-memory dict when not. The fallback
is not a compromise: the unit suite has no database, and a store that cannot
run without one would push every test onto a mock of itself.

Writes are upserts on the action id, so a replay of the same submission is
idempotent rather than a duplicate pending approval.
"""

from __future__ import annotations

import json
import os
from typing import Any

import structlog

logger = structlog.get_logger()

#: Process-local fallback, and the store the unit suite exercises.
_MEMORY: dict[str, dict[str, Any]] = {}

#: Set once a write has actually reached Postgres.
#:
#: This existed as a flag nothing read, which made the comment above it a
#: description of behaviour that did not happen. The property is worth having:
#: a store that worked and then stopped must not quietly revert to per-replica
#: memory, because that is the same "approve returns Action not found" failure
#: arriving by a different route — and it would arrive without a log line.
_DB_CONFIRMED = False


def _dsn() -> str | None:
    """An asyncpg-compatible DSN, or None when no database is configured.

    Accepts the SQLAlchemy spelling the API uses and the plain pgx spelling
    ``services/ingest`` uses, because both are present in deployed
    environments. Same resolution as ``tenant_policy._dsn``.
    """
    raw = (os.environ.get("DATABASE_DSN") or os.environ.get("DATABASE_URL") or "").strip()
    if not raw:
        return None
    return raw.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def _connect(dsn: str):
    import asyncpg  # noqa: PLC0415 — optional at import time; only needed with a DSN

    return await asyncpg.connect(dsn, timeout=5.0)


async def save(record: dict[str, Any]) -> None:
    """Persist or update an action record."""
    action_id = str(record["id"])
    _MEMORY[action_id] = record

    dsn = _dsn()
    if dsn is None:
        return
    try:
        conn = await _connect(dsn)
    except Exception as exc:  # noqa: BLE001 — an unreachable store must not drop the action
        _report_degraded("connect_failed", action_id, exc)
        return
    try:
        await conn.execute(
            """
            INSERT INTO aisoc_action_records (id, tenant_id, status, record, created_at, updated_at)
            VALUES ($1, $2, $3, $4, now(), now())
            ON CONFLICT (id) DO UPDATE
                SET status = EXCLUDED.status,
                    record = EXCLUDED.record,
                    updated_at = now()
            """,
            action_id,
            str(record.get("tenant_id") or ""),
            str(record.get("status") or ""),
            json.dumps(record, default=str),
        )
        global _DB_CONFIRMED
        _DB_CONFIRMED = True
    except Exception as exc:  # noqa: BLE001 — see above
        _report_degraded("write_failed", action_id, exc)
    finally:
        await conn.close()


def _report_degraded(event: str, action_id: str, exc: Exception) -> None:
    """Log a store failure at the severity its consequence deserves.

    Before the first successful write this is a warning: a deployment with no
    database is a supported configuration and says so at boot. *After* one,
    the same failure means a store that was working has stopped, and every
    pending approval from here on is invisible to any other replica — so it
    is an error, and it says which of the two it is.
    """
    logger.log(
        "error" if _DB_CONFIRMED else "warning",
        f"action_store.{event}",
        action_id=action_id,
        error=str(exc),
        previously_durable=_DB_CONFIRMED,
        consequence=(
            "the durable store was working and has stopped; pending actions are now per-replica"
            if _DB_CONFIRMED
            else "no durable store configured or reachable; pending actions are per-replica"
        ),
    )


async def get(action_id: str) -> dict[str, Any] | None:
    """Fetch an action record, preferring the durable copy.

    The in-memory copy is checked first only as a cache: on the replica that
    handled the submission it is the same object, and on any other replica it
    is absent and the database answers.
    """
    cached = _MEMORY.get(action_id)
    if cached is not None:
        return cached

    dsn = _dsn()
    if dsn is None:
        return None
    try:
        conn = await _connect(dsn)
    except Exception as exc:  # noqa: BLE001
        logger.warning("action_store.connect_failed", action_id=action_id, error=str(exc))
        return None
    try:
        row = await conn.fetchrow("SELECT record FROM aisoc_action_records WHERE id = $1", action_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("action_store.read_failed", action_id=action_id, error=str(exc))
        return None
    finally:
        await conn.close()

    if row is None:
        return None
    record = json.loads(row["record"])
    # Cache it so the approve path's subsequent mutation and save see one
    # object rather than two diverging copies.
    _MEMORY[action_id] = record
    return record


def clear() -> None:
    """Drop the in-memory copy. Used by tests."""
    _MEMORY.clear()
