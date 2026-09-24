"""Durable backing store for approval-SLA timers (Phase B3).

The :class:`~app.services.approval_timeout.ApprovalTimeoutScheduler` was
in-memory only: a bot restart wiped every pending "auto-reject in N minutes"
timer, so a forgotten approval posted just before a deploy could sit in
``awaiting_approval`` forever — the safe-default fallback silently never fired.

This module adds an optional persistence layer. On ``schedule`` the scheduler
writes a :class:`TimerRecord` (action_id, fire-at wall-clock, safe default,
case/channel/approver); on cancel or fire it deletes the row; on startup
``recover()`` reads the surviving rows and re-arms a timer for each, firing an
overdue one immediately. Persistence is **best-effort and fail-soft** — a DB
outage degrades to today's in-memory behaviour, never blocks an approval.

Two implementations:

* :class:`InMemoryTimerStore` — the default; keeps the current (non-durable)
  semantics and is what the unit tests drive.
* :class:`PostgresTimerStore` — asyncpg-backed durable store for production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import structlog

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class TimerRecord:
    action_id: str
    fire_at_epoch: float  # absolute wall-clock deadline (time.time() based)
    safe_default: str  # "rejected" | "approved"
    case_id: str = ""
    channel: str | None = None
    approver_id: str = "scheduler"
    #: The tenant the action belongs to. v1 maps one Slack workspace to one
    #: AiSOC tenant, so it comes from ``AISOC_DEFAULT_TENANT_ID`` rather than
    #: from the card — but it is carried on the record, not assumed by the
    #: store, because the row is what a policy filters on and a timer decides
    #: whether a containment auto-rejects.
    tenant_id: str = ""


@runtime_checkable
class TimerStore(Protocol):
    """Durable store for pending approval timers."""

    async def put(self, record: TimerRecord) -> None:
        """Persist (or overwrite) a pending timer record."""

    async def delete(self, action_id: str) -> None:
        """Remove the timer record for ``action_id`` if present."""

    async def list_pending(self) -> list[TimerRecord]:
        """Return all currently pending timer records."""


class InMemoryTimerStore:
    """Non-durable default — restarts wipe timers (the pre-B3 behaviour)."""

    def __init__(self) -> None:
        self._rows: dict[str, TimerRecord] = {}

    async def put(self, record: TimerRecord) -> None:
        self._rows[record.action_id] = record

    async def delete(self, action_id: str) -> None:
        self._rows.pop(action_id, None)

    async def list_pending(self) -> list[TimerRecord]:
        return list(self._rows.values())


class MissingApprovalTimersTable(RuntimeError):
    """``approval_timers`` is absent, and this store will not create it."""


class PostgresTimerStore:
    """asyncpg-backed durable store. Fail-soft: DB errors are logged, not raised.

    Two properties this class deliberately does **not** have any more.

    It does not create its own table. ``approval_timers`` lives in
    ``services/api/migrations/062_approval_timers.sql``; before that it existed
    in no migration anywhere, so it had no row-level-security policy while
    every other tenant-scoped table in the schema did — on a table that decides
    whether a pending containment auto-rejects. Runtime DDL is also how the
    store would have broken silently: ``061_runtime_app_role.sql`` takes
    ``CREATE`` on schema public away from the runtime role, Postgres checks the
    schema ACL *before* the existence test, and ``main.py`` turns the resulting
    error into a warning and falls back to the non-durable store. A probe that
    says "apply the migration" is a failure somebody can act on.

    It does not read rows it cannot attribute. Every statement carries
    ``tenant_id``, so the store does not depend on the policy alone — and each
    connection binds ``app.current_tenant_id`` so the policy engages as well.
    One control in the query, one in the database.
    """

    def __init__(self, pool: Any, tenant_id: str) -> None:
        self._pool = pool
        self._tenant_id = tenant_id

    @classmethod
    async def create(cls, dsn: str, tenant_id: str) -> PostgresTimerStore:
        import asyncpg  # noqa: PLC0415

        async def _bind_tenant(conn: Any) -> None:
            # Not SET LOCAL: there is no surrounding transaction, and the
            # binding is meant to last for the pooled connection. The pool is
            # this process's and this process serves one tenant.
            await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_id)

        pool = await asyncpg.create_pool(
            dsn.replace("postgresql+asyncpg://", "postgresql://", 1),
            min_size=1,
            max_size=2,
            init=_bind_tenant,
        )
        async with pool.acquire() as conn:
            present = await conn.fetchval("SELECT to_regclass('public.approval_timers')")
        if present is None:
            await pool.close()
            raise MissingApprovalTimersTable(
                "approval_timers does not exist. Apply the API migration chain "
                "(062_approval_timers.sql) with the owner credential; this service holds DML only "
                "and will not create the table at runtime."
            )
        return cls(pool, tenant_id)

    async def put(self, record: TimerRecord) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO approval_timers
                           (action_id, tenant_id, fire_at, safe_default, case_id, channel, approver_id)
                       VALUES ($1,$2,$3,$4,$5,$6,$7)
                       ON CONFLICT (action_id) DO UPDATE SET fire_at=$3, safe_default=$4
                        WHERE approval_timers.tenant_id = $2""",
                    record.action_id,
                    record.tenant_id or self._tenant_id,
                    record.fire_at_epoch,
                    record.safe_default,
                    record.case_id,
                    record.channel,
                    record.approver_id,
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("timer_store.put_failed", action_id=record.action_id, error=str(exc))

    async def delete(self, action_id: str) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM approval_timers WHERE action_id=$1 AND tenant_id=$2",
                    action_id,
                    self._tenant_id,
                )
        except Exception as exc:  # noqa: BLE001
            log.warning("timer_store.delete_failed", action_id=action_id, error=str(exc))

    async def list_pending(self) -> list[TimerRecord]:
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(
                    """SELECT action_id, tenant_id, fire_at, safe_default, case_id, channel, approver_id
                         FROM approval_timers
                        WHERE tenant_id = $1""",
                    self._tenant_id,
                )
            return [
                TimerRecord(
                    action_id=r["action_id"],
                    fire_at_epoch=r["fire_at"],
                    safe_default=r["safe_default"],
                    case_id=r["case_id"],
                    channel=r["channel"],
                    approver_id=r["approver_id"],
                    tenant_id=r["tenant_id"],
                )
                for r in rows
            ]
        except Exception as exc:  # noqa: BLE001
            log.warning("timer_store.list_failed", error=str(exc))
            return []
