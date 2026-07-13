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


@runtime_checkable
class TimerStore(Protocol):
    async def put(self, record: TimerRecord) -> None: ...
    async def delete(self, action_id: str) -> None: ...
    async def list_pending(self) -> list[TimerRecord]: ...


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


_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS approval_timers (
    action_id     TEXT PRIMARY KEY,
    fire_at       DOUBLE PRECISION NOT NULL,
    safe_default  TEXT NOT NULL DEFAULT 'rejected',
    case_id       TEXT NOT NULL DEFAULT '',
    channel       TEXT,
    approver_id   TEXT NOT NULL DEFAULT 'scheduler',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


class PostgresTimerStore:  # pragma: no cover — thin asyncpg wrapper, exercised by the live service
    """asyncpg-backed durable store. Fail-soft: DB errors are logged, not raised."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    @classmethod
    async def create(cls, dsn: str) -> PostgresTimerStore:
        import asyncpg  # noqa: PLC0415

        pool = await asyncpg.create_pool(dsn.replace("postgresql+asyncpg://", "postgresql://", 1), min_size=1, max_size=2)
        async with pool.acquire() as conn:
            await conn.execute(_CREATE_SQL)
        return cls(pool)

    async def put(self, record: TimerRecord) -> None:
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO approval_timers (action_id, fire_at, safe_default, case_id, channel, approver_id)
                       VALUES ($1,$2,$3,$4,$5,$6)
                       ON CONFLICT (action_id) DO UPDATE SET fire_at=$2, safe_default=$3""",
                    record.action_id,
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
                await conn.execute("DELETE FROM approval_timers WHERE action_id=$1", action_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("timer_store.delete_failed", action_id=action_id, error=str(exc))

    async def list_pending(self) -> list[TimerRecord]:
        try:
            async with self._pool.acquire() as conn:
                rows = await conn.fetch("SELECT action_id, fire_at, safe_default, case_id, channel, approver_id FROM approval_timers")
            return [
                TimerRecord(
                    action_id=r["action_id"],
                    fire_at_epoch=r["fire_at"],
                    safe_default=r["safe_default"],
                    case_id=r["case_id"],
                    channel=r["channel"],
                    approver_id=r["approver_id"],
                )
                for r in rows
            ]
        except Exception as exc:  # noqa: BLE001
            log.warning("timer_store.list_failed", error=str(exc))
            return []
