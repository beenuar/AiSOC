"""Suspend a playbook run at an approval step, and resume it on the decision.

Parity plan 5.2.

What was wrong
--------------
The engine is a single-threaded index walk with no pause and no resume, so
an `approval` step had nothing to suspend. It failed closed, which was the
right interim behaviour: before that it returned `{"skipped": true}` while
reporting SUCCESS, so a run continued straight into the very action a human
was supposed to authorise. But failing closed means **12 shipped playbooks
abort at their approval step**, which is not an approval mechanism either.

Three properties the plan requires, and what each costs
--------------------------------------------------------
* **Resumes from `/approvals/{id}/decide`.** The route already exists and
  already persists to `agent_approvals`; what was missing is anything on
  the engine side to wake.
* **Survives restarts.** So the position and the context go to Postgres,
  not to a process. An in-memory pause is lost by exactly the thing most
  likely to interrupt a long-running approval.
* **Expires with a recorded outcome.** `expired` is a decision, not an
  absence of one. A pause with no expiry is a run that hangs forever and
  an operator who never learns it did.

What a resumed run must not do
------------------------------
Re-run the approval step. The stored index is the step *itself* and resume
advances past it, so a replayed decision (a double-tap in the responder
app, a retried webhook) continues rather than pausing again.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

logger = structlog.get_logger()

#: How long an approval waits before it expires with a recorded outcome.
#: Long enough to cross a weekend, short enough that a forgotten request
#: does not sit open for a quarter.
DEFAULT_TTL_HOURS = float(os.getenv("AISOC_PLAYBOOK_APPROVAL_TTL_HOURS", "72"))


@dataclass(frozen=True)
class Pause:
    """A suspended run, as stored."""

    id: str
    run_id: str
    playbook_id: str
    step_index: int
    step_id: str
    run_context: dict[str, Any]
    step_results: list[dict[str, Any]]
    approval_id: str | None
    expires_at: datetime

    @property
    def resume_index(self) -> int:
        """Where the resumed run starts.

        One **past** the approval step. Storing the step itself and
        advancing here means a replayed decision continues the run rather
        than pausing on the same step again, which a double-tap in the
        responder app would otherwise do.
        """
        return self.step_index + 1


async def _pool() -> Any | None:
    from app.memory.institutional import _get_pool

    try:
        return await _get_pool()
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause.pool_unavailable", error=str(exc))
        return None


async def suspend(
    *,
    tenant_id: str,
    run_id: str,
    playbook_id: str,
    playbook_name: str,
    step_index: int,
    step_id: str,
    run_context: dict[str, Any],
    step_results: list[dict[str, Any]],
    approval_id: str | None = None,
    ttl_hours: float | None = None,
) -> Pause | None:
    """Record where this run stopped. None when it could not be stored.

    Returning None rather than raising, and the caller treats that as a
    failed step: a pause that was not written is a run nothing can resume,
    and continuing past the approval step would be the original defect
    (running the action a human was meant to authorise).
    """
    pool = await _pool()
    if pool is None:
        logger.warning("playbook_pause.no_database", run_id=run_id)
        return None

    pause_id = str(uuid.uuid4())
    expires_at = datetime.now(UTC) + timedelta(hours=ttl_hours or DEFAULT_TTL_HOURS)
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO aisoc_playbook_pauses
                    (id, tenant_id, run_id, playbook_id, playbook_name, step_index,
                     step_id, run_context, step_results, approval_id, expires_at)
                VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb,
                        $10::uuid, $11)
                """,
                pause_id,
                tenant_id,
                run_id,
                playbook_id,
                playbook_name,
                step_index,
                step_id,
                json.dumps(run_context, default=str),
                json.dumps(step_results, default=str),
                approval_id,
                expires_at,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause.write_failed", run_id=run_id, error=str(exc))
        return None

    logger.info(
        "playbook_pause.suspended",
        run_id=run_id,
        step_id=step_id,
        approval_id=approval_id,
        expires_at=expires_at.isoformat(),
    )
    return Pause(
        id=pause_id,
        run_id=run_id,
        playbook_id=playbook_id,
        step_index=step_index,
        step_id=step_id,
        run_context=run_context,
        step_results=step_results,
        approval_id=approval_id,
        expires_at=expires_at,
    )


async def find_waiting(*, approval_id: str) -> Pause | None:
    """The run waiting on this approval, if any."""
    pool = await _pool()
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, run_id, playbook_id, step_index, step_id,
                       run_context, step_results, approval_id, expires_at
                  FROM aisoc_playbook_pauses
                 WHERE approval_id = $1::uuid AND status = 'waiting'
                 LIMIT 1
                """,
                approval_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause.lookup_failed", approval_id=approval_id, error=str(exc))
        return None
    if row is None:
        return None
    return _row_to_pause(row)


def _row_to_pause(row: Any) -> Pause:
    def _json(value: Any, default: Any) -> Any:
        if value is None:
            return default
        if isinstance(value, str):
            try:
                return json.loads(value)
            except ValueError:
                return default
        return value

    return Pause(
        id=str(row["id"]),
        run_id=row["run_id"],
        playbook_id=row["playbook_id"],
        step_index=int(row["step_index"]),
        step_id=row["step_id"],
        run_context=_json(row["run_context"], {}),
        step_results=_json(row["step_results"], []),
        approval_id=str(row["approval_id"]) if row["approval_id"] else None,
        expires_at=row["expires_at"],
    )


async def resolve(*, pause_id: str, status: str, resolution: str) -> bool:
    """Mark a pause resumed, denied, expired or cancelled.

    The status is set **before** the run continues, so a decision that
    arrives twice cannot resume the same run twice: the second update
    matches no `waiting` row.
    """
    if status not in {"resumed", "denied", "expired", "cancelled"}:
        raise ValueError(f"unknown pause resolution {status!r}")
    pool = await _pool()
    if pool is None:
        return False
    try:
        async with pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE aisoc_playbook_pauses
                   SET status = $2, resolved_at = NOW(), resolution = $3
                 WHERE id = $1::uuid AND status = 'waiting'
                """,
                pause_id,
                status,
                resolution[:500],
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause.resolve_failed", pause_id=pause_id, error=str(exc))
        return False
    # asyncpg returns "UPDATE <n>"; zero means somebody else resolved it
    # first, which is the double-decision case and is not an error.
    changed = str(result).rsplit(" ", 1)[-1] != "0"
    if not changed:
        logger.info("playbook_pause.already_resolved", pause_id=pause_id)
    return changed


async def expire_due(*, now: datetime | None = None) -> list[str]:
    """Expire every pause past its deadline. Returns the run ids.

    Run from the scheduler. An expiry that nothing sweeps is a status
    column that never changes, which looks identical to a pause still
    legitimately waiting.
    """
    pool = await _pool()
    if pool is None:
        return []
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                UPDATE aisoc_playbook_pauses
                   SET status = 'expired',
                       resolved_at = NOW(),
                       resolution = 'no decision before the approval deadline'
                 WHERE status = 'waiting' AND expires_at <= $1
             RETURNING run_id
                """,
                now or datetime.now(UTC),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause.expiry_sweep_failed", error=str(exc))
        return []
    run_ids = [r["run_id"] for r in rows]
    if run_ids:
        # Info, not debug. An expired approval means an action a human was
        # asked to authorise did not happen, and nobody decided that.
        logger.info("playbook_pause.expired", count=len(run_ids), run_ids=run_ids[:10])
    return run_ids
