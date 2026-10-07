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
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

# The stdlib logger, not structlog. `app.playbook.engine` imports this
# module and two gates import the engine with only httpx and pydantic
# installed: `validate_playbooks.py` and the schema-parity check. Pulling
# structlog into that chain made both fail with ModuleNotFoundError, which
# is a dependency this file does not need.
logger = logging.getLogger("aisoc.playbook.pause")

#: How long an approval waits before it expires with a recorded outcome.
#: Long enough to cross a weekend, short enough that a forgotten request
#: does not sit open for a quarter.
DEFAULT_TTL_HOURS = float(os.getenv("AISOC_PLAYBOOK_APPROVAL_TTL_HOURS", "72"))


#: How long a `wait` pause may sit before it expires with a recorded
#: outcome. Longer than an approval's because a wait is often deliberate
#: ("re-check in six hours"), and short enough that a callback nobody ever
#: fires does not leave a run open forever.
DEFAULT_WAIT_TTL_HOURS = float(os.getenv("AISOC_PLAYBOOK_WAIT_TTL_HOURS", "168"))


@dataclass(frozen=True)
class Pause:
    """A suspended run, as stored."""

    id: str
    tenant_id: str
    run_id: str
    playbook_id: str
    step_index: int
    step_id: str
    run_context: dict[str, Any]
    step_results: list[dict[str, Any]]
    approval_id: str | None
    expires_at: datetime
    #: ``approval`` (waiting on a person) or ``wait`` (a clock or a
    #: callback). Defaults to ``approval`` for the same reason the column
    #: does: every row that predates migration 096 is one, and the other
    #: default would have the sweeper resume live approvals with no
    #: decision.
    kind: str = "approval"
    #: When a timer wait becomes due. ``None`` for an approval and for a
    #: callback wait, which means "not on a clock", not "due now".
    resume_at: datetime | None = None
    #: The handle a callback presents. Never the row id: the id appears in
    #: run records an analyst can read, and a callback is unauthenticated
    #: by construction.
    resume_token: str | None = None

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
        logger.warning("playbook_pause: pool unavailable: %s", exc)
        return None


async def suspend(
    *,
    kind: str = "approval",
    resume_at: datetime | None = None,
    resume_token: str | None = None,
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
        logger.warning("playbook_pause: no database; run %s cannot be suspended", run_id)
        return None

    pause_id = str(uuid.uuid4())
    expires_at = datetime.now(UTC) + timedelta(hours=ttl_hours or DEFAULT_TTL_HOURS)
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO aisoc_playbook_pauses
                    (id, tenant_id, run_id, playbook_id, playbook_name, step_index,
                     step_id, run_context, step_results, approval_id, expires_at,
                     kind, resume_at, resume_token)
                VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb,
                        $10::uuid, $11, $12, $13, $14)
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
                kind,
                resume_at,
                resume_token,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause: write failed for run %s: %s", run_id, exc)
        return None

    logger.info(
        "playbook_pause: run %s suspended at step %s on approval %s, expires %s",
        run_id,
        step_id,
        approval_id,
        expires_at.isoformat(),
    )
    return Pause(
        id=pause_id,
        tenant_id=tenant_id,
        run_id=run_id,
        playbook_id=playbook_id,
        step_index=step_index,
        step_id=step_id,
        run_context=run_context,
        step_results=step_results,
        approval_id=approval_id,
        expires_at=expires_at,
        kind=kind,
        resume_at=resume_at,
        resume_token=resume_token,
    )


async def find_waiting(*, approval_id: str, tenant_id: str) -> Pause | None:
    """The run waiting on this approval, if any.

    Scoped on the tenant as well as the approval. The approval id is an
    unguessable UUID, which is an argument for it being hard to reach the
    wrong row and not an argument for being allowed to: resuming another
    tenant's playbook run is the kind of thing that should take two
    mistakes, not one.
    """
    pool = await _pool()
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, tenant_id, run_id, playbook_id, step_index, step_id,
                       run_context, step_results, approval_id, expires_at
                  FROM aisoc_playbook_pauses
                 WHERE approval_id = $1::uuid
                   AND tenant_id = $2::uuid
                   AND status = 'waiting'
                 LIMIT 1
                """,
                approval_id,
                tenant_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause: lookup failed for approval %s: %s", approval_id, exc)
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

    # `.get` rather than subscripting: `find_waiting` predates migration
    # 096 and does not select the three new columns, and a KeyError there
    # would turn an approval resume into a crash.
    def _column(name: str) -> Any:
        try:
            return row[name]
        except (KeyError, IndexError):
            return None

    return Pause(
        id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        run_id=row["run_id"],
        playbook_id=row["playbook_id"],
        step_index=int(row["step_index"]),
        step_id=row["step_id"],
        run_context=_json(row["run_context"], {}),
        step_results=_json(row["step_results"], []),
        approval_id=str(row["approval_id"]) if row["approval_id"] else None,
        expires_at=row["expires_at"],
        kind=str(_column("kind") or "approval"),
        resume_at=_column("resume_at"),
        resume_token=_column("resume_token"),
    )


#: The columns a wait lookup needs. Named rather than ``SELECT *`` so an
#: added column cannot change what a row means to ``_row_to_pause``.
_PAUSE_COLUMNS = (
    "id, tenant_id, run_id, playbook_id, step_index, step_id, run_context, "
    "step_results, approval_id, expires_at, kind, resume_at, resume_token"
)


async def find_wait_by_token(*, resume_token: str) -> Pause | None:
    """The run waiting on this callback token, if any.

    Not scoped on the tenant, and that is deliberate rather than an
    oversight: a callback is unauthenticated by construction, so the caller
    has no tenant to present. The token is the whole credential, which is
    why it is minted separately from the row id (the id appears in run
    records an analyst can read) and is never returned to anything outside
    this service. ``kind = 'wait'`` is in the predicate so an approval can
    never be resumed this way even if a token were somehow written onto one.
    """
    pool = await _pool()
    if pool is None:
        return None
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""
                SELECT {_PAUSE_COLUMNS}
                  FROM aisoc_playbook_pauses
                 WHERE resume_token = $1
                   AND kind = 'wait'
                   AND status = 'waiting'
                 LIMIT 1
                """,
                resume_token,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause: token lookup failed: %s", exc)
        return None
    return _row_to_pause(row) if row is not None else None


async def due_waits(*, now: datetime | None = None, limit: int = 50) -> list[Pause]:
    """Timer waits whose deadline has passed.

    Cross-tenant for the same reason ``expire_due`` is, and recorded in
    ``scripts/check_tenant_query_predicates.py`` alongside it: a per-tenant
    sweep needs a list of tenants, and a tenant missing from that list has
    waits that never wake — which is the silent hang this exists to stop.

    Read-only. Claiming a row is ``resolve``'s job and happens one at a
    time, so two replicas sweeping at once resume each wait once.
    """
    pool = await _pool()
    if pool is None:
        return []
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                f"""
                SELECT {_PAUSE_COLUMNS}
                  FROM aisoc_playbook_pauses
                 WHERE status = 'waiting'
                   AND kind = 'wait'
                   AND resume_at IS NOT NULL
                   AND resume_at <= $1
                 ORDER BY resume_at
                 LIMIT $2
                """,
                now or datetime.now(UTC),
                limit,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause: due-wait sweep failed: %s", exc)
        return []
    return [_row_to_pause(row) for row in rows]


async def resolve(*, pause_id: str, status: str, resolution: str, tenant_id: str) -> bool:
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
                 WHERE id = $1::uuid
                   AND tenant_id = $4::uuid
                   AND status = 'waiting'
                """,
                pause_id,
                status,
                resolution[:500],
                tenant_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("playbook_pause: resolve failed for %s: %s", pause_id, exc)
        return False
    # asyncpg returns "UPDATE <n>"; zero means somebody else resolved it
    # first, which is the double-decision case and is not an error.
    changed = str(result).rsplit(" ", 1)[-1] != "0"
    if not changed:
        logger.info("playbook_pause: %s was already resolved", pause_id)
    return changed


async def expire_due(*, now: datetime | None = None) -> list[str]:
    """Expire every pause past its deadline. Returns the run ids.

    Deliberately cross-tenant, and recorded as such in
    `scripts/check_tenant_query_predicates.py`. A per-tenant sweep would
    need a list of tenants to iterate, and a tenant missing from that list
    would have approvals that never expire — the exact silent-hang this
    sweep exists to prevent.

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
        logger.warning("playbook_pause: expiry sweep failed: %s", exc)
        return []
    run_ids = [r["run_id"] for r in rows]
    if run_ids:
        # Info, not debug. An expired approval means an action a human was
        # asked to authorise did not happen, and nobody decided that.
        logger.info("playbook_pause: %d pause(s) expired: %s", len(run_ids), run_ids[:10])
    return run_ids
