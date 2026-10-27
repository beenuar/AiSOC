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

What a store has to guarantee before a vendor is contacted
----------------------------------------------------------
Durability was only half of it. The approve path read a record, checked its
status in Python, called the vendor and saved afterwards, which left three
gaps that an upsert alone cannot close:

* **Nobody claimed the execution.** Two replicas, or one replica and a client
  that retried, both read ``awaiting_approval`` and both contained the host.
  :func:`claim_for_execution` is one conditional ``UPDATE`` — Postgres takes a
  row lock, so a second claimant blocks, re-evaluates the predicate against the
  committed row, finds ``running`` and matches nothing. Same mechanism as
  ``scheduler_leases`` (migration 115), and for the same reason: a
  SELECT-then-UPDATE has no such re-evaluation.
* **The cache outranked the database.** ``get`` answered from ``_MEMORY``
  first, so the replica that handled the submission held an
  ``awaiting_approval`` copy for the life of the process and would execute
  again whatever the database had since recorded. Reads on a decision path ask
  for ``authoritative=True``, which skips the cache when a DSN is configured
  and *raises* rather than reporting a reachable store's outage as a missing
  action.
* **Intent was mutable under the approver.** ``ON CONFLICT (id) DO UPDATE SET
  record = EXCLUDED.record`` with no condition meant a second submission of the
  same id could retarget an action a human was in the middle of approving. The
  upsert now refuses to change the action type, target or parameters of a
  record that is awaiting approval or running, and says so.

Failures are not swallowed on those paths. ``save`` keeps its tolerant
behaviour — losing a *pending* action because the store blinked is the failure
this module was written to prevent, and an outcome write that raised would lose
the one record of a vendor that has already been touched — but a claim refuses
rather than proceeding, because that write is the authorization for an external
effect.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()

#: Process-local fallback, and the store the unit suite exercises.
_MEMORY: dict[str, dict[str, Any]] = {}

#: Serialises the in-memory claim. Only load-bearing when no DSN is configured;
#: with one, Postgres' row lock is the serialisation point and this lock is
#: held across no I/O.
_MEMORY_CLAIM_LOCK = asyncio.Lock()


class ActionStoreUnavailable(RuntimeError):
    """A durable store is configured and could not be read or written.

    Distinct from "no such action" on purpose. Reporting a reachable store's
    outage as a 404 sends an operator to look for an action that exists, and
    reporting it as success would let an external effect proceed with no
    record of the authorization behind it.
    """


class ActionIntentConflict(RuntimeError):
    """A submission tried to change what a pending action would do.

    Carries the stored intent so the caller can say what the approver is
    actually looking at rather than only that the write was refused.
    """

    def __init__(self, action_id: str, stored: dict[str, Any]) -> None:
        super().__init__(f"action {action_id} is already awaiting a decision on a different target or parameters")
        self.action_id = action_id
        self.stored = stored


class ClaimOutcome(str, Enum):
    """Why a claim did or did not take.

    Every value except ``CLAIMED`` means *do not contact the vendor*, and they
    are kept apart because they need different answers: a losing replica is a
    409, an action in an unknown state needs reconciliation rather than a
    retry, and an unwritable store is a 503 the caller may repeat.
    """

    CLAIMED = "claimed"
    NOT_FOUND = "not_found"
    WRONG_STATE = "wrong_state"
    STORE_UNAVAILABLE = "store_unavailable"


@dataclass(frozen=True)
class Claim:
    outcome: ClaimOutcome
    #: The record as it stands *after* a successful claim, read back from the
    #: database rather than reconstructed, so what executes is what was
    #: claimed. ``None`` when the claim did not take and there is no row.
    record: dict[str, Any] | None = None
    #: The status that blocked the claim, for the caller's message.
    current_status: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome is ClaimOutcome.CLAIMED


#: The fields that define *what an approver signed off*. A change to any of
#: them is a different action, whatever the id says.
#:
#: ``rationale`` is deliberately out: it is the explanation shown to a human
#: and an agent re-running its triage may word it differently without changing
#: what would happen to the estate. ``confidence`` is out for the same reason —
#: it is re-graded by the gate on every submission.
INTENT_FIELDS: tuple[str, ...] = ("action_type", "target", "parameters")


def intent_of(record: dict[str, Any]) -> dict[str, Any]:
    """The immutable part of an action, for comparison and for an error."""
    return {field: record.get(field) for field in INTENT_FIELDS}


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


def _column_text(value: Any) -> str:
    """The value a column should hold, for an enum or a plain string.

    `ActionStatus` and `ApprovalRequirement` are `(str, Enum)` classes, and
    `Enum` keeps its own `__str__` for a mixin like that — so `str(member)`
    is `'ActionStatus.COMPLETED'`, not `'completed'`. The `status` column
    was written that way since the table was added, which meant the index
    on `(tenant_id, status)` indexed a string no query ever asked for and
    the usage meter counting executed actions could only return zero.

    `json.dumps` does not go through `__str__` for a `str` subclass, so the
    JSONB copy of the same record was always right. One of the two had to
    be wrong, and it was never going to be noticed from the record.
    """
    if value is None:
        return ""
    return str(getattr(value, "value", value))


#: Statuses whose intent an approver may already be looking at.
#:
#: Spelled as literals rather than imported from ``app.models.action`` because
#: this module is the storage layer and the column holds text; importing the
#: enum here would make the SQL depend on the executor contract, which is the
#: coupling 055 avoided by storing the record whole.
_INTENT_LOCKED_STATUSES = ("awaiting_approval", "running", "reconciliation_required")

#: The same tuple as a SQL list. Built rather than written twice so the two
#: cannot drift, and quoted here because these are fixed identifiers from a
#: closed set, never request data.
_INTENT_LOCKED_SQL_LIST = "(" + ", ".join(f"'{status}'" for status in _INTENT_LOCKED_STATUSES) + ")"

#: Refuse an intent change while a decision is outstanding, allow every other
#: update, and tell the caller which happened.
#:
#: ``RETURNING id`` is how: an ``ON CONFLICT DO UPDATE`` whose ``WHERE`` is not
#: satisfied returns no row, which is the only signal Postgres gives that the
#: upsert declined. ``IS NOT DISTINCT FROM`` rather than ``=`` because a NULL
#: target must compare equal to itself.
_UPSERT_SQL = f"""
    INSERT INTO aisoc_action_records (id, tenant_id, status, approval_tier, record, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, now(), now())
    ON CONFLICT (id) DO UPDATE
        SET status = EXCLUDED.status,
            approval_tier = EXCLUDED.approval_tier,
            record = EXCLUDED.record,
            updated_at = now()
     WHERE aisoc_action_records.status NOT IN {_INTENT_LOCKED_SQL_LIST}
        OR (
            aisoc_action_records.record ->> 'action_type' IS NOT DISTINCT FROM EXCLUDED.record ->> 'action_type'
            AND aisoc_action_records.record ->> 'target' IS NOT DISTINCT FROM EXCLUDED.record ->> 'target'
            AND aisoc_action_records.record -> 'parameters' IS NOT DISTINCT FROM EXCLUDED.record -> 'parameters'
        )
    RETURNING id
"""


async def save(record: dict[str, Any]) -> None:
    """Persist or update an action record.

    Raises :class:`ActionIntentConflict` when the write would change what a
    pending action does. Everything else is still tolerated and logged: the
    whole reason this module exists is that losing a pending containment to a
    store blink is worse than running degraded, and an outcome write that
    raised would discard the only record of a vendor already touched.

    The durable write goes first. It used to be second, so a refused or failed
    write left the process-local copy holding a record the database had never
    accepted — and ``get`` preferred that copy.
    """
    action_id = str(record["id"])

    dsn = _dsn()
    if dsn is None:
        _MEMORY[action_id] = record
        return

    try:
        conn = await _connect(dsn)
    except Exception as exc:  # noqa: BLE001 — an unreachable store must not drop the action
        _report_degraded("connect_failed", action_id, exc)
        _MEMORY[action_id] = record
        return
    try:
        written = await conn.fetchval(
            _UPSERT_SQL,
            action_id,
            _column_text(record.get("tenant_id")),
            _column_text(record.get("status")),
            _column_text(record.get("approval_tier")) or None,
            json.dumps(record, default=str),
        )
        global _DB_CONFIRMED
        _DB_CONFIRMED = True
        if written is None:
            stored = await _fetch_record(conn, action_id, None)
            logger.warning(
                "action_store.intent_change_refused",
                action_id=action_id,
                stored_intent=intent_of(stored or {}),
                submitted_intent=intent_of(record),
            )
            raise ActionIntentConflict(action_id, intent_of(stored or {}))
    except ActionIntentConflict:
        raise
    except Exception as exc:  # noqa: BLE001 — see above
        _report_degraded("write_failed", action_id, exc)
        _MEMORY[action_id] = record
        return
    finally:
        await conn.close()

    _MEMORY[action_id] = record


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


async def _fetch_record(conn: Any, action_id: str, tenant_id: str | None) -> dict[str, Any] | None:
    """One tenant-narrowed read, on a connection the caller owns."""
    if tenant_id is None:
        row = await conn.fetchrow("SELECT record FROM aisoc_action_records WHERE id = $1", action_id)
    else:
        row = await conn.fetchrow(
            "SELECT record FROM aisoc_action_records WHERE id = $1 AND tenant_id = $2",
            action_id,
            str(tenant_id),
        )
    return json.loads(row["record"]) if row is not None else None


async def get(action_id: str, tenant_id: str | None = None, *, authoritative: bool = False) -> dict[str, Any] | None:
    """Fetch an action record.

    ``tenant_id`` narrows the lookup to one tenant and should be supplied from
    a request path wherever the caller has an authenticated identity to take
    it from. ``aisoc_action_records``' RLS policy is inert on this service's
    connections — it reads ``app.current_tenant_id``, which nothing here sets,
    and its unset arm is deliberately permissive so cross-tenant workers are
    not starved — so without a predicate an id is a capability: an action
    record names the host or account an action was aimed at.

    ``authoritative`` is for the decision paths. The in-memory copy is a cache,
    and on the replica that handled the submission it is a cache that never
    expires: it held ``awaiting_approval`` for the life of the process, so an
    approve on that replica would execute an action another replica had already
    run. An authoritative read skips it when a DSN is configured and raises
    :class:`ActionStoreUnavailable` rather than answering "no such action" for
    a store that is merely unreachable.
    """
    dsn = _dsn()

    if dsn is None:
        cached = _MEMORY.get(action_id)
        if cached is not None and tenant_id is not None and str(cached.get("tenant_id") or "") != str(tenant_id):
            return None
        return cached

    if not authoritative:
        cached = _MEMORY.get(action_id)
        if cached is not None:
            if tenant_id is not None and str(cached.get("tenant_id") or "") != str(tenant_id):
                return None
            return cached

    try:
        conn = await _connect(dsn)
    except Exception as exc:  # noqa: BLE001
        logger.warning("action_store.connect_failed", action_id=action_id, error=str(exc))
        if authoritative:
            raise ActionStoreUnavailable("the action store is configured and unreachable") from exc
        return None
    try:
        record = await _fetch_record(conn, action_id, tenant_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("action_store.read_failed", action_id=action_id, error=str(exc))
        if authoritative:
            raise ActionStoreUnavailable("the action store is configured and could not be read") from exc
        return None
    finally:
        await conn.close()

    if record is None:
        # Drop any cached copy: the authoritative answer is that this tenant
        # has no such action, and leaving a stale one behind is how the cache
        # outranked the database in the first place.
        if authoritative:
            _MEMORY.pop(action_id, None)
        return None
    _MEMORY[action_id] = record
    return record


async def claim_for_execution(
    action_id: str,
    *,
    tenant_id: str,
    expected_status: str,
    claimed_by: str,
    running_status: str = "running",
) -> Claim:
    """Take exclusive ownership of an action's execution, durably, or refuse.

    One conditional ``UPDATE``. Postgres locks the row, so a second claimant
    blocks until the first commits, then re-evaluates ``status =
    $expected_status`` against the committed row, finds ``running`` and matches
    nothing. That re-evaluation is the whole mechanism and it is why this is
    not a ``SELECT`` followed by an ``UPDATE``: that pair has no re-evaluation
    and elects two executors, which here means contacting a vendor twice.

    The tenant is a predicate rather than a check afterwards. A handler that
    fetches globally and compares in Python is the same defect one line later.

    An unreachable or unwritable store returns ``STORE_UNAVAILABLE`` and the
    caller must not proceed: this write *is* the authorization for an external
    effect, and an effect nobody can prove was authorized is worse than a
    refused approval an operator can repeat.
    """
    claimed_at = datetime.now(UTC).isoformat()
    dsn = _dsn()

    if dsn is None:
        async with _MEMORY_CLAIM_LOCK:
            record = _MEMORY.get(action_id)
            if record is None or str(record.get("tenant_id") or "") != str(tenant_id):
                return Claim(ClaimOutcome.NOT_FOUND)
            current = _column_text(record.get("status"))
            if current != expected_status:
                return Claim(ClaimOutcome.WRONG_STATE, current_status=current)
            record["status"] = running_status
            record["dispatch"] = {"claimed_by": claimed_by, "claimed_at": claimed_at, "state": "claimed"}
            return Claim(ClaimOutcome.CLAIMED, record=dict(record))

    try:
        conn = await _connect(dsn)
    except Exception as exc:  # noqa: BLE001
        _report_degraded("claim_connect_failed", action_id, exc)
        return Claim(ClaimOutcome.STORE_UNAVAILABLE)

    try:
        row = await conn.fetchrow(
            """
            UPDATE aisoc_action_records
               SET status = $4,
                   record = jsonb_set(
                       jsonb_set(record, '{status}', to_jsonb($4::text), true),
                       '{dispatch}', $5::jsonb, true
                   ),
                   updated_at = now()
             WHERE id = $1
               AND tenant_id = $2
               AND status = $3
            RETURNING record
            """,
            action_id,
            str(tenant_id),
            expected_status,
            running_status,
            json.dumps({"claimed_by": claimed_by, "claimed_at": claimed_at, "state": "claimed"}),
        )
    except Exception as exc:  # noqa: BLE001
        _report_degraded("claim_failed", action_id, exc)
        await conn.close()
        return Claim(ClaimOutcome.STORE_UNAVAILABLE)

    try:
        if row is not None:
            global _DB_CONFIRMED
            _DB_CONFIRMED = True
            record = json.loads(row["record"])
            _MEMORY[action_id] = record
            return Claim(ClaimOutcome.CLAIMED, record=record)

        # Nothing matched. Say which of the three reasons it was, because an
        # operator's next step differs for each: another replica has it, the
        # action is in a state no approval can move, or this tenant has no
        # such action at all.
        existing = await _fetch_record(conn, action_id, str(tenant_id))
        if existing is None:
            _MEMORY.pop(action_id, None)
            return Claim(ClaimOutcome.NOT_FOUND)
        current = _column_text(existing.get("status"))
        _MEMORY[action_id] = existing
        return Claim(ClaimOutcome.WRONG_STATE, record=existing, current_status=current)
    except Exception as exc:  # noqa: BLE001
        _report_degraded("claim_readback_failed", action_id, exc)
        return Claim(ClaimOutcome.STORE_UNAVAILABLE)
    finally:
        await conn.close()


def clear() -> None:
    """Drop the in-memory copy. Used by tests."""
    _MEMORY.clear()
