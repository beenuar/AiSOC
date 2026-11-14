"""
Per-action approval timeout scheduler.

Approval cards posted by :func:`app.blocks.approval_card_blocks` carry a
"⏱️ Auto-{verb} in N min" footer when ``timeout_seconds`` is set. T3.6
adds the actual server-side enforcement of that promise:

1. When the bot submits an action that needs approval, it asks the
   :class:`ApprovalTimeoutScheduler` to register a *fallback* for that
   ``action_id`` with the configured safe-default decision (typically
   ``"rejected"`` so a forgotten approval can never accidentally
   execute).
2. If a human clicks Approve / Deny first, the bot cancels the
   registration. The cancellation is idempotent — clicking a card we
   never scheduled is silently fine.
3. Otherwise the scheduler fires the fallback: it calls into
   ``services/actions`` exactly as if a human had clicked Deny (or
   Approve, for blast-radius=0 actions where that's the safe default)
   and writes a ``decision="timeout_fallback"`` row to the audit sink so
   the case timeline reflects *why* the action terminated.

The scheduler is asyncio-native — one :class:`asyncio.Task` per pending
action, cancelled in O(1) via ``Task.cancel()``. This is sufficient at
SOC scale; a horizontally-scaled deployment would graduate to a
persistent timer table, but that's out of scope here. The unit test
walks the timer all the way through with ``asyncio.sleep(0)`` ticks and
a tiny ``timeout_seconds`` so the test stays sub-second.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal

import structlog

from app.services.approval_audit import (
    ApprovalAuditEvent,
    ApprovalAuditSink,
    NullAuditSink,
)
from app.services.timer_store import InMemoryTimerStore, TimerRecord, TimerStore

log = structlog.get_logger(__name__)

SafeDefault = Literal["rejected", "approved"]


class ApprovalTimeoutScheduler:
    """
    asyncio-based timeout scheduler for approval actions.

    The scheduler holds **no state on disk** — restarts wipe pending
    timers. That's the same blast-radius model as Bolt's request queue,
    and the comment block in the class docstring above explains the
    rationale.

    Callbacks are *async*: ``approve_fn(action_id) -> dict`` and
    ``reject_fn(action_id) -> dict``. They typically wrap
    :class:`app.services.aisoc_clients.AisocActionsClient` but the
    scheduler doesn't care — anything awaitable that records the
    decision upstream works, which is what makes the timeout test
    hermetic.
    """

    def __init__(
        self,
        *,
        approve_fn: Callable[[str], Awaitable[Any]],
        reject_fn: Callable[[str], Awaitable[Any]],
        audit_sink: ApprovalAuditSink | None = None,
        store: TimerStore | None = None,
    ) -> None:
        self._approve_fn = approve_fn
        self._reject_fn = reject_fn
        self._audit_sink = audit_sink or NullAuditSink()
        # Phase B3 — optional durable backing store so pending SLA timers
        # survive a bot restart. Defaults to non-durable in-memory (pre-B3
        # behaviour); production injects a PostgresTimerStore.
        self._store: TimerStore = store or InMemoryTimerStore()
        self._timers: dict[str, asyncio.Task[None]] = {}

    @property
    def pending(self) -> int:
        """Number of timers currently armed (mostly for tests / metrics)."""
        return sum(1 for t in self._timers.values() if not t.done())

    def schedule(
        self,
        action_id: str,
        *,
        timeout_seconds: float,
        safe_default: SafeDefault = "rejected",
        case_id: str = "",
        channel: str | None = None,
        approver_id: str = "scheduler",
    ) -> asyncio.Task[None]:
        """
        Arm a timeout for ``action_id``. Returns the underlying task so
        tests can ``await`` it deterministically.

        Calling :meth:`schedule` twice for the same ``action_id`` cancels
        the previous timer first — Slack can replay an approval card
        post and we want exactly one safe-default in flight at a time.
        """
        existing = self._timers.get(action_id)
        if existing is not None and not existing.done():
            existing.cancel()

        # Phase B3 — persist the pending timer so a restart can recover it.
        # Best-effort: a store failure never blocks arming the in-memory timer.
        record = TimerRecord(
            action_id=action_id,
            fire_at_epoch=time.time() + timeout_seconds,
            safe_default=safe_default,
            case_id=case_id,
            channel=channel,
            approver_id=approver_id,
        )
        asyncio.create_task(self._store.put(record))  # noqa: RUF006 — fire-and-forget persist

        async def _fire() -> None:
            try:
                await asyncio.sleep(timeout_seconds)
            except asyncio.CancelledError:
                return
            # The timer fired — drop the durable row so recovery won't re-arm it.
            with contextlib.suppress(Exception):
                await self._store.delete(action_id)
            try:
                if safe_default == "approved":
                    await self._approve_fn(action_id)
                else:
                    await self._reject_fn(action_id)
            except Exception as exc:  # noqa: BLE001 - last-resort guard
                log.error(
                    "approval_timeout.fallback_call_failed",
                    action_id=action_id,
                    error=str(exc),
                )
                await self._audit_sink.record(
                    ApprovalAuditEvent(
                        case_id=case_id,
                        action_id=action_id,
                        approver_id=approver_id,
                        decision="timeout_fallback",
                        channel=channel,
                        source="scheduler",
                        error=str(exc),
                        metadata={"safe_default": safe_default},
                    )
                )
                return

            log.info(
                "approval_timeout.fallback_fired",
                action_id=action_id,
                safe_default=safe_default,
                case_id=case_id,
            )
            await self._audit_sink.record(
                ApprovalAuditEvent(
                    case_id=case_id,
                    action_id=action_id,
                    approver_id=approver_id,
                    decision="timeout_fallback",
                    channel=channel,
                    source="scheduler",
                    metadata={"safe_default": safe_default},
                )
            )

        task = asyncio.create_task(_fire(), name=f"approval-timeout-{action_id}")
        self._timers[action_id] = task
        return task

    def cancel(self, action_id: str) -> bool:
        """
        Cancel the timer for ``action_id``. Returns ``True`` if a timer
        was armed and got cancelled; ``False`` if nothing was pending
        (idempotent — Slack can replay events).
        """
        # Human decided in time (or explicit cancel) — drop the durable row so a
        # restart won't resurrect a timer for an already-decided action.
        asyncio.create_task(self._store.delete(action_id))  # noqa: RUF006 — fire-and-forget

        existing = self._timers.pop(action_id, None)
        if existing is None or existing.done():
            return False
        existing.cancel()
        return True

    async def recover(self) -> int:
        """Re-arm timers from the durable store after a restart.

        Called from the FastAPI lifespan on startup. An overdue timer (deadline
        already passed while the bot was down) is re-armed with a near-zero
        delay so its safe-default fires promptly. Returns the number recovered.
        """
        recovered = 0
        now = time.time()
        for record in await self._store.list_pending():
            if record.action_id in self._timers and not self._timers[record.action_id].done():
                continue
            remaining = max(0.0, record.fire_at_epoch - now)
            self.schedule(
                record.action_id,
                timeout_seconds=remaining,
                safe_default=record.safe_default,  # type: ignore[arg-type]
                case_id=record.case_id,
                channel=record.channel,
                approver_id=record.approver_id,
            )
            recovered += 1
        if recovered:
            log.info("approval_timeout.recovered", count=recovered)
        return recovered

    async def aclose(self) -> None:
        """Cancel every armed timer (called from the FastAPI lifespan)."""
        for task in list(self._timers.values()):
            if not task.done():
                task.cancel()
        for task in list(self._timers.values()):
            # ``asyncio.CancelledError`` is a ``BaseException`` (not an
            # ``Exception``) on Python 3.8+, so ``suppress(Exception)``
            # lets it propagate and tear the lifespan down with one
            # ``CancelledError`` per pending timer. We expect cancellation
            # here — that's the whole point of the shutdown path — so
            # suppress it explicitly alongside any tear-down errors.
            with contextlib.suppress(asyncio.CancelledError, Exception):
                # Assign to ``_`` so CodeQL ``py/ineffectual-statement``
                # doesn't flag this awaited coroutine as a discarded
                # expression. We genuinely don't care about the return
                # value — we only ``await`` so the task either finishes
                # or raises ``CancelledError`` before we drop the
                # reference.
                _ = await task
        self._timers.clear()
