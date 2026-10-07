"""The loop that wakes timer waits and expires pauses that nobody decided.

Why this file exists at all
---------------------------
``pause.expire_due`` was written with the approval pause and has had no
production caller since: its only reference in the tree is a test. So an
approval that nobody decided stayed ``waiting`` forever, and the `expired`
outcome the design calls "a decision, not an absence of one" was never
recorded by anything.

A ``wait`` step inherits that hole and makes it worse, because an approval
at least has a human who might come back. A timer wait with no sweeper is a
run that stops and never continues, reporting ``paused`` indefinitely.

Three properties, each the opposite of a way this could go wrong
-----------------------------------------------------------------
**Tells permanent from transient.** An unreachable database is transient and
is retried with a capped backoff. A missing playbook is permanent for that
pause, and the resume path records it rather than retrying forever.

**Says so when it cannot do its job.** A sweeper that silently stops is
indistinguishable from one with nothing to do. Every error is logged at
``warning`` with the reason, and consecutive failures escalate the interval
rather than hammering a store that is down.

**Safe to run on several replicas.** Claiming a pause is a conditional
``UPDATE ... WHERE status = 'waiting'``, so two sweepers racing the same row
resume it once; the loser sees zero rows changed and moves on.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os

logger = logging.getLogger("aisoc.playbook.sweeper")

#: How often to look. A wait is a coarse instrument — the shortest one that
#: reaches this loop is already longer than the inline ceiling — so a minute
#: of latency on a six-hour wait costs nothing and a tight poll would be a
#: query per second against a table that is empty most of the time.
DEFAULT_INTERVAL_SECONDS = float(os.getenv("AISOC_PLAYBOOK_SWEEP_INTERVAL_SECONDS", "60"))

#: Ceiling for the backoff a failing store earns. Past this the sweeper is
#: still trying, just not pretending the next attempt is urgent.
_MAX_BACKOFF_SECONDS = 600.0


def enabled() -> bool:
    """Off only by explicit opt-out.

    On by default, unlike everything in this wave that reaches a vendor:
    this reaches nothing outward. Its job is to finish work the product has
    already started, and the failure mode of not running it is a run that
    hangs — which is the defect, not the safe state.
    """
    return os.getenv("AISOC_PLAYBOOK_SWEEPER_DISABLE", "").strip().lower() not in {"1", "true", "yes", "on"}


async def sweep_once() -> dict[str, int]:
    """One pass: resume what is due, expire what is past its deadline.

    Resume first. A pause whose timer came due in the same tick that its
    TTL expired should run, not be cancelled — the run did what it was
    asked to, slightly late, and expiring it would discard work for a
    scheduling detail.
    """
    from app.playbook import engine
    from app.playbook import pause as playbook_pause

    resumed = await engine.resume_due_waits()
    expired = await playbook_pause.expire_due()
    if resumed or expired:
        logger.info("playbook_sweeper: resumed %d wait(s), expired %d pause(s)", len(resumed), len(expired))
    return {"resumed": len(resumed), "expired": len(expired)}


async def run_forever(*, interval_seconds: float | None = None) -> None:
    """Sweep on a fixed cadence until cancelled."""
    interval = interval_seconds or DEFAULT_INTERVAL_SECONDS
    consecutive_failures = 0
    while True:
        try:
            await sweep_once()
            consecutive_failures = 0
            delay = interval
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a failed sweep must not end the loop
            consecutive_failures += 1
            delay = min(interval * (2**consecutive_failures), _MAX_BACKOFF_SECONDS)
            logger.warning(
                "playbook_sweeper: pass %d failed (%s); next attempt in %.0fs",
                consecutive_failures,
                exc,
                delay,
            )
        await asyncio.sleep(delay)


def start(app: object) -> asyncio.Task | None:
    """Start the sweeper as a background task on the app, or say why not."""
    if not enabled():
        logger.info("playbook_sweeper: disabled by AISOC_PLAYBOOK_SWEEPER_DISABLE")
        return None
    task = asyncio.create_task(run_forever())
    task.add_done_callback(_log_exit)
    with contextlib.suppress(AttributeError):
        app.state.playbook_sweeper_task = task  # type: ignore[attr-defined]
    logger.info("playbook_sweeper: started, every %.0fs", DEFAULT_INTERVAL_SECONDS)
    return task


def _log_exit(task: asyncio.Task) -> None:
    """Retrieve the task's outcome so a dead sweeper is in the log.

    The same pairing the triage worker and the fusion consumer carry. A
    background task whose exception is never retrieved dies quietly, and
    the only symptom is runs that stop resuming — which looks like a
    playbook problem rather than a missing sweeper.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("playbook_sweeper: exited on %s; waits will no longer resume", exc)
