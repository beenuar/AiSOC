"""The loop that closes investigation runs orphaned by a dead process.

Why this exists alongside the deadline
--------------------------------------
``app.api.investigate._run_and_store`` now runs under the shared wall-clock
budget, so a run that hangs inside a live process ends as ``failed`` and says
why. That covers nothing at all once the process is gone: the run store is a
module-level dict, so a restart, an OOM kill or an ordinary rollout drops every
in-flight run on the floor while its ``investigation_runs`` row stays
``'running'``. Nothing else in the service will ever write a terminal status to
it, and the Investigation Ledger renders exactly that row.

How long is "stale"
-------------------
Derived from the same budget the deadline uses, never restated. A run cannot
legitimately outlast ``AISOC_INVESTIGATION_MAX_SECONDS`` any more, so a row
still ``running`` several multiples past it belongs to a process that is not
coming back. The multiplier plus a floor is the margin against clock skew and
a replica that is merely slow to write its terminal status; an operator who
needs a different one sets ``AISOC_INVESTIGATION_STALE_AFTER_SECONDS``.

Three properties, matching ``app.playbook.sweeper``
---------------------------------------------------
**Safe on several replicas.** The staleness predicate lives inside the
``UPDATE``, so two reapers racing one row close it once.

**Says so when it cannot do its job.** Every failed pass is logged at
``warning`` with the reason, and consecutive failures back off rather than
hammering a store that is down.

**Off only by explicit opt-out.** The failure mode of not running it is the
defect it exists to fix, not the safe state.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os

from app.graph.runner import default_budget
from app.investigator import ledger

logger = logging.getLogger("aisoc.investigator.run_reaper")

#: How often to look. Orphans only appear at process death, so this is a query
#: against an indexed ``status`` column on a table that is empty of stale rows
#: almost always; a minute of latency on a run that has already been abandoned
#: for several multiples of its budget costs nothing.
DEFAULT_INTERVAL_SECONDS = float(os.getenv("AISOC_INVESTIGATION_REAP_INTERVAL_SECONDS", "60"))

#: Multiples of the run budget before a row counts as abandoned.
_STALE_BUDGET_MULTIPLE = 3.0

#: Floor for the staleness margin, so a deployment that sets a very small
#: budget for its own testing does not start reaping runs that a replica is
#: still writing the terminal status for.
_MIN_STALE_SECONDS = 300.0

#: Ceiling for the backoff a failing store earns.
_MAX_BACKOFF_SECONDS = 600.0

#: What the closed row says. An operator reading the ledger needs to know this
#: was a reap rather than a verdict the agent reached.
STALE_REASON = "Investigation abandoned: the process running it exited before writing a result."


def stale_after_seconds() -> float:
    """Seconds a run may sit at ``running`` before it counts as abandoned.

    Derived from ``AISOC_INVESTIGATION_MAX_SECONDS`` so the reaper and the
    deadline cannot disagree about how long a run is allowed to take — two
    independently written numbers for one budget is how the shorter one wins
    silently. ``AISOC_INVESTIGATION_STALE_AFTER_SECONDS`` overrides it outright
    for an operator who wants a different margin.
    """
    raw = os.getenv("AISOC_INVESTIGATION_STALE_AFTER_SECONDS", "").strip()
    if raw:
        try:
            return float(raw)
        except ValueError:
            logger.warning(
                "run_reaper: AISOC_INVESTIGATION_STALE_AFTER_SECONDS=%r is not a number; deriving from the run budget",
                raw,
            )
    return max(default_budget().max_seconds * _STALE_BUDGET_MULTIPLE, _MIN_STALE_SECONDS)


def enabled() -> bool:
    """On unless explicitly disabled, like the playbook sweeper."""
    return os.getenv("AISOC_INVESTIGATION_REAPER_DISABLE", "").strip().lower() not in {"1", "true", "yes", "on"}


async def reap_once() -> int:
    """One pass. Returns how many rows were closed."""
    closed = await ledger.fail_stale_runs(
        older_than_seconds=stale_after_seconds(),
        reason=STALE_REASON,
    )
    if closed:
        logger.info("run_reaper: closed %d abandoned investigation run(s)", len(closed))
    return len(closed)


async def run_forever(*, interval_seconds: float | None = None) -> None:
    """Reap on a fixed cadence until cancelled."""
    interval = interval_seconds or DEFAULT_INTERVAL_SECONDS
    consecutive_failures = 0
    while True:
        try:
            await reap_once()
            consecutive_failures = 0
            delay = interval
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a failed pass must not end the loop
            consecutive_failures += 1
            delay = min(interval * (2**consecutive_failures), _MAX_BACKOFF_SECONDS)
            logger.warning(
                "run_reaper: pass %d failed (%s); next attempt in %.0fs",
                consecutive_failures,
                exc,
                delay,
            )
        await asyncio.sleep(delay)


def start(app: object) -> asyncio.Task | None:
    """Start the reaper as a background task on the app, or say why not."""
    if not enabled():
        logger.info("run_reaper: disabled by AISOC_INVESTIGATION_REAPER_DISABLE")
        return None
    task = asyncio.create_task(run_forever())
    task.add_done_callback(_log_exit)
    with contextlib.suppress(AttributeError):
        app.state.investigation_reaper_task = task  # type: ignore[attr-defined]
    logger.info(
        "run_reaper: started, every %.0fs, closing runs older than %.0fs",
        DEFAULT_INTERVAL_SECONDS,
        stale_after_seconds(),
    )
    return task


def _log_exit(task: asyncio.Task) -> None:
    """Retrieve the task's outcome so a dead reaper is in the log.

    The same pairing the triage worker, the fusion consumer and the playbook
    sweeper carry. A background task whose exception is never retrieved dies
    quietly, and the only symptom is orphaned runs accumulating — which looks
    like an agent problem rather than a missing reaper.
    """
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("run_reaper: exited on %s; abandoned runs will stay 'running'", exc)
