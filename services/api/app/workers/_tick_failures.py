"""Report a failing scheduler tick in a way an operator can act on.

Both long-running tick loops in this package used to log ``err=%s`` with
``type(exc).__name__`` and nothing else. That is louder than silence and not
much more useful: ``err=ProgrammingError`` repeated every thirty seconds says
a tick failed, never *why*, and — the part that costs an incident —
never whether waiting is the right response.

The distinction matters because these loops cannot tell the two apart by
construction. A ``ProgrammingError`` from a column the migration never
created will fail identically on every future tick; an ``OperationalError``
from a database that is restarting will clear on the next one. Printing the
same line for both makes a permanent misconfiguration read as ordinary churn,
which is the failure mode the UEBA consumer shipped with and the playbook
bridge was split in two to avoid.

So a tracker counts consecutive failures, keeps the message, and escalates
once the run has outlived any explanation a retry would fix. It does not
classify exception types: doing that here would need a SQLAlchemy import in
a module two loops share for logging, and the elapsed-time signal answers the
operator's actual question — "is this still worth waiting on" — without
guessing.

Messages are sanitised inline at the call site rather than through a helper,
because CodeQL's taint tracker does not follow a sanitiser across a function
boundary but does recognise the inline ``replace``/slice chain. See
``apps/docs/docs/operations/security.md#static-analysis-codeql``.
"""

from __future__ import annotations

import logging
import time


class TickFailures:
    """Consecutive-failure state for one tick loop.

    Not thread-safe and does not need to be: each instance belongs to a
    single asyncio task that owns its loop.
    """

    def __init__(self, name: str, logger: logging.Logger, *, stuck_after_seconds: float = 300.0) -> None:
        self._name = name
        self._log = logger
        self._stuck_after = stuck_after_seconds
        self._consecutive = 0
        self._since = 0.0

    @property
    def consecutive(self) -> int:
        return self._consecutive

    @property
    def not_resolving(self) -> bool:
        """Whether this run of failures has outlived a transient explanation."""
        return self._consecutive > 0 and (time.monotonic() - self._since) >= self._stuck_after

    def record_failure(self, exc: BaseException) -> None:
        """Log one failed tick at a level that matches what can be done about it."""
        now = time.monotonic()
        if self._consecutive == 0:
            self._since = now
        self._consecutive += 1
        elapsed = now - self._since

        # Inline sanitisation, deliberately not extracted (see module docstring).
        detail = str(exc).replace("\r", "").replace("\n", " ")[:300]

        if self.not_resolving:
            self._log.error(
                "%s tick failing for %.0fs across %d consecutive attempts; "
                "treat this as a misconfiguration rather than churn err=%s detail=%s",
                self._name,
                elapsed,
                self._consecutive,
                type(exc).__name__,
                detail,
            )
        else:
            self._log.warning(
                "%s tick failed (attempt %d) err=%s detail=%s",
                self._name,
                self._consecutive,
                type(exc).__name__,
                detail,
            )

    def record_success(self) -> None:
        """Clear the run, and say so if there was one.

        A recovery that is not logged leaves the last line in the log
        describing a fault that has since cleared.
        """
        if self._consecutive:
            self._log.info(
                "%s recovered after %d consecutive failure(s) over %.0fs",
                self._name,
                self._consecutive,
                time.monotonic() - self._since,
            )
        self._consecutive = 0
        self._since = 0.0
