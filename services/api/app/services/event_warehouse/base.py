"""Event-warehouse provider protocol — Phase 4.5.

Every provider implements one async method, :meth:`run_hunt`, taking a
saved-hunt row and returning the number of hits. The scheduler does
not care which warehouse answered — it only feeds the hit count into
the case-open callback.

Provider authors must:

1. Subclass :class:`EventWarehouseProvider` (or implement the protocol).
2. Set :attr:`translated_query_key` to the dict key in
   ``hunt.translated_query`` that this provider consumes (e.g.
   ``"esql"`` for the Elasticsearch driver).
3. Raise :class:`HuntNotConfigured` for "skip me, no creds" — the
   scheduler treats this as a soft skip (logged at INFO once per
   missing-creds run).
4. Raise :class:`UnsupportedTranslation` for "hunt translated to a
   query language this provider doesn't speak" — the scheduler tries
   the next provider on the priority chain rather than failing the
   sweep.
5. Raise :class:`HuntExecutionError` (or let
   :class:`AirgapViolation` / :class:`ValueError` propagate) for hard
   errors. The scheduler logs and skips the ``last_run_at`` bump so
   the hunt is retried on the next tick.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from app.models.saved_hunt import SavedHunt


class HuntNotConfigured(RuntimeError):
    """Warehouse credentials / wiring not present for this provider.

    Treated as a soft-skip by the scheduler — no case opened, no
    ``last_run_at`` stamp, no log noise beyond a one-shot INFO.
    """


class UnsupportedTranslation(RuntimeError):
    """The hunt's translated_query doesn't carry a key this provider speaks.

    The scheduler walks the provider chain; this exception lets it
    skip to the next candidate without aborting the sweep.
    """


class HuntExecutionError(RuntimeError):
    """The provider tried to run but the warehouse returned an error.

    Wraps transport errors so the scheduler only needs one ``except``.
    """


@runtime_checkable
class EventWarehouseProvider(Protocol):
    """Pluggable warehouse driver — implements one async method."""

    #: Logical name of the provider (used in log lines + provider chain).
    name: str
    #: Key inside ``hunt.translated_query`` that this provider consumes.
    translated_query_key: str

    async def run_hunt(self, hunt: SavedHunt, *, max_rows: int = 500) -> int:
        """Execute ``hunt`` and return the hit count.

        Implementations must:

        * Raise :class:`UnsupportedTranslation` when the hunt has no
          query in the provider's translated_query_key.
        * Raise :class:`HuntNotConfigured` when credentials are
          missing.
        * Raise :class:`HuntExecutionError` (or let
          :class:`AirgapViolation` / :class:`ValueError` propagate)
          on hard execution errors.
        * Return 0 (not raise) when the warehouse runs cleanly but
          finds no hits.
        """


class _BaseProvider:
    """Convenience base — common helpers for the built-in drivers.

    Provider implementers can subclass this for the boilerplate
    (translated-query lookup, key validation) or just implement the
    :class:`EventWarehouseProvider` protocol directly. The two are
    interchangeable from the scheduler's point of view.
    """

    name: str = "unknown"
    translated_query_key: str = ""

    def _read_translated(self, hunt: SavedHunt) -> Any:
        """Extract this provider's translated-query string from ``hunt``.

        Raises :class:`UnsupportedTranslation` if the hunt was
        translated for a different warehouse (or never translated at
        all). The scheduler uses this signal to walk to the next
        provider candidate.
        """
        tq = hunt.translated_query
        if not isinstance(tq, dict):
            raise UnsupportedTranslation(f"{self.name}: hunt {hunt.id} has no translated_query dict")
        value = tq.get(self.translated_query_key)
        if not value:
            raise UnsupportedTranslation(f"{self.name}: hunt {hunt.id} has no '{self.translated_query_key}' translation")
        return value
