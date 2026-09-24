"""Event-warehouse provider protocol — Phase 4.5.

Every provider implements one async method, :meth:`run_hunt`, taking a
saved-hunt row plus the credentials of the tenant-owned warehouse
instance it should query, and returning the number of hits. The
scheduler does not care which warehouse answered — it only feeds the
hit count into the case-open callback.

Provider authors must:

1. Subclass :class:`EventWarehouseProvider` (or implement the protocol).
2. Set :attr:`translated_query_key` to the dict key in
   ``hunt.translated_query`` that this provider consumes (e.g.
   ``"esql"`` for the Elasticsearch driver).
3. Set :attr:`connector_types` to the connector type ids whose stored
   credentials this driver can use. The scheduler resolves one of them
   from the tenant's ``connectors`` rows and hands the decrypted result
   to :meth:`run_hunt`. Providers do **not** read process settings:
   doing so is what made every driver unreachable before, and it is
   also what made the warehouse global rather than per-tenant.
4. Raise :class:`HuntNotConfigured` for "skip me, no creds" — the
   scheduler treats this as a soft skip (logged at INFO once per
   missing-creds run).
5. Raise :class:`UnsupportedTranslation` for "hunt translated to a
   query language this provider doesn't speak" — the scheduler tries
   the next provider on the priority chain rather than failing the
   sweep.
6. Raise :class:`HuntExecutionError` (or let
   :class:`AirgapViolation` / :class:`ValueError` propagate) for hard
   errors. The scheduler logs and skips the ``last_run_at`` bump so
   the hunt is retried on the next tick.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from app.models.saved_hunt import SavedHunt

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    # ``credentials`` imports :class:`HuntNotConfigured` from this module, so
    # the runtime import would be circular. The annotation is only needed for
    # type checkers, which resolve it lazily under ``from __future__``.
    from .credentials import WarehouseCredentials


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
    #: Connector type ids this driver can take credentials from.
    connector_types: tuple[str, ...]

    async def run_hunt(
        self,
        hunt: SavedHunt,
        *,
        credentials: WarehouseCredentials,
        max_rows: int = 500,
    ) -> int:
        """Execute ``hunt`` against ``credentials`` and return the hit count.

        Implementations must:

        * Raise :class:`UnsupportedTranslation` when the hunt has no
          query in the provider's translated_query_key.
        * Raise :class:`HuntNotConfigured` when the resolved connector
          is missing a field the driver needs (e.g. an Elastic instance
          saved with neither an API key nor a username/password pair).
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
    connector_types: tuple[str, ...] = ()

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
