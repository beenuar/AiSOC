"""The event lake as a scheduled-hunt backend — wave 2, Phase 5.2.

Why this provider exists
------------------------
Until now every registered provider took credentials from a connector the
tenant had enabled, and `resolve_provider` required
``connected_types.intersection(provider.connector_types)`` to be non-empty.
A tenant that has connected **no** SIEM therefore matched nothing, the
resolver raised `UnsupportedTranslation`, and `_execute_hunt` returned `0`.

That zero is the problem. It is indistinguishable from "your hunt ran and
found nothing", and it was the answer on every deployment whose data lives
in AiSOC's own lake rather than in somebody else's SIEM — which is the
default deployment. The lake is not a third-party warehouse a tenant may or
may not have bought; it is the store AiSOC fills from its own connectors, so
a scheduled hunt should be able to run there.

Selection, and why `connector_types` is empty
---------------------------------------------
This provider declares no connector types, because there is no connector to
resolve: the lake's address is deployment configuration, the same for every
tenant, and `execute_lake_query` already holds it. The registry treats an
empty `connector_types` as "needs no connected warehouse" and allows such a
provider to be selected on its translation alone. It is deliberately **last**
in the priority chain: a tenant who has connected a SIEM has years of history
AiSOC never ingested, and answering from the lake instead would be a quieter,
narrower answer to the same question.

Tenant scoping
--------------
Through `compile_hunt`, which binds `tenant_id = %(tenant_id)s` structurally
into the WHERE clause and asserts the predicate survived before returning —
not through `rewrite_for_tenant`, which exists to constrain untrusted
*operator* SQL and cannot help a caller who forgets to call it. Values are
bound as parameters; no part of the hunt becomes query text.

What a partial answer looks like
--------------------------------
`compile_hunt` reports `unsupported_fields` for intents the lake schema
cannot express. Those are logged rather than swallowed, because a hunt that
ran with two of its four conditions dropped found fewer hits than the
analyst asked about, and reporting that count as the hunt's result would be
a false negative wearing a number.
"""

from __future__ import annotations

import logging
from typing import Any

from app.models.saved_hunt import SavedHunt

from .base import HuntExecutionError, UnsupportedTranslation, WarehouseCredentials, _BaseProvider

logger = logging.getLogger(__name__)

#: The window a scheduled lake hunt looks back over, in hours.
#:
#: Matches the saved-hunt run route's default rather than introducing a
#: second number: a hunt that returns different counts depending on whether
#: an analyst pressed Run or the scheduler fired is a hunt nobody can
#: reason about.
DEFAULT_LOOKBACK_HOURS = 24


class LakeProvider(_BaseProvider):
    """Run a saved hunt against this deployment's own event lake."""

    name = "lake"
    #: The translator emits `intents` beside `esql` / `spl` / `kql`. The lake
    #: compiler consumes the structured form, which is the whole reason no
    #: hunt text reaches ClickHouse.
    translated_query_key = "intents"
    #: Deliberately empty — see the module header. This is the signal the
    #: registry reads to allow selection with no connected warehouse.
    connector_types: tuple[str, ...] = ()

    async def run_hunt(
        self,
        hunt: SavedHunt,
        *,
        credentials: WarehouseCredentials | None = None,
        max_rows: int = 500,
    ) -> int:
        """Compile the hunt's intents and count what the lake returns.

        ``credentials`` is accepted and ignored so the signature matches the
        protocol every other provider implements; the scheduler passes
        ``None`` for a provider that declares no connector types.
        """
        intents = self._read_translated(hunt)

        # Imported here rather than at module scope: `lake_hunt` pulls in the
        # vendored translator and `clickhouse` opens a driver, and this module
        # is imported by the registry at API start-up on every profile —
        # including CORE, where the lake is a `full`-profile service. A
        # deployment without ClickHouse must still be able to list providers.
        from app.db.clickhouse import execute_lake_query
        from app.services.lake_hunt import HuntCompileError, compile_hunt

        try:
            compiled = compile_hunt(
                _as_intents(intents),
                tenant_id=str(hunt.tenant_id),
                hours=DEFAULT_LOOKBACK_HOURS,
                limit=max_rows,
            )
        except HuntCompileError as exc:
            # Not a hard error: this hunt asks something the lake schema
            # cannot express, which is the same class as "translated for a
            # warehouse I do not speak".
            raise UnsupportedTranslation(f"lake: hunt {hunt.id} does not compile to a lake query ({exc})") from exc

        if compiled.unsupported_fields:
            # Logged, never silently dropped. A hunt that ran with conditions
            # missing found fewer hits than was asked for, and publishing that
            # count without the caveat is a false negative with a number on it.
            logger.info(
                "hunt_scheduler.lake_partial hunt_id=%s dropped=%s",
                hunt.id,
                ",".join(sorted(compiled.unsupported_fields)),
            )

        try:
            result = await execute_lake_query(compiled.sql, params=compiled.params)
        except Exception as exc:  # noqa: BLE001 — one exception type for the scheduler
            raise HuntExecutionError(f"lake: hunt {hunt.id} failed against the event lake ({exc})") from exc

        return int(getattr(result, "row_count", 0) or 0)


def _as_intents(value: Any) -> Any:
    """Accept the intents in either shape the translator envelope stores.

    `translated_query` is JSONB, so a round trip through Postgres turns the
    translator's `QueryIntents` into a plain dict. `compile_hunt` documents
    that it takes "anything with the same attributes", which a dict is not —
    so a dict is wrapped in a thin attribute view rather than being handed
    over to fail on the first `getattr`.
    """
    if isinstance(value, dict):
        return _IntentsView(value)
    return value


class _IntentsView:
    """Attribute access over a JSONB-round-tripped intents dict."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        # `compile_hunt` reads optional intents and treats a missing one as
        # absent, so returning None for an unknown key is the contract it
        # already expects — raising here would turn a hunt that simply did
        # not mention a field into a failed run.
        return self._data.get(name)
