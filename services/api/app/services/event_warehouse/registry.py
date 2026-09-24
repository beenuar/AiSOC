"""Provider registry — which warehouse driver runs a given hunt.

Selection rules
~~~~~~~~~~~~~~~

1. If the hunt's :attr:`SavedHunt.warehouse_provider` field is set *and*
   points at a known provider name, that provider is the only one tried.
   This is the per-hunt override surface (the model field will land in a
   follow-up migration; see :func:`_select_provider_name`).
2. Otherwise we walk :data:`SUPPORTED_PROVIDERS` in priority order and pick
   the first provider that can both (a) read a translation out of the
   hunt and (b) take credentials from a connector type the tenant has
   actually enabled.
3. If nothing matches we raise :class:`UnsupportedTranslation`, whose
   message distinguishes "this hunt was never translated" from "you have
   not connected a SIEM we can run it against".

Why rule 2 needs the tenant's connected types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Selection used to consider only the translation. The natural-language
translator emits ES|QL, SPL *and* KQL for every question, so the ``esql``
key was always present and the Elasticsearch driver was always chosen —
including for a tenant whose only SIEM is Splunk. Implementing the Splunk
driver would not have helped on its own, because it could never have been
reached. Selection must be driven by what the tenant connected, and the
translation is the second filter rather than the first.
"""

from __future__ import annotations

import logging

from app.models.saved_hunt import SavedHunt

from .base import EventWarehouseProvider, UnsupportedTranslation
from .elasticsearch import ElasticsearchProvider
from .splunk import SplunkProvider

logger = logging.getLogger(__name__)

# Priority decides only which backend wins when a tenant has connected more
# than one. Elasticsearch leads because ES|QL is the translator's primary
# dialect and the driver is the oldest.
#
# The Chronicle scaffold that used to sit here was removed rather than
# ported: it read ``hunt.translated_query["udm"]``, nothing in the
# repository emits UDM, and it gated on two settings that were never fields
# on ``Settings``. It could not be selected and could not run, while
# ``available_providers()`` reported it as a supported warehouse. Adding a
# real one is a `register_provider` call plus a UDM translator.
SUPPORTED_PROVIDERS: list[EventWarehouseProvider] = [
    ElasticsearchProvider(),
    SplunkProvider(),
]


def register_provider(provider: EventWarehouseProvider) -> None:
    """Append a custom provider to the registry.

    Exposed for tests and downstream forks. The scheduler picks up the
    new provider on the next sweep — there's no need to restart the
    worker.
    """
    SUPPORTED_PROVIDERS.append(provider)


def available_providers() -> list[str]:
    """Names of every provider currently in the registry."""
    return [p.name for p in SUPPORTED_PROVIDERS]


def candidate_connector_types() -> tuple[str, ...]:
    """Every connector type any registered provider can take credentials from.

    The scheduler asks the database once per hunt which of these the tenant
    has enabled, rather than issuing one query per provider.
    """
    seen: list[str] = []
    for provider in SUPPORTED_PROVIDERS:
        for connector_type in getattr(provider, "connector_types", ()):
            if connector_type not in seen:
                seen.append(connector_type)
    return tuple(seen)


def _select_provider_name(hunt: SavedHunt) -> str | None:
    """Read the per-hunt provider override, if any.

    The :attr:`SavedHunt.warehouse_provider` column ships in a future
    migration; until then we return ``None`` and the priority chain
    runs unmodified. The lookup is wrapped in ``getattr`` so this
    module loads cleanly against the current model schema.
    """
    return getattr(hunt, "warehouse_provider", None)


def _has_translation(provider: EventWarehouseProvider, hunt: SavedHunt) -> bool:
    tq = hunt.translated_query if isinstance(hunt.translated_query, dict) else {}
    return bool(tq.get(provider.translated_query_key))


def resolve_provider(
    hunt: SavedHunt,
    *,
    connected_types: set[str],
) -> EventWarehouseProvider:
    """Return the provider that should run ``hunt``.

    ``connected_types`` is the set of connector types the hunt's tenant has
    enabled, from :func:`.credentials.connected_warehouse_types`. Passing an
    empty set is meaningful — it is how "this tenant has connected no SIEM"
    reaches the caller as a message rather than as a silent zero.

    Raises :class:`UnsupportedTranslation` when nothing in the registry can
    answer the hunt. The scheduler treats this as a soft skip, so the
    message has to carry the reason.
    """
    override = _select_provider_name(hunt)
    if override:
        for provider in SUPPORTED_PROVIDERS:
            if provider.name == override:
                return provider
        raise UnsupportedTranslation(
            f"resolve_provider: hunt {hunt.id} pins warehouse_provider={override!r} but no such provider is registered"
        )

    translatable = [p for p in SUPPORTED_PROVIDERS if _has_translation(p, hunt)]
    if not translatable:
        tq = hunt.translated_query if isinstance(hunt.translated_query, dict) else {}
        raise UnsupportedTranslation(
            f"resolve_provider: hunt {hunt.id} has no translated query for any registered provider " f"(have keys: {sorted(tq.keys())})"
        )

    for provider in translatable:
        if connected_types.intersection(provider.connector_types):
            return provider

    wanted = sorted({t for p in translatable for t in p.connector_types})
    raise UnsupportedTranslation(
        f"resolve_provider: hunt {hunt.id} translates for {sorted(p.name for p in translatable)} "
        f"but this tenant has no enabled connector of type {wanted} — connect one from the console"
    )
