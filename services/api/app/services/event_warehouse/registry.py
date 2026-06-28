"""Provider registry — Phase 4.5.

Encapsulates the (a) provider list, (b) priority order, and (c)
fallthrough policy. The hunt scheduler calls :func:`resolve_provider`
with a hunt and gets back the provider that can actually run it.

Selection rules
~~~~~~~~~~~~~~~

1. If the hunt's :attr:`SavedHunt.warehouse_provider` field is set
   *and* points at a known provider name, that provider is the only
   one tried. This is the per-hunt override surface (Phase 4.5
   extension — the model field will land in a follow-up migration;
   see ``select_provider_name``).
2. Otherwise we walk :data:`SUPPORTED_PROVIDERS` in priority order
   and pick the first provider whose ``translated_query_key`` is
   present in the hunt's ``translated_query`` dict.
3. If nothing matches we raise :class:`UnsupportedTranslation`, which
   the scheduler logs and treats as a soft skip (the hunt was never
   translated, or was translated for a warehouse we don't support).
"""

from __future__ import annotations

import logging

from app.models.saved_hunt import SavedHunt

from .base import EventWarehouseProvider, UnsupportedTranslation
from .chronicle import ChronicleProvider
from .elasticsearch import ElasticsearchProvider
from .splunk import SplunkProvider

logger = logging.getLogger(__name__)

# Priority is deliberate:
#   * Elasticsearch first because it's the production-grade driver and
#     the historical default for AiSOC (matches the ES|QL endpoint).
#   * Splunk + Chronicle behind it so the scheduler keeps working
#     against an ES backend even when a hunt also has SPL / UDM
#     translations attached.
SUPPORTED_PROVIDERS: list[EventWarehouseProvider] = [
    ElasticsearchProvider(),
    SplunkProvider(),
    ChronicleProvider(),
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


def _select_provider_name(hunt: SavedHunt) -> str | None:
    """Read the per-hunt provider override, if any.

    The :attr:`SavedHunt.warehouse_provider` column ships in a future
    migration; until then we return ``None`` and the priority chain
    runs unmodified. The lookup is wrapped in ``getattr`` so this
    module loads cleanly against the current model schema.
    """
    return getattr(hunt, "warehouse_provider", None)


def resolve_provider(hunt: SavedHunt) -> EventWarehouseProvider:
    """Return the provider that should run ``hunt``.

    Raises :class:`UnsupportedTranslation` when nothing in the
    registry can answer the hunt — the scheduler treats this as a
    soft skip.
    """
    override = _select_provider_name(hunt)
    if override:
        for provider in SUPPORTED_PROVIDERS:
            if provider.name == override:
                return provider
        raise UnsupportedTranslation(
            f"resolve_provider: hunt {hunt.id} pins warehouse_provider={override!r} but no such provider is registered"
        )

    tq = hunt.translated_query if isinstance(hunt.translated_query, dict) else {}
    for provider in SUPPORTED_PROVIDERS:
        if provider.translated_query_key in tq and tq[provider.translated_query_key]:
            return provider

    raise UnsupportedTranslation(
        f"resolve_provider: hunt {hunt.id} has no translated query for any registered provider (have keys: {sorted(tq.keys())})"
    )
