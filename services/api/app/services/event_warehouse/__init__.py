"""Pluggable event-warehouse providers for the hunt scheduler.

Phase 4.5 / Milestone 1F. Before this module landed, the hunt
scheduler hard-coded Elasticsearch as the only target — every saved
hunt had to translate to ES|QL, and operators on a Splunk / Chronicle /
Sumo backend couldn't use the scheduler at all.

The provider interface here keeps the scheduler's call shape stable
(``run_hunt(hunt) -> int hits``) while letting the platform grow new
warehouse drivers without touching the scheduler. Each provider:

* Declares its translated-query schema (the ``hunt.translated_query``
  dict key it consumes — ``"esql"`` for ES, ``"spl"`` for Splunk,
  ``"yara_l"`` for Chronicle, etc.).
* Encapsulates its own credential lookup and SSRF/air-gap guards.
* Returns a ``hit_count`` integer the scheduler can feed into the
  case-open callback unchanged.

Today the registry ships only the Elasticsearch driver (which simply
delegates to the existing :mod:`app.services.esql_runner`). The
Splunk / Chronicle / Sumo drivers are placeholder stubs that ship as
``NotImplemented`` but raise the right exception type so adding them
is a one-PR change. The scheduler's selection logic is documented
in :func:`resolve_provider`.
"""

from __future__ import annotations

from .base import (
    EventWarehouseProvider,
    HuntExecutionError,
    HuntNotConfigured,
    UnsupportedTranslation,
)
from .registry import (
    SUPPORTED_PROVIDERS,
    available_providers,
    register_provider,
    resolve_provider,
)

__all__ = [
    "SUPPORTED_PROVIDERS",
    "EventWarehouseProvider",
    "HuntExecutionError",
    "HuntNotConfigured",
    "UnsupportedTranslation",
    "available_providers",
    "register_provider",
    "resolve_provider",
]
