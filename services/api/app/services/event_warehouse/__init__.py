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

The registry ships two live drivers: Elasticsearch (ES|QL, delegating to
:mod:`app.services.esql_runner`) and Splunk (SPL, delegating to
:mod:`app.services.spl_runner`). Both take their credentials from the
tenant's own connector row rather than from process settings — see
:mod:`app.services.event_warehouse.credentials` for why that distinction
is the whole point of this package. The scheduler's selection logic is
documented in :func:`resolve_provider`.
"""

from __future__ import annotations

from .base import (
    EventWarehouseProvider,
    HuntExecutionError,
    HuntNotConfigured,
    UnsupportedTranslation,
)
from .credentials import (
    WarehouseCredentials,
    connected_warehouse_types,
    resolve_tenant_warehouse,
)
from .registry import (
    SUPPORTED_PROVIDERS,
    available_providers,
    candidate_connector_types,
    register_provider,
    resolve_provider,
)

__all__ = [
    "SUPPORTED_PROVIDERS",
    "EventWarehouseProvider",
    "HuntExecutionError",
    "HuntNotConfigured",
    "UnsupportedTranslation",
    "WarehouseCredentials",
    "available_providers",
    "candidate_connector_types",
    "connected_warehouse_types",
    "register_provider",
    "resolve_provider",
    "resolve_tenant_warehouse",
]
