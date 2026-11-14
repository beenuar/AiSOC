"""Intel-driven retro-hunts (gap-closure Phase 8.1).

A retro-hunt answers "have we ever seen this" when somebody else publishes an
indicator. Four modules, split along the lines that let each be tested on its
own:

``ioc_fields``
    Which lake column an indicator of each type is actually recorded in,
    annotated with the OCSF path the production lake writer reads to fill it.
``intel_types``
    Translation from a feed's own vocabulary to the one the platform sweeps
    with, refusing an unknown type by name rather than defaulting it.
``sweep``
    The aggregate query against the lake and the Phase 4 federated SIEM
    search, with the budget the warehouse enforces.
``service``
    Budget, dedup and the single alert an indicator opens for a tenant.
"""

from app.services.retro_hunt.intel_types import route_feed_type
from app.services.retro_hunt.ioc_fields import SWEEPABLE_TYPES, UNMAPPED_TYPES, mapping_for
from app.services.retro_hunt.service import IntelIndicator, TenantSweepReport, sweep_tenant
from app.services.retro_hunt.sweep import SweepOutcome, sweep_indicator

__all__ = [
    "SWEEPABLE_TYPES",
    "UNMAPPED_TYPES",
    "IntelIndicator",
    "SweepOutcome",
    "TenantSweepReport",
    "mapping_for",
    "route_feed_type",
    "sweep_indicator",
    "sweep_tenant",
]
