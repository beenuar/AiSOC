"""Pre-fetched ContextBundle for sub-agents (T2.1).

Sub-agents historically called graph / memory / TI tools as their *primary*
discovery step, which serialised four to six round-trips on the critical path
of every investigation. The :class:`ContextBundle` is built once, before the
fan-out to sub-agents, and carries:

* the entity neighbourhood walked from the alert (configurable depth, default 2),
* historical similar-case verdicts pulled from ``aisoc_institutional_memory``,
* peer-entity UEBA baselines for each principal in the alert,
* threat-intel matches for each IOC.

Tools the sub-agents still call become *enrichments* of the bundle, not
primary discovery.

See ``services/agents/tests/test_context_bundle.py`` for the latency gate
(p95 < 5s across the 200-incident eval set).
"""

from .bundle import (
    ContextBundle,
    ContextBundleBuilder,
    EntityNeighborhood,
    EntityRef,
    HistoricalCase,
    ThreatIntelMatch,
    UEBABaseline,
    build_context_bundle,
    extract_entities,
)

__all__ = [
    "ContextBundle",
    "ContextBundleBuilder",
    "EntityNeighborhood",
    "EntityRef",
    "HistoricalCase",
    "ThreatIntelMatch",
    "UEBABaseline",
    "build_context_bundle",
    "extract_entities",
]
