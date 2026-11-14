"""Third-party / supply-chain risk fusion agent (t3f-supply-chain).

Proactive, scheduler-driven sub-agent that fuses three Cyble-native
signal sources — ``cti.darkweb_search``, ``cti.brand_intel``,
``cti.asm_lookup``, ``cti.vuln_intel`` — against a tenant's declared
third-party footprint and materialises:

1.  :class:`VendorRiskSignal` rows — append-only audit log of every
    signal the agent observed per sweep.
2.  Threat-graph nodes/edges — ``NodeType.VENDOR`` plus
    ``EdgeType.DEPENDS_ON`` from each affected asset/user back to its
    vendor, keeping the graph as the canonical relationship store.
3.  Proactive :class:`Case` rows — opened when a vendor's recent
    risk score crosses ``settings.supply_chain_case_open_threshold``.

Design echoes :class:`ExposureAgent`: not a :class:`BaseAgent` subclass
(no case ownership), per-tenant instances, deterministic re-run safe,
and writes traces against the case it opens.
"""
from app.agents.supply_chain.agent import SupplyChainAgent
from app.agents.supply_chain.models import (
    SupplyChainSweepResult,
    VendorFinding,
)

__all__ = [
    "SupplyChainAgent",
    "SupplyChainSweepResult",
    "VendorFinding",
]
