"""
Router orchestrator package (T2.2 — v8.0).

This package owns the *new* router-style LangGraph topology that replaces
the sequential ``auto_triage → phishing → identity → cloud → insider →
responder`` chain with a fan-out / join shape:

    auto_triage  ──►  classify signals  ──►  (phishing | identity | cloud | insider)
                                              fan-out via asyncio.gather
                                                          │
                                                          ▼
                                                       Join
                                                          │
                                                          ▼
                                                      Responder

The fan-out runs each triggered sub-agent concurrently; the Join node
merges every sub-agent's findings, verdict, and MITRE mappings into a
single :class:`InvestigationState` for the Responder.

The legacy sequential path stays available under the same package so the
production fleet can keep running it until eval-gate green: it is selected
when ``AISOC_AGENT_PARALLEL_TOPOLOGY`` resolves to off (0 / false /
disabled). Default is **on** for dev / CI / test; production overrides via
env until the wet-eval scoreboard confirms no regression.

Public surface
--------------

* :class:`RouterOrchestrator` — high-level façade (matches the shape of
  :class:`app.investigator.orchestrator.InvestigatorOrchestrator`).
* :func:`run_router_investigation` — one-shot convenience entry point.
* :func:`is_parallel_topology_enabled` — boolean accessor used by the
  eval harness, tests, and ``/healthz`` to surface the active topology.

Nothing in this package mutates the existing
``services/agents/app/investigator/`` package; the router is additive.
"""

from __future__ import annotations

from .router import (
    PARALLEL_TOPOLOGY_FLAG,
    RouterOrchestrator,
    classify_signals,
    is_parallel_topology_enabled,
    run_router_investigation,
)

__all__ = [
    "PARALLEL_TOPOLOGY_FLAG",
    "RouterOrchestrator",
    "classify_signals",
    "is_parallel_topology_enabled",
    "run_router_investigation",
]
