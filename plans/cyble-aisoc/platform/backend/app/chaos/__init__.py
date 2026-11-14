"""Chaos engineering for agents (t6-chaos).

A small, deterministic fault-injection harness that exercises the
agent mesh under realistic failure modes:

* **LLM outage** — the next ``llm.complete*`` call raises a
  configurable exception instead of returning text.
* **Tool timeout** — the next ``tool.run`` for a matching name
  sleeps past its timeout window then raises.
* **Tool malformed response** — the next tool call returns
  syntactically valid but semantically broken output (e.g. missing
  required keys) so we can validate the agent's defensive parsing.
* **Tool slowness** — adds an artificial latency floor without
  necessarily failing.

The module is *active by config*: when no faults are scheduled, it
is a no-op and adds zero latency. Tests that exercise chaos
schedule a fault, run the orchestrator, and assert the surfaced
behaviour (case still progresses, no silent data loss, retry
budget honoured).

Why a separate module rather than monkeypatching at test time?
Production deployments can enable a "shadow chaos" mode that runs
fault injections in their pre-prod region before each release. The
config-driven harness lets ops trigger a controlled outage without
patching code in production.
"""
from app.chaos.engine import (
    ChaosEngine,
    ChaosFault,
    ChaosKind,
    ChaosResult,
    ChaosScenario,
    chaos_engine,
)

__all__ = [
    "ChaosEngine",
    "ChaosFault",
    "ChaosKind",
    "ChaosResult",
    "ChaosScenario",
    "chaos_engine",
]
