"""aisoc-sandbox: run an AiSOC agent investigation offline in under 30 seconds.

This package is the quickest possible on-ramp to AiSOC: no Docker, no
Postgres / Kafka / Redis, no API key, no network — `aisoc-sandbox demo`
walks one alert fixture through a Detect → Triage → Hunt → Respond
agent funnel and prints a step-by-step Investigation Ledger to stdout.

It is a deterministic, in-memory simulator of the production stack at
[`services/agents/`](https://github.com/beenuar/AiSOC/tree/main/services/agents).
The shape of the ledger, the funnel stages, the decision metadata, and
the recommended actions all mirror what the real four-agent system in
the monorepo emits. The simulator is intentionally NOT the production
graph: the production graph requires Postgres + Kafka + an LLM API
key, and a 30-second offline demo cannot afford any of those.

When you're ready to run the real stack: `pnpm aisoc:demo`.

Public entry points:

  - :class:`Investigation`  — one investigation run.
  - :class:`Ledger`         — the step-by-step record.
  - :func:`load_scenario`   — load a built-in or user-supplied scenario.
  - :func:`run_investigation` — high-level orchestrator (used by the CLI).
"""

from __future__ import annotations

from .investigation import Investigation, run_investigation
from .ledger import Ledger, LedgerStep
from .scenarios import Scenario, available_scenarios, load_scenario

__all__ = [
    "Investigation",
    "Ledger",
    "LedgerStep",
    "Scenario",
    "available_scenarios",
    "load_scenario",
    "run_investigation",
]

__version__ = "0.1.0"
