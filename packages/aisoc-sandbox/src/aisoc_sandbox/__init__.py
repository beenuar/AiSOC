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
graph: the production graph requires Postgres + Kafka + a model, and a
30-second offline demo cannot afford any of those.

What it shows, and what it refuses to
-------------------------------------
The sandbox exists to show you the *ledger format* and the funnel. It
is not a triage engine and does not pretend to be one, which is a
sharper line than it sounds: everything it prints is either arithmetic
over the events in the scenario (see :mod:`aisoc_sandbox.signals` —
impossible travel is a distance over an elapsed time, so it is computed
and the answer follows the events) or an explicit
:class:`~aisoc_sandbox.ledger.NotComputed` naming what it could not
work out and why. It emits no confidence score, no automation tier and
no verdict, because it has no basis for any of the three.

When you're ready to run the real stack: `pnpm aisoc:demo`.

Public entry points:

  - :class:`Investigation`  — one investigation run.
  - :class:`Ledger`         — the step-by-step record.
  - :class:`NotComputed`    — a value this run did not compute, and why.
  - :func:`compute_signals` — what can be derived from a list of events.
  - :func:`load_scenario`   — load a built-in or user-supplied scenario.
  - :func:`run_investigation` — high-level orchestrator (used by the CLI).
"""

from __future__ import annotations

from .investigation import EvidenceNarrator, Investigation, run_investigation
from .ledger import SYNTHETIC_NOTICE, Ledger, LedgerStep, NotComputed
from .scenarios import Scenario, available_scenarios, load_scenario
from .signals import Signal, compute_signals, technique_support

__all__ = [
    "SYNTHETIC_NOTICE",
    "EvidenceNarrator",
    "Investigation",
    "Ledger",
    "LedgerStep",
    "NotComputed",
    "Scenario",
    "Signal",
    "available_scenarios",
    "compute_signals",
    "load_scenario",
    "run_investigation",
    "technique_support",
]

__version__ = "0.1.0"
