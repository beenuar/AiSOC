"""Result dataclasses for the Continuous Detection Validation Agent.

These are the in-memory shapes returned by ``DetectionValidationAgent.scan()``.
They are intentionally separate from the SQLModel `ValidationRun` persistence
shape — the agent computes a rich result object, then the agent persists a
compact JSON projection of it into `ValidationRun.simulation_results`.

We follow the same pattern as `app/agents/attack_path/models.py` (frozen-ish
dataclasses, no DB types here) so the agent can be unit-tested without a
session, and so callers like the API layer can serialize results with a
trivial ``dataclasses.asdict``.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Simulation:
    """A single synthetic attack scenario.

    `events` is a tuple of OCSF-shaped dicts that, when replayed through the
    `DetectionEngine`, are *expected* to trigger at least one of the rules
    matching `expected_rule_ids`. The catalogue lives in `simulations.py`.

    `expected_techniques` is the MITRE ATT&CK technique set the simulation
    represents — used for the coverage-regression report regardless of
    which exact rule fires.
    """

    sim_id: str
    name: str
    description: str
    events: tuple[dict, ...]
    expected_rule_ids: tuple[str, ...]
    expected_techniques: tuple[str, ...]


@dataclass
class SimulationResult:
    """Outcome of replaying one `Simulation` through the live engine."""

    sim_id: str
    name: str
    expected_rule_ids: tuple[str, ...]
    expected_techniques: tuple[str, ...]
    # Rule IDs that actually fired on any event in the simulation.
    fired_rule_ids: tuple[str, ...]
    # MITRE techniques covered by the rules that fired (deduped).
    fired_techniques: tuple[str, ...]
    # True iff at least one of the expected rules fired. We use "at least
    # one" rather than "all" because a simulation often has multiple
    # candidate rules (e.g. a generic + a tuned variant) and the analyst
    # only needs one to fire to count as covered.
    ok: bool
    # True iff this simulation was OK in the baseline run and is not OK now
    # — populated by the agent after comparing against the baseline.
    drifted: bool = False
    # Case opened for this drift (if any). Populated by the agent after
    # case creation; None for healthy runs.
    case_id: int | None = None

    def to_json(self) -> dict:
        """Serialize for `ValidationRun.simulation_results`."""
        return {
            "name": self.name,
            "expected_rule_ids": list(self.expected_rule_ids),
            "expected_techniques": list(self.expected_techniques),
            "fired_rule_ids": list(self.fired_rule_ids),
            "fired_techniques": list(self.fired_techniques),
            "ok": self.ok,
            "drifted": self.drifted,
            "case_id": self.case_id,
        }


@dataclass
class ValidationScanResult:
    """Top-level result returned by ``DetectionValidationAgent.scan()``."""

    run_id: int
    baseline_run_id: int | None
    simulations_run: int
    simulations_fired: int
    simulations_silent: int
    drift_count: int
    coverage_regressions: int
    mitre_covered: list[str] = field(default_factory=list)
    mitre_dropped: list[str] = field(default_factory=list)
    simulations: list[SimulationResult] = field(default_factory=list)
    cases_opened: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Render to a JSON-serializable dict for the API response."""
        return {
            "run_id": self.run_id,
            "baseline_run_id": self.baseline_run_id,
            "simulations_run": self.simulations_run,
            "simulations_fired": self.simulations_fired,
            "simulations_silent": self.simulations_silent,
            "drift_count": self.drift_count,
            "coverage_regressions": self.coverage_regressions,
            "mitre_covered": list(self.mitre_covered),
            "mitre_dropped": list(self.mitre_dropped),
            "cases_opened": list(self.cases_opened),
            "simulations": [
                {"sim_id": s.sim_id, **s.to_json()} for s in self.simulations
            ],
        }


__all__ = [
    "Simulation",
    "SimulationResult",
    "ValidationScanResult",
]
