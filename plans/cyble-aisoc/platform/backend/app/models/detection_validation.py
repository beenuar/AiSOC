"""Persistence layer for the Continuous Detection Validation Agent (t2h-bas).

Each run of the validation agent replays a fixed catalogue of synthetic
OCSF events through the live `DetectionEngine` and records:

* which simulations fired ≥1 rule (and which rules);
* which simulations were *expected* to fire but didn't (drift);
* which MITRE ATT&CK techniques are now uncovered relative to baseline.

The `ValidationRun` row is the durable artefact the analyst can compare
across days — i.e. "yesterday simulation `bas-aws-create-key` fired rule
`aisoc-id-0008`, today it doesn't, here's the case the agent opened".

Stored as a single denormalized row per run rather than a per-simulation
child table because:

* a run is cheap (≤ a few hundred simulations) so a JSON blob is fine;
* the analyst reads runs whole, never one simulation at a time;
* we don't need to query "all runs that fired rule X" in SQL — that's
  what the per-run `simulation_results` blob is for, and the agent re-
  evaluates it in Python at compare-time anyway.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel


class ValidationRunStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ValidationRun(SQLModel, table=True):
    """One full BAS sweep over the catalogue of synthetic simulations."""

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="demo-tenant", index=True)
    status: ValidationRunStatus = Field(default=ValidationRunStatus.RUNNING, index=True)
    # Total number of simulations attempted in this run (including any
    # that errored). Useful as a sanity-check vs. baseline run sizes.
    simulations_run: int = 0
    # Counters that the dashboard reads directly — kept as columns (not
    # only in the JSON blob) so we can build a `/mitre-coverage` SQL
    # query without unpacking JSON on the fly.
    simulations_fired: int = 0
    simulations_silent: int = 0
    drift_count: int = 0
    coverage_regressions: int = 0
    # MITRE ATT&CK techniques (e.g. "T1110", "T1078.004") for which at
    # least one rule fired during the run. Used to compute coverage
    # regressions against the previous successful run for the same
    # tenant.
    mitre_covered: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    # Techniques where coverage *dropped* vs. the prior baseline — i.e.
    # the technique was covered yesterday and is uncovered today. Drives
    # the proactive case the agent opens.
    mitre_dropped: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    # Per-simulation result blob. Schema:
    #   { sim_id: {
    #       "name": str,
    #       "expected_techniques": [str, ...],
    #       "fired_rules": [str, ...],
    #       "fired_techniques": [str, ...],
    #       "ok": bool,            # at least one expected rule fired
    #       "drifted": bool,       # was OK in baseline run, not now
    #       "case_id": int | None,
    #   } }
    simulation_results: dict = Field(default_factory=dict, sa_column=Column(JSON))
    # Cases opened from drift/coverage regressions in this run. Stored
    # for easy navigation from the run detail view.
    cases_opened: list[int] = Field(default_factory=list, sa_column=Column(JSON))
    # Pointer to the previous successful run for the same tenant, so
    # the dashboard can show a clean diff link. Nullable because the
    # very first run for a tenant has no baseline.
    baseline_run_id: int | None = Field(default=None, index=True)
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    completed_at: datetime | None = None


__all__ = ["ValidationRun", "ValidationRunStatus"]
