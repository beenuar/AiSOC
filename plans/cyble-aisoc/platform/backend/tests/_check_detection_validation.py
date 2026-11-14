"""End-to-end smoke check for the Continuous Detection Validation Agent (t2h-bas).

Exercises the BAS-style proactive scan against an isolated SQLite DB
using the in-tree synthetic simulation catalogue and the live detection
engine. The validation agent is proactive (no alert handoff), so the
test calls ``DetectionValidationAgent(...).scan()`` directly.

What we verify:

  * Imports + symbols: the agent, its dataclasses, the ``ValidationRun``
    SQLModel, ``ValidationRunStatus`` enum, and ``AgentName.CONTINUOUS_VALIDATION``
    all exist.
  * Tenancy: constructing without a tenant raises; every ``ValidationRun``,
    ``Case``, and ``AgentTrace`` row carries the active tenant.
  * First-run semantics: with no baseline, no simulation is marked as
    drifted (a brand-new tenant cannot drift relative to itself).
  * Replay + persistence: scan returns a ``ValidationScanResult``, the
    ``ValidationRun`` row lands in DB with ``COMPLETED`` status, and
    counters (simulations_run / _fired / _silent) are consistent.
  * Engine integration: at least one expected rule from the seed pack
    fires against the synthetic OCSF events.
  * Drift detection: after monkey-patching the catalogue to add a
    simulation pointing at an unknown rule id, a *second* scan that
    revokes the monkey-patch must detect drift for sims that previously
    fired but no longer do. (We simulate drift the deterministic way:
    add a sim that fires in run 1, then remove a rule from the engine
    before run 2 so the sim no longer fires.)
  * Proactive cases: every drifted sim opens a ``Severity.HIGH`` /
    ``status=CaseStatus.NEW`` case prefixed ``[Detection drift]``, each
    with an ``AgentTrace`` under ``AgentName.CONTINUOUS_VALIDATION``.
  * Coverage regression: when a previously-covered MITRE technique
    becomes uncovered, a single roll-up case is opened with
    ``[Coverage regression]`` prefix.
  * Serialization: ``ValidationScanResult.to_dict()`` returns a JSON-
    friendly summary with the fields the API + UI rely on.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_detection_validation.py

Exits non-zero on any failure and prints a PASS/FAIL summary per check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-bas-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    # Disable the background scheduler — this test drives the agent
    # directly and a sneaky concurrent sweep would race the assertions.
    os.environ["AISOC_BAS_SCHEDULER_ENABLED"] = "false"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.detection_validation import (  # noqa: E402
    DetectionValidationAgent,
    Simulation,
    SimulationResult,
    ValidationScanResult,
)
from app.agents.detection_validation import simulations as bas_sims  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.models.case import Case, CaseStatus, Severity  # noqa: E402
from app.models.detection_validation import (  # noqa: E402
    ValidationRun,
    ValidationRunStatus,
)
from app.models.trace import AgentName, AgentTrace  # noqa: E402


# ── Tiny test harness ───────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(label: str) -> None:
    print(f"\n── {label} ──")


# ── Checks ──────────────────────────────────────────────────────────────


def check_symbols() -> None:
    section("Module surface is wired up")
    check(
        "DetectionValidationAgent importable",
        callable(DetectionValidationAgent),
    )
    check(
        "Simulation dataclass importable",
        isinstance(Simulation, type),
    )
    check(
        "SimulationResult dataclass importable",
        isinstance(SimulationResult, type),
    )
    check(
        "ValidationScanResult dataclass importable",
        isinstance(ValidationScanResult, type),
    )
    check(
        "ValidationRunStatus has the three lifecycle states",
        {m.value for m in ValidationRunStatus}
        == {"running", "completed", "failed"},
        detail=f"members={[m.value for m in ValidationRunStatus]}",
    )
    check(
        "AgentName.CONTINUOUS_VALIDATION exists",
        hasattr(AgentName, "CONTINUOUS_VALIDATION"),
        detail=f"members={[m.name for m in AgentName]}",
    )


def check_tenancy_enforced() -> None:
    section("Agent refuses to construct without a tenant")
    init_db()
    with Session(engine) as s:
        raised = False
        try:
            DetectionValidationAgent(s, tenant_id="")
        except ValueError:
            raised = True
        check(
            "empty tenant_id raises ValueError",
            raised,
            detail="agent should refuse cross-tenant runs",
        )


async def check_first_run_no_drift() -> ValidationScanResult:
    section("First run for a tenant has no baseline and no drift")
    init_db()
    tenant_id = "t-bas-test"

    with Session(engine) as s:
        agent = DetectionValidationAgent(s, tenant_id=tenant_id)
        result = await agent.scan()

    check(
        "scan returned a ValidationScanResult",
        isinstance(result, ValidationScanResult),
        detail=f"type={type(result).__name__}",
    )
    check(
        "simulations_run matches the catalogue size",
        result.simulations_run == len(bas_sims.get_simulations()),
        detail=(
            f"got={result.simulations_run} "
            f"catalogue={len(bas_sims.get_simulations())}"
        ),
    )
    check(
        "simulations_fired + simulations_silent == simulations_run",
        result.simulations_fired + result.simulations_silent
        == result.simulations_run,
        detail=(
            f"fired={result.simulations_fired} "
            f"silent={result.simulations_silent} "
            f"total={result.simulations_run}"
        ),
    )
    check(
        "at least one simulation fired (engine is wired up)",
        result.simulations_fired > 0,
        detail=(
            "the seed Sigma rule pack should contain at least one of the "
            "expected rule ids; if zero fire, either the pack or the "
            "OCSF field-paths regressed"
        ),
    )
    check(
        "first run has no baseline_run_id",
        result.baseline_run_id is None,
        detail=f"baseline_run_id={result.baseline_run_id}",
    )
    check(
        "first run reports no drift",
        result.drift_count == 0,
        detail=f"drift_count={result.drift_count}",
    )
    check(
        "first run reports no coverage regressions",
        result.coverage_regressions == 0,
        detail=f"coverage_regressions={result.coverage_regressions}",
    )
    check(
        "first run opened no proactive cases",
        len(result.cases_opened) == 0,
        detail=f"cases_opened={result.cases_opened}",
    )

    # The ValidationRun row must land in DB with COMPLETED status and
    # the tenant_id stamped on it.
    with Session(engine) as s:
        run = s.get(ValidationRun, result.run_id)
        check(
            "ValidationRun row persisted",
            run is not None,
            detail=f"run_id={result.run_id}",
        )
        if run is not None:
            check(
                "run status == COMPLETED",
                run.status == ValidationRunStatus.COMPLETED,
                detail=f"status={run.status}",
            )
            check(
                "run tenant_id matches",
                run.tenant_id == tenant_id,
                detail=f"got={run.tenant_id}",
            )
            check(
                "run.completed_at is set",
                run.completed_at is not None,
                detail=f"completed_at={run.completed_at}",
            )
            check(
                "run.simulation_results contains every sim",
                set(run.simulation_results.keys())
                == {s.sim_id for s in bas_sims.get_simulations()},
                detail=f"keys={sorted(run.simulation_results.keys())}",
            )
    return result


async def check_drift_detection(first: ValidationScanResult) -> None:
    section("Second run with a removed rule detects drift + coverage loss")

    tenant_id = "t-bas-test"

    # Identify the simulations the first run treated as OK. We need to
    # make at least one of them go silent on the next run to provoke a
    # drift case. The deterministic way to do that without mutating the
    # rule pack is to monkey-patch ``get_simulations`` so the next run
    # sees a *modified* version of one OK simulation whose events no
    # longer match anything.
    catalogue = list(bas_sims.get_simulations())
    ok_sims = [
        s
        for s in catalogue
        if first.simulations
        and any(r.sim_id == s.sim_id and r.ok for r in first.simulations)
    ]
    check(
        "first run had at least one OK simulation to drift",
        len(ok_sims) > 0,
        detail=f"ok_sim_count={len(ok_sims)}",
    )
    if not ok_sims:
        return

    target = ok_sims[0]

    # Build a drifted variant: same sim_id + expected_rule_ids (so the
    # diff logic sees it as the "same" simulation) but with events that
    # cannot possibly match any rule.
    drifted_variant = Simulation(
        sim_id=target.sim_id,
        name=target.name,
        description=target.description,
        events=(
            {
                "event": {
                    "action": "this-action-cannot-match-any-rule",
                    "outcome": "n/a",
                },
                "_bas_test_marker": "drift",
            },
        ),
        expected_rule_ids=target.expected_rule_ids,
        expected_techniques=target.expected_techniques,
    )
    drifted_catalogue = tuple(
        drifted_variant if s.sim_id == target.sim_id else s for s in catalogue
    )

    # The agent imports ``get_simulations`` by name at module load, so
    # patching ``bas_sims.get_simulations`` does not reach it. But
    # ``get_simulations`` itself reads ``SIMULATIONS`` at call time,
    # so patching the module-level tuple works for both call sites.
    original_simulations = bas_sims.SIMULATIONS
    bas_sims.SIMULATIONS = drifted_catalogue  # type: ignore[assignment]
    try:
        with Session(engine) as s:
            agent = DetectionValidationAgent(s, tenant_id=tenant_id)
            second = await agent.scan()
    finally:
        bas_sims.SIMULATIONS = original_simulations  # type: ignore[assignment]

    check(
        "second run picked up first run as baseline",
        second.baseline_run_id == first.run_id,
        detail=(
            f"baseline_run_id={second.baseline_run_id} "
            f"expected={first.run_id}"
        ),
    )
    check(
        "second run flags at least one drifted simulation",
        second.drift_count >= 1,
        detail=f"drift_count={second.drift_count}",
    )
    check(
        "target simulation marked drifted in second run",
        any(r.sim_id == target.sim_id and r.drifted for r in second.simulations),
        detail=(
            "the simulation whose events we mutated should have flipped "
            "from ok→silent and been flagged as drift"
        ),
    )
    # The technique covered only by the drifted simulation should now
    # appear in mitre_dropped (unless another sim covers the same
    # technique, in which case coverage stays intact — that's the
    # legitimate "redundant coverage saved us" case).
    target_techniques = set(target.expected_techniques)
    other_covered: set[str] = set()
    for r in second.simulations:
        if r.sim_id == target.sim_id:
            continue
        if r.ok:
            other_covered.update(r.fired_techniques)
    expected_dropped = target_techniques - other_covered
    if expected_dropped:
        check(
            "MITRE coverage regression includes the dropped technique(s)",
            expected_dropped.issubset(set(second.mitre_dropped)),
            detail=(
                f"expected_dropped={sorted(expected_dropped)} "
                f"mitre_dropped={second.mitre_dropped}"
            ),
        )
        check(
            "second run reports at least one coverage regression",
            second.coverage_regressions >= 1,
            detail=f"coverage_regressions={second.coverage_regressions}",
        )

    check(
        "second run opened at least one proactive case",
        len(second.cases_opened) >= 1,
        detail=f"cases_opened={second.cases_opened}",
    )

    # Inspect the cases that landed in the DB.
    with Session(engine) as s:
        cases = s.exec(
            select(Case).where(Case.id.in_(second.cases_opened))  # type: ignore[attr-defined]
        ).all()
        check(
            "every opened case row exists in DB",
            len(cases) == len(second.cases_opened),
            detail=f"db={len(cases)} expected={len(second.cases_opened)}",
        )
        check(
            "every opened case is Severity.HIGH",
            all(c.severity == Severity.HIGH for c in cases),
            detail=f"severities={[c.severity for c in cases]}",
        )
        check(
            "every opened case starts as CaseStatus.NEW",
            all(c.status == CaseStatus.NEW for c in cases),
            detail=f"statuses={[c.status for c in cases]}",
        )
        check(
            "every opened case is tenant-scoped",
            all(c.tenant_id == tenant_id for c in cases),
            detail=f"tenants={[c.tenant_id for c in cases]}",
        )
        prefixes = {
            "drift": "[Detection drift]",
            "coverage": "[Coverage regression]",
        }
        ok_titles = all(
            c.title.startswith(prefixes["drift"])
            or c.title.startswith(prefixes["coverage"])
            for c in cases
        )
        check(
            "case titles use the BAS prefixes",
            ok_titles,
            detail=f"titles={[c.title for c in cases]}",
        )

        # Every BAS case must have at least one trace row attributed to
        # AgentName.CONTINUOUS_VALIDATION so the timeline view explains
        # itself.
        for c in cases:
            traces = s.exec(
                select(AgentTrace)
                .where(AgentTrace.case_id == c.id)
                .where(AgentTrace.agent == AgentName.CONTINUOUS_VALIDATION)
            ).all()
            check(
                f"case {c.id} has ≥1 AgentTrace under CONTINUOUS_VALIDATION",
                len(traces) > 0,
                detail=f"trace_count={len(traces)}",
            )
            check(
                f"case {c.id} traces are tenant-scoped",
                all(t.tenant_id == tenant_id for t in traces),
                detail=f"trace_tenants={[t.tenant_id for t in traces]}",
            )


async def check_to_dict_shape() -> None:
    section("ValidationScanResult.to_dict() exposes the UI fields")

    tenant_id = "t-bas-test-todict"
    with Session(engine) as s:
        agent = DetectionValidationAgent(s, tenant_id=tenant_id)
        result = await agent.scan()

    d = result.to_dict()
    check(
        "to_dict returns a dict",
        isinstance(d, dict),
        detail=f"type={type(d).__name__}",
    )
    required = {
        "run_id",
        "baseline_run_id",
        "simulations_run",
        "simulations_fired",
        "simulations_silent",
        "drift_count",
        "coverage_regressions",
        "mitre_covered",
        "mitre_dropped",
        "simulations",
        "cases_opened",
    }
    check(
        "to_dict carries the required summary keys",
        isinstance(d, dict) and required.issubset(d.keys()),
        detail=f"missing={required - set(d.keys()) if isinstance(d, dict) else 'n/a'}",
    )
    if isinstance(d, dict) and d.get("simulations"):
        first_sim = d["simulations"][0]
        check(
            "to_dict simulation entries carry per-sim fields",
            {
                "sim_id",
                "name",
                "expected_rule_ids",
                "expected_techniques",
                "fired_rule_ids",
                "fired_techniques",
                "ok",
                "drifted",
            }.issubset(first_sim.keys()),
            detail=f"keys={sorted(first_sim.keys())}",
        )


# ── Main ────────────────────────────────────────────────────────────────


async def _main() -> int:
    check_symbols()
    check_tenancy_enforced()
    first = await check_first_run_no_drift()
    await check_drift_detection(first)
    await check_to_dict_shape()

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All Continuous Detection Validation Agent smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
