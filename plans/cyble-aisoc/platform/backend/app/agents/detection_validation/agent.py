"""Continuous Detection Validation Agent (todo ``t2h-bas``).

A BAS-style ("Breach and Attack Simulation") agent that runs on a
schedule, replays a fixed catalogue of synthetic OCSF events through
the live :class:`~app.detections.engine.DetectionEngine`, and detects
**detection drift** — i.e. a rule that fired yesterday no longer fires
today. When drift is detected (or MITRE technique coverage regresses
relative to the prior green baseline) the agent opens a proactive
``Case`` so the SOC notices *before* an adversary does.

Why this exists
---------------
Detection content silently breaks. Rule packs evolve, OCSF
normalization changes, upstream connectors rename fields, a previously
green rule gets accidentally regressed by a "small fix". You don't
find out until you get popped. The BAS agent runs the simulation
catalogue every day, compares results against the most recent green
baseline, and tells the SOC the moment something drifts.

The agent is intentionally *not* a :class:`BaseAgent` subclass for the
same reasons as the Attack-Path Agent:

* It is proactive, not reactive — it runs on a schedule (or via the
  ``POST /detection-validation/scan`` endpoint), not in response to an
  alert handoff.
* It does not mutate the live environment. The only write is opening
  a proactive Case, and that is done through the same :class:`Case`
  model the orchestrator uses — no tool surface, no HITL gate.
* It manages its own tenancy: ``ValidationRun`` rows and ``Case`` rows
  always carry the active ``tenant_id``.

Flow
----
1. **Collect**: pull the simulation catalogue from
   :mod:`app.agents.detection_validation.simulations`. The catalogue
   is hand-curated and version-controlled so additions are auditable.
2. **Replay**: for every simulation, feed each OCSF event through the
   process-wide :class:`DetectionEngine` and record which rule IDs
   actually fired.
3. **Diff vs. baseline**: load the most recent ``COMPLETED``
   ``ValidationRun`` for this tenant. For each simulation that was
   OK in the baseline but is not OK now, mark it ``drifted``. For
   each MITRE technique covered in the baseline but uncovered now,
   record a ``coverage_regression``.
4. **Open proactive cases**: each drifted simulation gets its own
   ``Severity.HIGH`` proactive case. A separate roll-up case is
   opened for tenant-wide coverage regressions when the dropped-
   technique set is non-empty.
5. **Persist**: write a ``ValidationRun`` row capturing run-level
   counters, per-simulation results, and the new baseline pointer.

Determinism guarantees
----------------------
The agent is deterministic given (a) the same simulation catalogue
and (b) the same rule pack. That property is what makes drift
detection meaningful: any change in fired-rule set between runs
*must* be attributable to the rule pack itself.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlmodel import Session, select

from app.agents.detection_validation.models import (
    SimulationResult,
    ValidationScanResult,
)
from app.agents.detection_validation.simulations import get_simulations
from app.detections.runtime import get_engine_for_tenant
from app.models.case import Case, CaseStatus, Severity
from app.models.detection_validation import ValidationRun, ValidationRunStatus
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.realtime.case_events import publish_case_created

logger = logging.getLogger("aisoc.detection_validation")


# Tag prefix used on Sigma rule tags to mark a MITRE ATT&CK technique.
# Sigma convention is ``attack.t1059.001`` → MITRE technique T1059.001.
# Normalising to upper-case + stripping the prefix lets us compare
# coverage sets across runs without worrying about case variance.
_ATTACK_PREFIX = "attack.t"


class DetectionValidationAgent:
    """BAS-style detection drift detector for one tenant.

    Instantiated per-tenant per-run (the scheduler creates one,
    calls :meth:`scan`, and discards it). Tenancy enforcement is
    trivially correct: a single instance only ever sees one tenant.
    """

    def __init__(
        self,
        session: Session,
        *,
        tenant_id: str,
    ) -> None:
        if not tenant_id:
            # Same hard requirement as the Attack-Path Agent — every
            # ValidationRun and every Case must carry tenant_id, and
            # we refuse to construct without one so MSSP deployments
            # cannot accidentally leak runs across tenants.
            raise ValueError("DetectionValidationAgent requires a tenant_id")
        self.session = session
        self.tenant_id = tenant_id
        # Engine resolution is deferred to scan time. We use
        # ``get_engine_for_tenant(self.tenant_id)`` so the BAS replay
        # exercises the *same* rule set the runtime would evaluate
        # against this tenant's events — vertical packs they're
        # assigned to, severity overrides, disabled rules. A
        # tenant-agnostic engine would silently report green coverage
        # for rules they've explicitly turned off, which is the
        # opposite of what BAS is supposed to surface.

    # ── public entry point ─────────────────────────────────────────
    async def scan(self) -> ValidationScanResult:
        """Run one full validation sweep.

        Returns the in-memory :class:`ValidationScanResult` for the
        API caller; persistence is handled inline so the database is
        always consistent with the returned value.
        """
        # Open the ValidationRun row up-front in RUNNING state so that
        # if the process crashes mid-scan we leave behind a forensic
        # marker rather than a silent gap in the timeline.
        run = ValidationRun(
            tenant_id=self.tenant_id,
            status=ValidationRunStatus.RUNNING,
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        assert run.id is not None

        baseline = self._load_baseline_run()
        baseline_results = self._baseline_results(baseline)
        baseline_techniques = set(baseline.mitre_covered) if baseline else set()

        try:
            sim_results = self._replay_simulations()
            self._mark_drift(sim_results, baseline_results)
            covered, dropped = self._coverage_diff(sim_results, baseline_techniques)
            cases_opened = await self._open_cases(sim_results, dropped)

            # Materialize the final aggregates and persist the run row.
            run.simulations_run = len(sim_results)
            run.simulations_fired = sum(1 for r in sim_results if r.ok)
            run.simulations_silent = sum(1 for r in sim_results if not r.ok)
            run.drift_count = sum(1 for r in sim_results if r.drifted)
            run.coverage_regressions = len(dropped)
            run.mitre_covered = sorted(covered)
            run.mitre_dropped = sorted(dropped)
            run.simulation_results = {r.sim_id: r.to_json() for r in sim_results}
            run.cases_opened = list(cases_opened)
            run.baseline_run_id = baseline.id if baseline else None
            run.status = ValidationRunStatus.COMPLETED
            run.completed_at = datetime.now(timezone.utc)
            self.session.add(run)
            self.session.commit()
            self.session.refresh(run)

            result = ValidationScanResult(
                run_id=run.id,
                baseline_run_id=run.baseline_run_id,
                simulations_run=run.simulations_run,
                simulations_fired=run.simulations_fired,
                simulations_silent=run.simulations_silent,
                drift_count=run.drift_count,
                coverage_regressions=run.coverage_regressions,
                mitre_covered=list(run.mitre_covered),
                mitre_dropped=list(run.mitre_dropped),
                simulations=sim_results,
                cases_opened=list(cases_opened),
            )
            self._log_summary(result)
            return result
        except Exception:  # noqa: BLE001 — never lose the run row
            # Flip the run row to FAILED so the dashboard sees the
            # ground-truth state and surfaces a follow-up. We re-raise
            # so the caller (scheduler / API) sees the original error.
            run.status = ValidationRunStatus.FAILED
            run.completed_at = datetime.now(timezone.utc)
            self.session.add(run)
            self.session.commit()
            logger.exception(
                "detection_validation:scan_failed tenant=%s run=%s",
                self.tenant_id,
                run.id,
            )
            raise

    # ── baseline lookup ────────────────────────────────────────────
    def _load_baseline_run(self) -> ValidationRun | None:
        """Most recent ``COMPLETED`` run for this tenant, or ``None``.

        First-ever run for a tenant has no baseline; in that case every
        simulation's ``drifted`` is False and every covered technique
        is "new", which is the desired behaviour — a brand-new tenant
        cannot drift relative to itself.
        """
        stmt = (
            select(ValidationRun)
            .where(ValidationRun.tenant_id == self.tenant_id)
            .where(ValidationRun.status == ValidationRunStatus.COMPLETED)
            .order_by(ValidationRun.started_at.desc())
            .limit(1)
        )
        return self.session.exec(stmt).first()

    @staticmethod
    def _baseline_results(baseline: ValidationRun | None) -> dict[str, dict[str, Any]]:
        """Project the baseline's per-simulation blob into a lookup map."""
        if baseline is None:
            return {}
        # ValidationRun.simulation_results is keyed by sim_id with the
        # SimulationResult.to_json() shape; no transformation needed.
        return dict(baseline.simulation_results or {})

    # ── replay ────────────────────────────────────────────────────
    def _replay_simulations(self) -> list[SimulationResult]:
        """Replay every simulation in declaration order.

        Engine is fetched once per scan rather than once per event:
        rebuilding the pack mid-scan would invalidate the run's
        determinism guarantee. The tenant-effective engine is used so
        drift detection mirrors what the runtime would actually fire
        on this tenant's traffic, including their vertical packs and
        calibration overrides.
        """
        engine = get_engine_for_tenant(self.tenant_id)
        results: list[SimulationResult] = []
        for sim in get_simulations():
            fired_rule_ids: set[str] = set()
            fired_techniques: set[str] = set()
            for event in sim.events:
                try:
                    hits = engine.evaluate(event)
                except Exception:  # noqa: BLE001 — never lose the scan
                    # A bug in the engine for one event should not blow
                    # away the rest of the catalogue. We log, count
                    # this event as silent, and keep going.
                    logger.exception(
                        "detection_validation:eval_error sim=%s tenant=%s",
                        sim.sim_id,
                        self.tenant_id,
                    )
                    continue
                for hit in hits:
                    fired_rule_ids.add(hit.rule_id)
                    fired_techniques.update(self._extract_techniques(hit.tags))
            ok = bool(set(sim.expected_rule_ids) & fired_rule_ids)
            results.append(
                SimulationResult(
                    sim_id=sim.sim_id,
                    name=sim.name,
                    expected_rule_ids=sim.expected_rule_ids,
                    expected_techniques=sim.expected_techniques,
                    fired_rule_ids=tuple(sorted(fired_rule_ids)),
                    fired_techniques=tuple(sorted(fired_techniques)),
                    ok=ok,
                )
            )
        return results

    @staticmethod
    def _extract_techniques(tags: Iterable[str]) -> set[str]:
        """Pull MITRE technique IDs out of a Sigma rule's tag list.

        Sigma convention: ``attack.t1110.003`` → ``T1110.003``. Anything
        that doesn't start with ``attack.t`` is not a technique and is
        skipped (it might be ``attack.credential_access`` — a *tactic*
        — or ``cve.2024-12345`` etc.).
        """
        out: set[str] = set()
        for tag in tags:
            low = (tag or "").lower()
            if not low.startswith(_ATTACK_PREFIX):
                continue
            # ``attack.t1110.003`` → ``t1110.003`` → ``T1110.003``
            technique = low[len("attack.") :].upper()
            out.add(technique)
        return out

    # ── drift + coverage diff ──────────────────────────────────────
    @staticmethod
    def _mark_drift(
        results: list[SimulationResult],
        baseline: dict[str, dict[str, Any]],
    ) -> None:
        """Mark a simulation drifted iff it was OK in baseline, not now.

        We do not flag the inverse (silent yesterday, OK today) as
        drift — that's *improvement*, and we want it celebrated, not
        ticketed. The mitre_covered set captures it implicitly.
        """
        for r in results:
            prior = baseline.get(r.sim_id)
            if not prior:
                continue
            if bool(prior.get("ok")) and not r.ok:
                r.drifted = True

    @staticmethod
    def _coverage_diff(
        results: list[SimulationResult],
        baseline_techniques: set[str],
    ) -> tuple[set[str], set[str]]:
        """Return (covered_now, dropped_vs_baseline).

        Coverage is computed from the union of techniques whose rules
        fired in this run (not the *expected* techniques) so that we
        measure ground truth, not aspiration.
        """
        covered_now: set[str] = set()
        for r in results:
            if r.ok:
                covered_now.update(r.fired_techniques)
        dropped = baseline_techniques - covered_now
        return covered_now, dropped

    # ── case opening ───────────────────────────────────────────────
    async def _open_cases(
        self,
        results: list[SimulationResult],
        dropped_techniques: set[str],
    ) -> list[int]:
        """Open one case per drifted sim + one roll-up for coverage loss.

        Returns the list of case IDs opened (in the order they were
        created) so the run row + scan result can link back to them.
        """
        opened: list[int] = []
        for r in results:
            if not r.drifted:
                continue
            case_id = await self._open_drift_case(r)
            r.case_id = case_id
            opened.append(case_id)

        if dropped_techniques:
            roll_up_id = await self._open_coverage_case(dropped_techniques)
            opened.append(roll_up_id)
        return opened

    async def _open_drift_case(self, r: SimulationResult) -> int:
        """Open a HIGH-severity proactive case for one drifted sim."""
        narrative = (
            "Detection drift detected by the Continuous Detection "
            "Validation Agent.\n\n"
            f"Simulation: {r.name}\n"
            f"Expected to fire: {', '.join(r.expected_rule_ids)}\n"
            f"Expected technique(s): {', '.join(r.expected_techniques)}\n"
            f"Fired this run: "
            f"{', '.join(r.fired_rule_ids) if r.fired_rule_ids else '(nothing)'}\n\n"
            "This simulation fired in the previous baseline run for "
            "this tenant but did not fire today. A rule, an OCSF "
            "field path, or a connector mapping has regressed — "
            "investigate before an adversary exploits the gap.\n\n"
            f"sim_id: {r.sim_id}"
        )
        case = Case(
            tenant_id=self.tenant_id,
            title=f"[Detection drift] {r.name}",
            narrative=narrative,
            status=CaseStatus.NEW,
            severity=Severity.HIGH,
            mitre_techniques=list(r.expected_techniques),
        )
        self.session.add(case)
        self.session.commit()
        self.session.refresh(case)
        assert case.id is not None

        self._log_trace(
            case_id=case.id,
            step=TraceStep.DECISION,
            summary=(
                f"Opened drift case for sim {r.sim_id} "
                f"(expected={list(r.expected_rule_ids)}, fired={list(r.fired_rule_ids)})"
            ),
            detail={
                "sim_id": r.sim_id,
                "expected_rule_ids": list(r.expected_rule_ids),
                "expected_techniques": list(r.expected_techniques),
                "fired_rule_ids": list(r.fired_rule_ids),
                "fired_techniques": list(r.fired_techniques),
            },
        )
        await publish_case_created(
            tenant_id=self.tenant_id,
            case_id=case.id,
            title=case.title,
            severity=case.severity.value,
            status=case.status.value,
            source="detection-validation",
        )
        return case.id

    async def _open_coverage_case(self, dropped: set[str]) -> int:
        """One roll-up case summarising tenant-wide MITRE regressions."""
        techniques = sorted(dropped)
        bullets = "\n".join(f"• {t}" for t in techniques)
        narrative = (
            "MITRE ATT&CK coverage regression detected by the "
            "Continuous Detection Validation Agent.\n\n"
            "Techniques previously covered that are no longer covered "
            "by any firing rule for this tenant:\n\n"
            f"{bullets}\n\n"
            "Use the detection-author agent to author or restore "
            "coverage; the per-simulation drift cases (if any) point "
            "at the specific rules that regressed."
        )
        case = Case(
            tenant_id=self.tenant_id,
            title=(
                f"[Coverage regression] {len(techniques)} MITRE "
                f"technique{'s' if len(techniques) != 1 else ''} uncovered"
            ),
            narrative=narrative,
            status=CaseStatus.NEW,
            severity=Severity.HIGH,
            mitre_techniques=techniques,
        )
        self.session.add(case)
        self.session.commit()
        self.session.refresh(case)
        assert case.id is not None

        self._log_trace(
            case_id=case.id,
            step=TraceStep.DECISION,
            summary=f"Coverage regression: {len(techniques)} techniques dropped",
            detail={"dropped_techniques": techniques},
        )
        await publish_case_created(
            tenant_id=self.tenant_id,
            case_id=case.id,
            title=case.title,
            severity=case.severity.value,
            status=case.status.value,
            source="detection-validation",
        )
        return case.id

    # ── trace + summary ────────────────────────────────────────────
    def _log_trace(
        self,
        *,
        case_id: int | None,
        step: TraceStep,
        summary: str,
        detail: dict[str, Any],
    ) -> None:
        """Persist an AgentTrace row.

        AgentTrace's FK requires a case_id, so we only persist traces
        bound to a real case. Summary-only traces (scan with no cases)
        are emitted via logger so the run is still observable in the
        process logs and surfaces in Loki/CloudWatch.
        """
        if case_id is None:
            logger.info(
                "detection_validation:summary tenant=%s %s", self.tenant_id, summary
            )
            return
        trace = AgentTrace(
            tenant_id=self.tenant_id,
            case_id=case_id,
            agent=AgentName.CONTINUOUS_VALIDATION,
            step=step,
            summary=summary,
            detail=detail,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(trace)
        self.session.commit()

    def _log_summary(self, result: ValidationScanResult) -> None:
        """One-line per-run log so the dashboard isn't the only signal."""
        logger.info(
            "detection_validation:run_complete tenant=%s run=%s "
            "fired=%d/%d drifted=%d dropped_techniques=%d cases=%d",
            self.tenant_id,
            result.run_id,
            result.simulations_fired,
            result.simulations_run,
            result.drift_count,
            result.coverage_regressions,
            len(result.cases_opened),
        )


__all__ = ["DetectionValidationAgent"]
