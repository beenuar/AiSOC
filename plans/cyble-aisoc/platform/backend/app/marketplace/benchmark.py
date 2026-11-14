"""Open AI-SOC benchmark runner + leaderboard scaffolding.

A benchmark *run* is a deterministic pass over all scenarios in the
suite. Each scenario:

1. Is ingested as an :class:`Alert` under a synthetic "benchmark"
   tenant so it does not pollute production tenant data.
2. Drives the same :class:`Orchestrator` agent mesh that handles real
   alerts in production. Running through the live mesh — not a
   shadow mock — is the entire point of the benchmark: it catches
   regressions in routing, tool-call risk gating, and grader logic
   that a unit test would miss.
3. Gets graded against the scenario's ``expected`` block, producing a
   per-scenario score and a per-run aggregate.

A :class:`BenchmarkRun` row records the leaderboard entry: model
provider/family, benchmark version, aggregate score, latency, and a
JSON outcome blob with the per-scenario detail. The leaderboard is
just ``ORDER BY score DESC, latency_ms ASC``.

The grader is intentionally simple and explicit (string-match on
required IOCs / techniques / response-action verbs) so it survives the
move into the public open-eval repo: anyone can re-run it offline and
arrive at the same number we publish.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlmodel import select

from app.agents.orchestrator import Orchestrator
from app.config import settings as runtime_settings
from app.db import session_scope
from app.marketplace.scenarios import BENCHMARK_VERSION, builtin_scenarios_raw
from app.models.alert import Alert
from app.models.benchmark import BenchmarkRun
from app.models.case import Case, CaseStatus, Severity, Verdict
from app.models.tool_call import ToolCall
from app.models.trace import AgentTrace

# Single-threaded benchmark; we run scenarios sequentially to keep the
# scoring deterministic and the SQLite engine happy. The wall-clock cost
# at five scenarios is in the low single-digit seconds with the default
# mock LLM provider.
BENCHMARK_TENANT_ID = "benchmark-suite"


# Rough severity ordering used by ``min_severity`` / ``max_severity``
# checks. ``info`` is the floor; ``critical`` the ceiling.
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _severity_rank(value: str) -> int:
    try:
        return _SEVERITY_ORDER.index(value.lower())
    except ValueError:
        return 0


# ─── DTOs ───────────────────────────────────────────────────────────────


@dataclass
class BenchmarkScenario:
    """In-memory scenario used by the runner."""

    id: str
    title: str
    description: str
    alert: dict[str, Any]
    expected: dict[str, Any]
    tags: list[str] = field(default_factory=list)


@dataclass
class ScenarioOutcome:
    scenario_id: str
    case_id: Optional[int]
    score: float  # 0..100
    passed: bool
    latency_ms: int
    verdict: Optional[str]
    severity: Optional[str]
    failure_reasons: list[str] = field(default_factory=list)
    response_actions: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)


@dataclass
class BenchmarkOutcome:
    run_id: Optional[int]
    benchmark_version: str
    model_provider: str
    model_name: str
    aggregate_score: float  # 0..100, mean of per-scenario scores
    pass_rate: float  # 0..1, fraction of scenarios that passed
    total_latency_ms: int
    scenarios: list[ScenarioOutcome] = field(default_factory=list)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        if self.started_at is not None:
            out["started_at"] = self.started_at.isoformat()
        if self.finished_at is not None:
            out["finished_at"] = self.finished_at.isoformat()
        return out


# ─── Built-in suite ─────────────────────────────────────────────────────


def builtin_scenarios() -> list[BenchmarkScenario]:
    """Materialise the on-disk JSON scenarios as :class:`BenchmarkScenario`."""
    return [BenchmarkScenario(**raw) for raw in builtin_scenarios_raw()]


# ─── Grading ────────────────────────────────────────────────────────────


def _grade_scenario(
    scenario: BenchmarkScenario,
    case: Optional[Case],
    response_actions: list[str],
    latency_ms: int,
) -> ScenarioOutcome:
    """Pure grading function — operates on a snapshotted Case + tool-call list.

    Score model (analyst-grade):

    - Verdict match: 30 points.
    - Severity bound (min or max): 15 points.
    - All required techniques surfaced on the case: 15 points.
    - All required IOCs landed in ``case.iocs``: 15 points.
    - All required users / hosts touched: 5 + 5 points.
    - Required response-action verbs were called: 10 points.
    - Latency under the per-scenario ceiling: 5 points.

    Any single check failing accumulates a reason in
    ``failure_reasons`` so the leaderboard JSON can show *why* a model
    lost points without requiring re-execution.
    """
    expected = scenario.expected
    reasons: list[str] = []
    score = 0.0

    if case is None:
        return ScenarioOutcome(
            scenario_id=scenario.id,
            case_id=None,
            score=0.0,
            passed=False,
            latency_ms=latency_ms,
            verdict=None,
            severity=None,
            failure_reasons=["case_not_created"],
            response_actions=response_actions,
        )

    case_verdict = case.verdict.value if isinstance(case.verdict, Verdict) else str(case.verdict)
    case_severity = (
        case.severity.value
        if isinstance(case.severity, Severity)
        else str(case.severity)
    )

    # 1. Verdict
    expected_verdict = expected.get("verdict")
    if expected_verdict is None:
        score += 30  # nothing to check
    elif case_verdict == expected_verdict:
        score += 30
    else:
        # Soft-pass: if the expected is true_positive but we got
        # needs_human, give partial credit — the analyst still gets the
        # case and the tool-call evidence; that's better than dropping it.
        if (
            expected_verdict == "true_positive"
            and case_verdict == "needs_human"
        ):
            score += 15
            reasons.append(
                f"verdict_partial: expected {expected_verdict}, got {case_verdict}"
            )
        else:
            reasons.append(
                f"verdict_mismatch: expected {expected_verdict}, got {case_verdict}"
            )

    # 2. Severity bounds
    severity_ok = True
    if "min_severity" in expected:
        if _severity_rank(case_severity) >= _severity_rank(expected["min_severity"]):
            score += 15
        else:
            severity_ok = False
            reasons.append(
                f"severity_below_min: expected >={expected['min_severity']}, "
                f"got {case_severity}"
            )
    elif "max_severity" in expected:
        if _severity_rank(case_severity) <= _severity_rank(expected["max_severity"]):
            score += 15
        else:
            severity_ok = False
            reasons.append(
                f"severity_above_max: expected <={expected['max_severity']}, "
                f"got {case_severity}"
            )
    else:
        score += 15

    # 3. MITRE techniques
    must_techniques = set(expected.get("must_techniques", []))
    case_techniques = set(case.mitre_techniques or [])
    if must_techniques.issubset(case_techniques):
        score += 15
    else:
        missing = must_techniques - case_techniques
        if missing:
            reasons.append(f"missing_techniques: {sorted(missing)}")

    # 4. IOCs
    must_iocs = set(expected.get("must_iocs", []))
    case_iocs = set(case.iocs or [])
    if must_iocs.issubset(case_iocs):
        score += 15
    else:
        missing = must_iocs - case_iocs
        if missing:
            reasons.append(f"missing_iocs: {sorted(missing)}")

    # 5. Affected users
    must_users = set(expected.get("must_users", []))
    case_users = set(case.affected_users or [])
    if must_users.issubset(case_users):
        score += 5
    else:
        missing = must_users - case_users
        if missing:
            reasons.append(f"missing_users: {sorted(missing)}")

    # 6. Affected hosts
    must_hosts = set(expected.get("must_hosts", []))
    case_hosts = set(case.affected_hosts or [])
    if must_hosts.issubset(case_hosts):
        score += 5
    else:
        missing = must_hosts - case_hosts
        if missing:
            reasons.append(f"missing_hosts: {sorted(missing)}")

    # 7. Response actions — match by suffix verb so our tool-name
    # convention (``edr.isolate_host``) lines up with the bare verbs
    # the scenario lists (``isolate_host``).
    must_actions = list(expected.get("must_response_actions", []))
    response_verbs = {
        action.split(".")[-1] for action in response_actions
    }
    if not must_actions:
        score += 10  # nothing required, free credit
    elif all(verb in response_verbs for verb in must_actions):
        score += 10
    else:
        missing = [v for v in must_actions if v not in response_verbs]
        reasons.append(f"missing_response_actions: {missing}")

    # 8. Latency
    max_latency_seconds = expected.get("max_latency_seconds")
    if max_latency_seconds is None:
        score += 5
    elif latency_ms <= max_latency_seconds * 1000:
        score += 5
    else:
        reasons.append(
            f"slow: {latency_ms}ms > {max_latency_seconds * 1000}ms"
        )

    # Pass = no missing-must reason. Severity-only soft failures still
    # count as a pass if the score is otherwise high; this matches the
    # plan's "analyst-grade" framing.
    passed = not reasons or (
        len(reasons) == 1 and not severity_ok and score >= 80
    )

    return ScenarioOutcome(
        scenario_id=scenario.id,
        case_id=case.id,
        score=round(score, 2),
        passed=passed,
        latency_ms=latency_ms,
        verdict=case_verdict,
        severity=case_severity,
        failure_reasons=reasons,
        response_actions=sorted(response_verbs),
        iocs=sorted(case_iocs),
        techniques=sorted(case_techniques),
    )


# ─── Runner ─────────────────────────────────────────────────────────────


class BenchmarkRunner:
    """Run benchmark scenarios end-to-end through the live agent mesh."""

    def __init__(self, *, scenarios: Optional[list[BenchmarkScenario]] = None) -> None:
        self._scenarios = scenarios or builtin_scenarios()

    @property
    def scenario_count(self) -> int:
        return len(self._scenarios)

    def list_scenarios(self) -> list[BenchmarkScenario]:
        return list(self._scenarios)

    async def run(
        self,
        *,
        notes: str | None = None,
        scenario_ids: list[str] | None = None,
    ) -> BenchmarkOutcome:
        """Execute the suite and persist a leaderboard entry."""
        settings = runtime_settings
        scenarios = (
            [s for s in self._scenarios if s.id in set(scenario_ids)]
            if scenario_ids
            else self.list_scenarios()
        )
        if not scenarios:
            raise ValueError("no scenarios selected")

        started_at = datetime.now(timezone.utc)
        outcomes: list[ScenarioOutcome] = []
        total_latency_ms = 0

        for scenario in scenarios:
            outcome = await self._run_scenario(scenario)
            outcomes.append(outcome)
            total_latency_ms += outcome.latency_ms

        # Aggregate
        aggregate_score = (
            round(sum(o.score for o in outcomes) / max(len(outcomes), 1), 2)
        )
        pass_rate = round(
            sum(1 for o in outcomes if o.passed) / max(len(outcomes), 1), 4
        )
        finished_at = datetime.now(timezone.utc)

        # Persist
        run_id = self._persist_run(
            outcomes=outcomes,
            aggregate_score=aggregate_score,
            pass_rate=pass_rate,
            total_latency_ms=total_latency_ms,
            settings=settings,
            notes=notes,
            started_at=started_at,
            finished_at=finished_at,
            scenarios_run=[s.id for s in scenarios],
        )

        return BenchmarkOutcome(
            run_id=run_id,
            benchmark_version=BENCHMARK_VERSION,
            model_provider=settings.llm_provider,
            model_name=settings.llm_model,
            aggregate_score=aggregate_score,
            pass_rate=pass_rate,
            total_latency_ms=total_latency_ms,
            scenarios=outcomes,
            started_at=started_at,
            finished_at=finished_at,
        )

    async def _run_scenario(
        self, scenario: BenchmarkScenario
    ) -> ScenarioOutcome:
        """Ingest the scenario alert, run the orchestrator, snapshot results."""
        wall_start = time.perf_counter()
        case_id: int | None = None

        # Phase 1: ingest. Keep this scope short — we open it just long
        # enough to write the alert + case, then release the session so
        # the orchestrator can have its own clean session.
        with session_scope() as session:
            alert_kwargs = dict(scenario.alert)
            external_id = alert_kwargs.pop("external_id", scenario.id)
            title = alert_kwargs.pop("title", scenario.title)
            severity_str = alert_kwargs.get("severity", "medium")
            mitre_techniques = alert_kwargs.get("mitre_techniques", [])

            try:
                severity_value = Severity(severity_str)
            except ValueError:
                severity_value = Severity.MEDIUM

            case = Case(
                tenant_id=BENCHMARK_TENANT_ID,
                title=title,
                severity=severity_value,
                status=CaseStatus.NEW,
                mitre_techniques=list(mitre_techniques),
            )
            session.add(case)
            session.commit()
            session.refresh(case)
            case_id = case.id

            alert = Alert(
                tenant_id=BENCHMARK_TENANT_ID,
                external_id=f"bench-{scenario.id}-{int(time.time())}",
                title=title,
                description=alert_kwargs.get("description", ""),
                source=alert_kwargs.get("source", "benchmark"),
                severity=severity_str,
                detection_rule=alert_kwargs.get("detection_rule"),
                mitre_tactics=list(alert_kwargs.get("mitre_tactics", [])),
                mitre_techniques=list(mitre_techniques),
                src_user=alert_kwargs.get("src_user"),
                src_host=alert_kwargs.get("src_host"),
                src_ip=alert_kwargs.get("src_ip"),
                dst_ip=alert_kwargs.get("dst_ip"),
                process_name=alert_kwargs.get("process_name"),
                file_hash=alert_kwargs.get("file_hash"),
                raw=dict(alert_kwargs.get("raw", {})),
                case_id=case_id,
            )
            session.add(alert)
            session.commit()

        # Phase 2: drive the agent mesh. We don't know how the
        # orchestrator was wired in this session, so the safest thing is
        # to open a brand-new session for it.
        try:
            with session_scope() as orch_session:
                orch = Orchestrator(
                    db=orch_session,
                    case_id=case_id,
                    tenant_id=BENCHMARK_TENANT_ID,
                )
                await asyncio.wait_for(
                    orch.run(),
                    timeout=600,  # 10 minutes; far above any realistic case
                )
        except asyncio.TimeoutError:
            # Don't crash the entire run — record the failure on this
            # scenario and move on.
            pass
        except Exception as exc:  # pragma: no cover - defensive
            # Same — we want the leaderboard entry to record what failed,
            # not blow up the whole suite on a single bad scenario.
            with session_scope() as session:
                case = session.get(Case, case_id) if case_id else None
                if case is not None:
                    case.narrative = (case.narrative or "") + f"\n[bench] error: {exc}"
                    session.add(case)
                    session.commit()

        latency_ms = int((time.perf_counter() - wall_start) * 1000)

        # Phase 3: snapshot the case + tool calls *outside* the
        # orchestrator session so the grading function operates on plain
        # Python — no detached-instance traps.
        with session_scope() as session:
            case = session.get(Case, case_id) if case_id else None
            if case is None:
                snapshot_case: Case | None = None
                response_actions: list[str] = []
            else:
                # Snapshot field-by-field into a fresh Case object so
                # session expiration after we exit can't break grading.
                snapshot_case = Case(
                    id=case.id,
                    tenant_id=case.tenant_id,
                    title=case.title,
                    narrative=case.narrative,
                    status=case.status,
                    severity=case.severity,
                    verdict=case.verdict,
                    confidence=case.confidence,
                    mitre_techniques=list(case.mitre_techniques or []),
                    affected_users=list(case.affected_users or []),
                    affected_hosts=list(case.affected_hosts or []),
                    iocs=list(case.iocs or []),
                    response_actions=list(case.response_actions or []),
                )
                tool_calls = session.exec(
                    select(ToolCall).where(ToolCall.case_id == case.id)
                ).all()
                response_actions = [tc.tool_name for tc in tool_calls]

        return _grade_scenario(
            scenario,
            snapshot_case,
            response_actions,
            latency_ms,
        )

    def _persist_run(
        self,
        *,
        outcomes: list[ScenarioOutcome],
        aggregate_score: float,
        pass_rate: float,
        total_latency_ms: int,
        settings: Any,
        notes: str | None,
        started_at: datetime,
        finished_at: datetime,
        scenarios_run: list[str],
    ) -> int | None:
        with session_scope() as session:
            row = BenchmarkRun(
                benchmark_version=BENCHMARK_VERSION,
                model_provider=settings.llm_provider,
                model_name=settings.llm_model,
                aggregate_score=aggregate_score,
                pass_rate=pass_rate,
                total_latency_ms=total_latency_ms,
                scenarios_run=scenarios_run,
                outcomes=[asdict(o) for o in outcomes],
                notes=notes or "",
                started_at=started_at,
                finished_at=finished_at,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.id


benchmark_runner = BenchmarkRunner()
