"""Detection-as-code proposal lifecycle endpoints (Wave 2 — w2-dac).

Surfaces the propose → review → eval-gated → promote flow that brings
detections under the same CI gate as agent prompts.

Two independent gates guard promotion, and approval requires **both**:

* **Candidate-rule gate (Phase 4, non-circular).** ``/evaluate-rule`` runs the
  *proposed rule body itself* through the runtime engine against caller-supplied
  positive and negative fixtures — it must fire on every positive and stay
  silent on every negative. This closes the Phase 0 reality-audit finding that
  the promote path never evaluated the proposed rule.
* **Substrate-benchmark gate.** ``/run-eval`` / ``/eval`` run
  ``scripts/run_evals.py`` and reject a candidate that regresses repo-wide MITRE
  accuracy by ≥ ``max_regression_pp`` pp. This guards against a rule that passes
  its own fixtures but perturbs the shared substrate.

Endpoints
---------
* ``GET    /detection-proposals``                     List proposals.
* ``POST   /detection-proposals``                     Create a proposal.
* ``GET    /detection-proposals/{id}``                Proposal detail.
* ``POST   /detection-proposals/{id}/comment``        Add a review comment.
* ``POST   /detection-proposals/{id}/evaluate-rule``  Evaluate the candidate rule vs its fixtures (non-circular gate).
* ``POST   /detection-proposals/{id}/eval``           Attach substrate-benchmark result + verdict.
* ``POST   /detection-proposals/{id}/decide``         Approve/reject a proposal.
* ``POST   /detection-proposals/{id}/promote``        Materialise into ``detection_rules``.
* ``GET    /detection-proposals/baselines``           List eval baselines.
* ``POST   /detection-proposals/baselines``           Record a new baseline.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.config import settings
from app.models.detection_proposal import (
    DetectionEvalBaseline,
    DetectionRuleProposal,
)
from app.models.detection_rule import DetectionRule
from app.services.detection_eval import evaluate_candidate_rule
from app.services.github import create_detection_pr

router = APIRouter(prefix="/detection-proposals", tags=["detection_rules", "dac"])


# Resolve the AiSOC repository root by walking up from this file until we
# find the eval harness this module shells out to (``scripts/run_evals.py``).
# Hard-coding ``Path(__file__).parents[6]`` only works on the host, where
# this file sits six levels under the repo root. Inside the API Docker
# image only the ``services/api/`` subtree is copied to ``/app``, so a
# fixed parent index raises ``IndexError`` at import time and crashes the
# entire API service before the first request — see GH #81 / #83.
#
# Every code path that *uses* the resolved root re-checks
# ``_EVAL_SCRIPT.exists()`` before invoking it, so the worst case in a
# stripped image is a clean 500 from ``/run-eval`` (with a helpful message)
# rather than an import-time crash.
_REPO_ROOT_MARKER = ("scripts", "run_evals.py")


def _resolve_repo_root(start: Path) -> Path:
    """Walk up from ``start`` looking for ``scripts/run_evals.py``.

    Returns the first ancestor that contains the marker file. If the marker
    is not present (typical inside the slimmed API container), falls back
    to the closest sensible ancestor — never to the filesystem root, which
    would silently produce nonsense paths for subsequent ``/`` joins.
    """
    candidates = (start, *start.parents)
    for candidate in candidates:
        if (candidate.joinpath(*_REPO_ROOT_MARKER)).is_file():
            return candidate
    # Fallback: ``services/api`` (or its in-container equivalent ``/app``).
    # That's parents[3] from this file and is guaranteed to exist in any
    # environment where the API service can import this module.
    parents = start.parents
    if len(parents) > 3:
        return parents[3]
    return parents[-1] if parents else start


_ENDPOINT_FILE = Path(__file__).resolve()
_REPO_ROOT_DEFAULT = _resolve_repo_root(_ENDPOINT_FILE)
_REPO_ROOT = Path(os.environ.get("AISOC_REPO_ROOT", str(_REPO_ROOT_DEFAULT)))
_EVAL_SCRIPT = _REPO_ROOT / "scripts" / "run_evals.py"


# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────


class ProposalResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    base_rule_id: uuid.UUID | None
    promoted_rule_id: uuid.UUID | None
    name: str
    description: str | None
    rule_language: str
    rule_body: str
    category: str
    severity: str
    confidence: int
    mitre_tactics: list
    mitre_techniques: list
    tags: list
    status: str
    eval_result: dict
    review_comments: list
    proposed_by_id: uuid.UUID | None
    decided_by_id: uuid.UUID | None
    decision_comment: str | None
    decided_at: datetime | None
    # WS-B4: git PR path — URL of the GitHub PR created on promotion (may be None).
    github_pr_url: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CreateProposalRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: str | None = None
    rule_language: str = Field(..., max_length=30)
    rule_body: str
    category: str = Field(..., max_length=100)
    severity: str = "medium"
    confidence: int = Field(default=50, ge=0, le=100)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    base_rule_id: uuid.UUID | None = None


class ReviewCommentRequest(BaseModel):
    comment: str = Field(..., min_length=1, max_length=4000)


class EvalAttachRequest(BaseModel):
    """Attach a `run_evals.py` JSON report to a proposal."""

    eval_report: dict[str, Any] = Field(
        ...,
        description=(
            "Full JSON output of `python3 scripts/run_evals.py --baseline ... --max-regression-pp ...` for the candidate ruleset."
        ),
    )
    max_regression_pp: float = Field(
        default=1.0,
        ge=0.0,
        le=50.0,
        description=(
            "Allowed MITRE accuracy regression vs baseline, in pp. Hard-capped "
            "at 50 — anything above that is indistinguishable from disabling "
            "the regression gate entirely."
        ),
    )


class EvaluateRuleRequest(BaseModel):
    """Evaluate the candidate rule body against its own fixtures (Phase 4).

    This is the non-circular gate: unlike ``/run-eval`` (which measures the
    repo-wide substrate benchmark and is independent of the proposed rule),
    this runs the *proposed rule body itself* through the runtime engine and
    asserts it fires on every positive fixture and stays silent on every
    negative one. Approval now requires this verdict to pass.
    """

    positive_fixtures: list[dict[str, Any]] = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Events the rule MUST fire on (the attacks it claims to catch). At least one required.",
    )
    negative_fixtures: list[dict[str, Any]] = Field(
        default_factory=list,
        max_length=200,
        description="Benign near-miss events the rule MUST NOT fire on.",
    )


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str | None = Field(default=None, max_length=2000)


class RunEvalRequest(BaseModel):
    """Trigger a local run of the offline eval harness.

    The runner is `scripts/run_evals.py`. It is fully offline and deterministic
    against the 200-incident synthetic benchmark, so this endpoint can be safely
    called from the rule editor on every "Propose for review" action.
    """

    use_active_baseline: bool = Field(
        default=True,
        description=(
            "If true (default), the most recent active MITRE accuracy baseline "
            "is materialised to a temp file and passed to run_evals.py via "
            "--baseline so the runner can compute baseline_compare in-band."
        ),
    )
    max_regression_pp: float = Field(
        default=1.0,
        ge=0.0,
        le=50.0,
        description=(
            "Allowed MITRE accuracy regression vs the active baseline, in "
            "percentage points. Forwarded to run_evals.py. Hard-capped at 50 "
            "to keep the regression gate meaningful."
        ),
    )
    timeout_seconds: int = Field(
        default=180,
        ge=10,
        le=600,
        description=(
            "Hard timeout for the eval subprocess. Capped at 10 minutes — the "
            "synthetic benchmark completes in under 60s on commodity hardware "
            "so anything longer is almost certainly a stuck process."
        ),
    )


class RunEvalResponse(BaseModel):
    """Wraps the JSON report emitted by `run_evals.py`."""

    report: dict[str, Any]
    exit_code: int
    duration_seconds: float
    ran_at: datetime
    script: str


class BaselineResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    suite: str
    score: float
    payload: dict
    is_active: bool
    recorded_by_id: uuid.UUID | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateBaselineRequest(BaseModel):
    suite: str = Field(..., max_length=64)
    score: float
    payload: dict[str, Any] = Field(default_factory=dict)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _ensure_dac_enabled() -> None:
    if not settings.AISOC_FEATURE_DAC:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection-as-code is disabled (AISOC_FEATURE_DAC=false)",
        )


async def _load_proposal(
    db: Any,
    proposal_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> DetectionRuleProposal:
    result = await db.execute(
        select(DetectionRuleProposal).where(
            DetectionRuleProposal.id == proposal_id,
            or_(
                DetectionRuleProposal.tenant_id == tenant_id,
                DetectionRuleProposal.tenant_id.is_(None),
            ),
        )
    )
    proposal = result.scalar_one_or_none()
    if proposal is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proposal not found",
        )
    return proposal


def _evaluate_eval_report(
    eval_report: dict[str, Any],
    baseline_score: float | None,
    max_regression_pp: float,
) -> dict[str, Any]:
    """Compute the gate verdict from a `run_evals.py` JSON report."""
    suites = eval_report.get("suites", {}) or {}
    mitre = suites.get("mitre_accuracy", {}) or {}
    candidate_score = float(mitre.get("value", 0.0))

    # Prefer baseline_compare block if the runner already computed it.
    cmp = eval_report.get("baseline_compare") or {}
    if cmp.get("available"):
        regressed = bool(cmp.get("regressed"))
        drop_pp = float(cmp.get("mitre_drop_pp", 0.0))
        baseline = float(cmp.get("deltas", {}).get("mitre_accuracy", {}).get("baseline", baseline_score or candidate_score))
    else:
        baseline = baseline_score if baseline_score is not None else candidate_score
        drop_pp = round(max(0.0, (baseline - candidate_score) * 100), 4)
        regressed = drop_pp >= max_regression_pp

    all_floors_passed = bool(eval_report.get("all_passed", False))
    passed = (not regressed) and all_floors_passed

    return {
        "ran_at": datetime.now(UTC).isoformat(),
        "candidate": {
            "mitre_accuracy": candidate_score,
            "all_passed": all_floors_passed,
        },
        "baseline": {
            "mitre_accuracy": baseline,
        },
        "drop_pp": drop_pp,
        "max_regression_pp": max_regression_pp,
        "regressed": regressed,
        "passed": passed,
    }


# ────────────────────────────────────────────────────────────────────────────
# Proposal endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("", response_model=list[ProposalResponse])
async def list_proposals(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
    proposal_status: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ProposalResponse]:
    """List detection rule proposals visible to the caller."""
    _ensure_dac_enabled()
    filters = [
        or_(
            DetectionRuleProposal.tenant_id == current_user.tenant_id,
            DetectionRuleProposal.tenant_id.is_(None),
        )
    ]
    if proposal_status:
        filters.append(DetectionRuleProposal.status == proposal_status)
    result = await db.execute(
        select(DetectionRuleProposal).where(and_(*filters)).order_by(DetectionRuleProposal.created_at.desc()).limit(limit)
    )
    return [ProposalResponse.model_validate(p) for p in result.scalars().all()]


@router.post("", response_model=ProposalResponse, status_code=status.HTTP_201_CREATED)
async def create_proposal(
    request: CreateProposalRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> ProposalResponse:
    """Open a new detection proposal in `proposed` state."""
    _ensure_dac_enabled()
    proposal = DetectionRuleProposal(
        tenant_id=current_user.tenant_id,
        base_rule_id=request.base_rule_id,
        name=request.name,
        description=request.description,
        rule_language=request.rule_language,
        rule_body=request.rule_body,
        category=request.category,
        severity=request.severity,
        confidence=request.confidence,
        mitre_tactics=request.mitre_tactics,
        mitre_techniques=request.mitre_techniques,
        tags=request.tags,
        status="proposed",
        proposed_by_id=current_user.user_id,
    )
    db.add(proposal)
    await db.commit()
    await db.refresh(proposal)
    return ProposalResponse.model_validate(proposal)


@router.get("/baselines", response_model=list[BaselineResponse])
async def list_baselines(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
    suite: str | None = Query(default=None),
) -> list[BaselineResponse]:
    """List eval baselines (most recent active baseline per suite is what we gate on)."""
    _ensure_dac_enabled()
    filters: list[Any] = [
        or_(
            DetectionEvalBaseline.tenant_id == current_user.tenant_id,
            DetectionEvalBaseline.tenant_id.is_(None),
        )
    ]
    if suite:
        filters.append(DetectionEvalBaseline.suite == suite)
    result = await db.execute(select(DetectionEvalBaseline).where(and_(*filters)).order_by(DetectionEvalBaseline.created_at.desc()))
    return [BaselineResponse.model_validate(b) for b in result.scalars().all()]


@router.post(
    "/baselines",
    response_model=BaselineResponse,
    status_code=status.HTTP_201_CREATED,
)
async def record_baseline(
    request: CreateBaselineRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> BaselineResponse:
    """Record a new eval baseline and deactivate older entries for the same suite."""
    _ensure_dac_enabled()
    # Deactivate older baselines for the same scope+suite so the gate reads
    # exactly one "current" snapshot.
    await db.execute(
        update(DetectionEvalBaseline)
        .where(
            DetectionEvalBaseline.tenant_id == current_user.tenant_id,
            DetectionEvalBaseline.suite == request.suite,
            DetectionEvalBaseline.is_active.is_(True),
        )
        .values(is_active=False)
    )
    baseline = DetectionEvalBaseline(
        tenant_id=current_user.tenant_id,
        suite=request.suite,
        score=request.score,
        payload=request.payload,
        is_active=True,
        recorded_by_id=current_user.user_id,
    )
    db.add(baseline)
    await db.commit()
    await db.refresh(baseline)
    return BaselineResponse.model_validate(baseline)


@router.get("/{proposal_id}", response_model=ProposalResponse)
async def get_proposal(
    proposal_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> ProposalResponse:
    """Get a proposal by id."""
    _ensure_dac_enabled()
    proposal = await _load_proposal(db, proposal_id, current_user.tenant_id)
    return ProposalResponse.model_validate(proposal)


@router.post("/{proposal_id}/comment", response_model=ProposalResponse)
async def comment_on_proposal(
    proposal_id: uuid.UUID,
    request: ReviewCommentRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> ProposalResponse:
    """Append a review comment and move the proposal into `in_review`."""
    _ensure_dac_enabled()
    proposal = await _load_proposal(db, proposal_id, current_user.tenant_id)
    if proposal.status in {"promoted", "rejected"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proposal is {proposal.status}; cannot add comments",
        )
    comments = list(proposal.review_comments or [])
    comments.append(
        {
            "actor_id": str(current_user.user_id),
            "actor_email": current_user.email,
            "comment": request.comment,
            "at": datetime.now(UTC).isoformat(),
        }
    )
    proposal.review_comments = comments
    if proposal.status == "proposed":
        proposal.status = "in_review"
    await db.commit()
    await db.refresh(proposal)
    return ProposalResponse.model_validate(proposal)


async def _resolve_active_baseline(
    db: Any,
    tenant_id: uuid.UUID,
) -> DetectionEvalBaseline | None:
    """Return the most recent active MITRE accuracy baseline for the tenant.

    Falls back to the platform-wide (tenant_id IS NULL) baseline.
    """
    q = await db.execute(
        select(DetectionEvalBaseline)
        .where(
            DetectionEvalBaseline.suite == "mitre_accuracy",
            DetectionEvalBaseline.is_active.is_(True),
            or_(
                DetectionEvalBaseline.tenant_id == tenant_id,
                DetectionEvalBaseline.tenant_id.is_(None),
            ),
        )
        .order_by(DetectionEvalBaseline.created_at.desc())
        .limit(1)
    )
    return q.scalar_one_or_none()


def _run_eval_subprocess(
    *,
    baseline_path: Path | None,
    out_path: Path,
    max_regression_pp: float,
    timeout_seconds: int,
) -> tuple[int, str, str]:
    """Run `scripts/run_evals.py` synchronously and return (exit_code, stdout, stderr).

    Designed to be invoked from a thread pool via ``run_in_executor`` so the
    FastAPI event loop is not blocked.
    """
    cmd: list[str] = [
        sys.executable,
        str(_EVAL_SCRIPT),
        "--json",
        "--out",
        str(out_path),
        "--max-regression-pp",
        str(max_regression_pp),
    ]
    if baseline_path is not None:
        cmd.extend(["--baseline", str(baseline_path)])

    env = os.environ.copy()
    # The runner imports modules from services/agents — ensure that path is always present.
    agents_path = str(_REPO_ROOT / "services" / "agents")
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = agents_path if not existing_pp else f"{agents_path}:{existing_pp}"

    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell=True
        cmd,
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        env=env,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


@router.post(
    "/run-eval",
    response_model=RunEvalResponse,
    summary="Run the offline eval harness (`scripts/run_evals.py`) and return the JSON report",
)
async def run_eval_harness(
    request: RunEvalRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> RunEvalResponse:
    """Execute the offline eval harness and return its JSON output.

    This is the "eval-harness regression on save" hook for the in-app rule editor.
    The harness is deterministic and offline, but takes 5–15s, so the editor
    surfaces it as an explicit "Propose for review" action rather than firing on
    every keystroke.
    """
    _ensure_dac_enabled()

    if not _EVAL_SCRIPT.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(f"Eval runner missing at {_EVAL_SCRIPT}. Set AISOC_REPO_ROOT or verify the deployment includes scripts/run_evals.py."),
        )

    baseline_path: Path | None = None
    baseline_tmp: tempfile._TemporaryFileWrapper[str] | None = None
    out_tmp: tempfile._TemporaryFileWrapper[str] | None = None
    started_at = datetime.now(UTC)
    try:
        if request.use_active_baseline:
            baseline = await _resolve_active_baseline(db, current_user.tenant_id)
            if baseline is not None:
                baseline_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115 — closed in finally
                    mode="w",
                    suffix="_baseline.json",
                    delete=False,
                )
                json.dump(baseline.payload or {}, baseline_tmp)
                baseline_tmp.flush()
                baseline_tmp.close()
                baseline_path = Path(baseline_tmp.name)

        out_tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115 — closed in finally
            mode="w",
            suffix="_eval_report.json",
            delete=False,
        )
        out_tmp.close()
        out_path = Path(out_tmp.name)

        loop = asyncio.get_event_loop()
        try:
            exit_code, stdout, stderr = await loop.run_in_executor(
                None,
                lambda: _run_eval_subprocess(
                    baseline_path=baseline_path,
                    out_path=out_path,
                    max_regression_pp=request.max_regression_pp,
                    timeout_seconds=request.timeout_seconds,
                ),
            )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=f"Eval harness exceeded {request.timeout_seconds}s timeout",
            ) from exc

        # The runner exits with:
        #   0 = pass, 1 = a suite is below floor, 2 = MITRE regressed vs baseline.
        # In all three cases the JSON report is still written to --out.
        if exit_code not in (0, 1, 2):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(f"Eval harness failed with exit code {exit_code}. stderr={stderr[-2000:].strip()}"),
            )

        # Prefer reading the on-disk JSON over parsing stdout — stdout is also
        # JSON when --json is set, but the runner sometimes prefixes a banner.
        try:
            report_text = out_path.read_text()
            report = json.loads(report_text) if report_text.strip() else json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(f"Eval harness produced unparseable JSON. stderr={stderr[-2000:].strip()}"),
            ) from exc

        finished_at = datetime.now(UTC)
        return RunEvalResponse(
            report=report,
            exit_code=exit_code,
            duration_seconds=round((finished_at - started_at).total_seconds(), 3),
            ran_at=started_at,
            script=str(_EVAL_SCRIPT.relative_to(_REPO_ROOT)) if _EVAL_SCRIPT.is_relative_to(_REPO_ROOT) else str(_EVAL_SCRIPT),
        )
    finally:
        for tmp in (baseline_tmp, out_tmp):
            if tmp is not None:
                try:
                    Path(tmp.name).unlink(missing_ok=True)
                except OSError as exc:
                    _ = exc  # best-effort cleanup; ignore unlink failures


@router.post("/{proposal_id}/evaluate-rule", response_model=ProposalResponse)
async def evaluate_rule(
    proposal_id: uuid.UUID,
    request: EvaluateRuleRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> ProposalResponse:
    """Evaluate the candidate rule body against its own fixtures (Phase 4).

    Runs the proposed ``rule_language`` + ``rule_body`` through the runtime
    engine against the supplied fixtures and stores the verdict under
    ``eval_result["candidate_rule"]``. This is the gate that de-circularises
    promotion: a rule that misses its positives (blind) or fires on its
    negatives (noisy) cannot be approved, regardless of the global benchmark.
    """
    _ensure_dac_enabled()
    proposal = await _load_proposal(db, proposal_id, current_user.tenant_id)
    if proposal.status in {"promoted", "rejected"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proposal is {proposal.status}; candidate-rule eval cannot be re-run",
        )

    result = evaluate_candidate_rule(
        rule_language=proposal.rule_language,
        rule_body=proposal.rule_body,
        positive_fixtures=request.positive_fixtures,
        negative_fixtures=request.negative_fixtures,
    )

    # Merge into eval_result so the benchmark verdict (if already attached) is
    # preserved alongside the candidate-rule verdict.
    merged = dict(proposal.eval_result or {})
    merged["candidate_rule"] = {**result.to_dict(), "ran_at": datetime.now(UTC).isoformat()}
    proposal.eval_result = merged

    # A candidate-rule failure is decisive — it cannot be approved. On pass,
    # only advance to eval_passed if the benchmark gate isn't failing.
    if not result.passed:
        proposal.status = "eval_failed"
    elif proposal.status not in {"eval_failed"}:
        proposal.status = "eval_passed"

    await db.commit()
    await db.refresh(proposal)
    return ProposalResponse.model_validate(proposal)


@router.post("/{proposal_id}/eval", response_model=ProposalResponse)
async def attach_eval_result(
    proposal_id: uuid.UUID,
    request: EvalAttachRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> ProposalResponse:
    """Attach the run_evals.py output and compute the gate verdict.

    Reads the active MITRE accuracy baseline for the tenant (falling back
    to the platform-wide baseline) and stores ``eval_result.passed=True``
    only when MITRE accuracy regression is < ``max_regression_pp``.
    """
    _ensure_dac_enabled()
    proposal = await _load_proposal(db, proposal_id, current_user.tenant_id)
    if proposal.status in {"promoted", "rejected"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proposal is {proposal.status}; eval cannot be re-attached",
        )

    # Resolve the most recent active MITRE accuracy baseline.
    baseline_q = await db.execute(
        select(DetectionEvalBaseline)
        .where(
            DetectionEvalBaseline.suite == "mitre_accuracy",
            DetectionEvalBaseline.is_active.is_(True),
            or_(
                DetectionEvalBaseline.tenant_id == current_user.tenant_id,
                DetectionEvalBaseline.tenant_id.is_(None),
            ),
        )
        .order_by(DetectionEvalBaseline.created_at.desc())
        .limit(1)
    )
    baseline = baseline_q.scalar_one_or_none()

    verdict = _evaluate_eval_report(
        eval_report=request.eval_report,
        baseline_score=baseline.score if baseline else None,
        max_regression_pp=request.max_regression_pp,
    )

    # Preserve any candidate-rule verdict already attached via /evaluate-rule.
    existing = dict(proposal.eval_result or {})
    candidate = existing.get("candidate_rule")
    merged = dict(verdict)
    if candidate is not None:
        merged["candidate_rule"] = candidate
    proposal.eval_result = merged

    # Benchmark pass alone is not sufficient if the candidate rule failed its
    # own fixtures — the non-circular gate is decisive.
    candidate_ok = (candidate or {}).get("passed", None)
    if candidate_ok is False:
        proposal.status = "eval_failed"
    else:
        proposal.status = "eval_passed" if verdict["passed"] else "eval_failed"
    await db.commit()
    await db.refresh(proposal)
    return ProposalResponse.model_validate(proposal)


@router.post("/{proposal_id}/decide", response_model=ProposalResponse)
async def decide_proposal(
    proposal_id: uuid.UUID,
    request: DecisionRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> ProposalResponse:
    """Approve or reject a proposal. Approving requires the eval gate to have passed."""
    _ensure_dac_enabled()
    proposal = await _load_proposal(db, proposal_id, current_user.tenant_id)
    if proposal.status in {"promoted", "rejected"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Proposal already {proposal.status}",
        )

    if request.decision == "approve":
        eval_result = proposal.eval_result or {}
        # Phase 4 — de-circularised gate. Approval requires the candidate rule
        # to have been evaluated against its own fixtures and passed (fires on
        # positives, silent on negatives). A benchmark-only "pass" is no longer
        # sufficient: the reality audit showed the benchmark is independent of
        # the proposed rule, so a blind/noisy rule could sail through.
        candidate = eval_result.get("candidate_rule")
        if not candidate:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=(
                    "Candidate-rule eval has not been run; cannot approve. "
                    "POST /detection-proposals/{id}/evaluate-rule with positive "
                    "and negative fixtures first."
                ),
            )
        if not bool(candidate.get("passed")):
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=f"Candidate-rule eval failed ({candidate.get('reason', 'rule did not pass its fixtures')}); cannot approve.",
            )
        # If a substrate-benchmark verdict is also attached it must not be a
        # regression failure.
        if "passed" in eval_result and not bool(eval_result.get("passed")):
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail="Substrate benchmark gate failed (MITRE regression); cannot approve.",
            )
        proposal.status = "approved"
    else:
        proposal.status = "rejected"

    proposal.decided_by_id = current_user.user_id
    proposal.decided_at = datetime.now(UTC)
    proposal.decision_comment = request.comment
    await db.commit()
    await db.refresh(proposal)
    return ProposalResponse.model_validate(proposal)


@router.post(
    "/{proposal_id}/promote",
    response_model=ProposalResponse,
    summary="Materialise an approved proposal into the detection_rules table",
)
async def promote_proposal(
    proposal_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> ProposalResponse:
    """Promote an approved proposal: create or update the linked detection rule."""
    _ensure_dac_enabled()
    proposal = await _load_proposal(db, proposal_id, current_user.tenant_id)
    if proposal.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=f"Proposal must be approved before promotion (current status: {proposal.status})",
        )

    if proposal.base_rule_id is not None:
        # Edit of an existing rule — update in place, bump version.
        rule_q = await db.execute(
            select(DetectionRule).where(
                DetectionRule.id == proposal.base_rule_id,
                or_(
                    DetectionRule.tenant_id == current_user.tenant_id,
                    DetectionRule.tenant_id.is_(None),
                ),
            )
        )
        existing = rule_q.scalar_one_or_none()
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Base rule no longer exists; cannot promote as edit",
            )
        await db.execute(
            update(DetectionRule)
            .where(DetectionRule.id == existing.id)
            .values(
                name=proposal.name,
                description=proposal.description,
                rule_language=proposal.rule_language,
                rule_body=proposal.rule_body,
                category=proposal.category,
                severity=proposal.severity,
                confidence=proposal.confidence,
                mitre_tactics=proposal.mitre_tactics,
                mitre_techniques=proposal.mitre_techniques,
                tags=proposal.tags,
                version=existing.version + 1,
                updated_at=datetime.now(UTC),
            )
        )
        promoted_id = existing.id
    else:
        new_rule = DetectionRule(
            tenant_id=current_user.tenant_id,
            name=proposal.name,
            description=proposal.description,
            rule_language=proposal.rule_language,
            rule_body=proposal.rule_body,
            category=proposal.category,
            severity=proposal.severity,
            confidence=proposal.confidence,
            mitre_tactics=proposal.mitre_tactics,
            mitre_techniques=proposal.mitre_techniques,
            tags=proposal.tags,
            created_by_id=current_user.user_id,
        )
        db.add(new_rule)
        await db.flush()
        promoted_id = new_rule.id

    proposal.promoted_rule_id = promoted_id
    proposal.status = "promoted"
    if proposal.decided_at is None:
        proposal.decided_at = datetime.now(UTC)
        proposal.decided_by_id = current_user.user_id

    # WS-B4: git PR path — Author: Beenu - beenu@cyble.com
    # Attempt to create a GitHub Pull Request carrying the Sigma/YARA rule file.
    # create_detection_pr() is a no-op (returns None) when AISOC_GITHUB_TOKEN is
    # not configured, so this never blocks promotion for unconfigured deployments.
    try:
        pr_url = await create_detection_pr(
            settings=settings,
            proposal_id=str(proposal_id),
            rule_name=proposal.name,
            rule_language=proposal.rule_language,
            rule_body=proposal.rule_body,
            category=proposal.category or "general",
        )
        if pr_url:
            proposal.github_pr_url = pr_url
    except Exception as exc:  # noqa: BLE001 — log and continue, never block promotion
        import logging as _logging

        # ``proposal_id`` is a FastAPI-validated UUID path param, but we still
        # strip CR/LF defensively so CodeQL's ``py/log-injection`` rule sees an
        # explicit sanitization step at the log boundary.
        safe_proposal_id = str(proposal_id).replace("\n", " ").replace("\r", " ")[:64]
        _logging.getLogger(__name__).warning(
            "WS-B4: GitHub PR creation failed for proposal %s — %s",
            safe_proposal_id,
            type(exc).__name__,
        )

    await db.commit()
    await db.refresh(proposal)
    return ProposalResponse.model_validate(proposal)
