"""Detection-as-code proposal lifecycle endpoints (Wave 2 — w2-dac).

Surfaces the propose → review → eval-gated → promote flow that brings
detections under the same CI gate as agent prompts. The eval gate is
satisfied by `scripts/run_evals.py` running offline; the result of that
run is stored back on the proposal as ``eval_result`` and a candidate
that regresses MITRE accuracy by ≥ ``max_regression_pp`` percentage
points cannot be promoted.

Endpoints
---------
* ``GET    /detection-proposals``                     List proposals.
* ``POST   /detection-proposals``                     Create a proposal.
* ``GET    /detection-proposals/{id}``                Proposal detail.
* ``POST   /detection-proposals/{id}/comment``        Add a review comment.
* ``POST   /detection-proposals/{id}/eval``           Attach eval result + verdict.
* ``POST   /detection-proposals/{id}/decide``         Approve/reject a proposal.
* ``POST   /detection-proposals/{id}/promote``        Materialise into ``detection_rules``.
* ``GET    /detection-proposals/baselines``           List eval baselines.
* ``POST   /detection-proposals/baselines``           Record a new baseline.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
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

router = APIRouter(prefix="/detection-proposals", tags=["detection_rules", "dac"])


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
            "Full JSON output of `python3 scripts/run_evals.py --baseline ... "
            "--max-regression-pp ...` for the candidate ruleset."
        ),
    )
    max_regression_pp: float = Field(
        default=1.0,
        ge=0.0,
        le=100.0,
        description="Allowed MITRE accuracy regression vs baseline, in pp.",
    )


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str | None = Field(default=None, max_length=2000)


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
        baseline = float(
            cmp.get("deltas", {}).get("mitre_accuracy", {}).get("baseline", baseline_score or candidate_score)
        )
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
        select(DetectionRuleProposal)
        .where(and_(*filters))
        .order_by(DetectionRuleProposal.created_at.desc())
        .limit(limit)
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
    result = await db.execute(
        select(DetectionEvalBaseline)
        .where(and_(*filters))
        .order_by(DetectionEvalBaseline.created_at.desc())
    )
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

    proposal.eval_result = verdict
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
        eval_passed = bool(proposal.eval_result.get("passed")) if proposal.eval_result else False
        if not eval_passed:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail="Eval gate has not passed; cannot approve. Run the eval suite and attach the report first.",
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
    await db.commit()
    await db.refresh(proposal)
    return ProposalResponse.model_validate(proposal)
