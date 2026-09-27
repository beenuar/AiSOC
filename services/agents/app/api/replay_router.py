"""Expose the replay runner so the API can orchestrate an evaluation.

Gap-closure Phase 1.4.

Phase 1.2 built ``app.replay.ReplayRunner``: it drives the production triage
path over a frozen historical window and writes nothing. Nothing called it.
This is the route that does, and it is the second of the two internal routes
the orchestration in ``services/api`` needs.

The tenant comes from the credential
------------------------------------
There is no ``tenant_id`` field on the request. The caller is either a console
session, whose token carries a verified tenant claim, or the API acting as a
trusted service, which declares the tenant it is acting for on
``X-AiSOC-Tenant-ID``. Both resolve through the vendored
``app.security.tenant_scope``, and a service token with no tenant header
resolves to an empty scope that refuses rather than widens.

That matters more here than on a read route. The tenant travels into the
envelope handed to triage, so a caller-supplied tenant would decide which
customer's business-context rules and institutional memory the graded verdict
was produced under.

This route writes nothing either
--------------------------------
The runner constructs the production worker with a
:class:`~app.replay.shadow.ShadowTriageWriter`, and the response carries the
attempted-write counters so the caller can assert on a number rather than on
an absence. Those counters travel into the report's method section.
"""

from __future__ import annotations

from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.replay import (
    DEFAULT_TRAIN_FRACTION,
    ContextSnapshot,
    HistoricalFinding,
    NormalizerUnavailable,
    ReplayRunner,
    capture_context,
    split_by_time,
)
from app.replay.connector_normalizer import fetch_normalized
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/replay", tags=["replay"])

ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]

#: Matches ``MAX_NORMALIZE_ROWS`` on the connectors service. A window larger
#: than one normalize batch would have to be split, and a split batch is a
#: second ordering to get wrong.
MAX_FINDINGS = 2000


class FrozenContext(BaseModel):
    """Organisation memory and outcome priors as the caller captured them.

    Optional. When absent the snapshot is empty, which is the honest default:
    an empty frozen context grades the agent with no institutional memory at
    all, which understates production rather than overstating it.

    Priors are deliberately not derived from the train window's labels here or
    anywhere. A human-authored prior suppresses a matching repeat without
    re-triage, so seeding priors from ground truth would score the ground
    truth.
    """

    statements: list[dict[str, Any]] = Field(default_factory=list)
    priors: dict[str, dict[str, Any]] = Field(default_factory=dict)


class ReplayRequest(BaseModel):
    """One window of closed findings, and the connector whose mapping to use."""

    #: The connector id whose ``normalize()`` the connectors service should
    #: run. Not a vendor name: two deployments of the same vendor can be
    #: reached by different connectors.
    connector_id: str = Field(..., min_length=1)
    #: ``ClosedFinding.as_dict()`` rows from the actions service.
    findings: list[dict[str, Any]] = Field(..., min_length=1)
    train_fraction: float = Field(default=DEFAULT_TRAIN_FRACTION, gt=0.0, lt=1.0)
    context: FrozenContext | None = None


class ReplayResponse(BaseModel):
    decisions: list[dict[str, Any]]
    #: Split point, frozen-context provenance, attempted writes and the
    #: enrichment gaps a replayed envelope does not carry. Travels into the
    #: report so a reader can decide whether to believe the numbers.
    method: dict[str, Any]


@router.post("/run", response_model=ReplayResponse, summary="Replay closed findings through production triage")
async def run_replay(body: ReplayRequest, principal: ScopedPrincipal) -> ReplayResponse:
    """Split, freeze, and replay the test window, writing nothing.

    Every failure here is a refusal with a reason rather than a short result.
    A replay that could not normalize its input, or whose history has no
    usable close times, has nothing to measure, and returning a partial run
    would publish a number over whichever rows happened to survive.
    """
    tenant_id = scoped_tenant_or_403(principal)

    if len(body.findings) > MAX_FINDINGS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"{len(body.findings)} findings exceeds the {MAX_FINDINGS}-finding limit for one replay; "
                f"narrow the window rather than grading a truncated one"
            ),
        )

    try:
        findings = [HistoricalFinding.from_mapping(row) for row in body.findings]
    except ValueError as exc:
        # An unparseable close time is refused rather than defaulted. A
        # finding with an invented close time lands on whichever side of the
        # split the default happens to fall, which is a leak wearing a
        # plausible timestamp.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    # The split is computed here rather than left to the runner, because the
    # frozen context has to be captured *at* the split instant and the runner
    # refuses a snapshot taken at any other one. Running the replay twice to
    # discover the split would place every model call twice.
    try:
        split = split_by_time(findings, train_fraction=body.train_fraction)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    if body.context is None:
        snapshot = ContextSnapshot(split_at=split.split_at)
    else:
        snapshot = capture_context(
            split_at=split.split_at,
            statements=body.context.statements,
            priors=body.context.priors,
        )

    try:
        normalizer = await fetch_normalized(
            body.connector_id,
            [dict(f.raw) for f in findings],
            tenant_id=str(tenant_id),
        )
    except NormalizerUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"replay cannot reach the production normalizer: {exc}",
        ) from exc

    runner = ReplayRunner(
        normalizer=normalizer,
        tenant_id=str(tenant_id),
        connector_id=body.connector_id,
    )

    try:
        run = await runner.run(findings, snapshot=snapshot, train_fraction=body.train_fraction)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    logger.info(
        "replay.run.completed",
        tenant_id=str(tenant_id),
        connector_id=body.connector_id,
        findings=len(findings),
        decisions=len(run.decisions),
        writes_attempted=sum(run.writes_attempted.values()),
    )
    return ReplayResponse(
        decisions=[d.as_dict() for d in run.decisions],
        method=run.method(),
    )
