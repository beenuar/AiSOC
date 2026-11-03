"""
Agent service REST API.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from app.graph.runner import run_full_investigation
from app.hunt import from_report, source_report_store
from app.hunt.agent import run_hunt
from app.hunt.plan import HUNT_FIELDS
from app.investigator import ledger as ledger_module
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model
from app.models.state import AgentTask, InvestigationState
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)

logger = structlog.get_logger(__name__)

router = APIRouter()

#: The console reaches this service directly through a Next rewrite, sending
#: the first-party access token as a bearer credential. The tenant comes from
#: that verified token; a `tenant_id` on the request is only ever a filter,
#: intersected with it, so naming a foreign tenant is a 403 rather than a
#: selector for somebody else's investigation.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]

# In-memory run store for status polling. The durable record of every step is
# the Postgres Investigation Ledger (written by the shared graph runner) — this
# dict is only the fast local status cache for GET /agent-runs/{run_id}.
_runs: dict[str, dict] = {}


class InvestigationRequest(BaseModel):
    incident_id: UUID
    tenant_id: UUID
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    task: AgentTask = AgentTask.INVESTIGATION


class InvestigationResponse(BaseModel):
    run_id: UUID
    status: str
    message: str


async def _run_investigation(run_id: str, state: InvestigationState) -> None:
    """Run investigation in background and store results.

    Uses the SAME durable graph runner as the Kafka auto-triage worker
    (issue #569), so manual and automated investigations share one
    orchestration implementation and both persist every step to the ledger.
    """
    try:
        result = await run_full_investigation(state)
        _runs[run_id] = {
            "status": "completed",
            "result": result.to_dict(),
            "completed_at": datetime.utcnow().isoformat(),
        }
    except Exception as exc:  # noqa: BLE001 — surface failure via the status cache
        _runs[run_id] = {"status": "failed", "error": str(exc)}


# `/agent-runs`, not `/investigations`. Both this module and
# `app.api.investigate` registered `GET /api/v1/investigations/{run_id}`,
# each reading its own `_runs` dict, and this one is mounted first
# (`main.py` includes `router` before `investigate_router`) so it answered
# every poll from the store that the other module writes to. The result was
# a 404 for a run that existed, while the sibling report routes under the
# same prefix worked, which is why it read as a flaky console rather than a
# routing bug.
#
# `app.api.investigate` owns the lifecycle and the report routes, so it
# keeps the canonical path. This pair is the in-process orchestrator state
# and has no caller: the console's ledger reads go to the API service, which
# `apps/web/next.config.js` documents and deliberately does not rewrite here.
@router.post("/agent-runs", response_model=InvestigationResponse)
async def start_investigation(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
    principal: ScopedPrincipal,
):
    """Start a new automated investigation for an incident."""
    run_id = str(uuid4())
    state = InvestigationState(
        run_id=UUID(run_id),
        incident_id=request.incident_id,
        tenant_id=scoped_tenant_or_403(principal, request.tenant_id),
        task=request.task,
        alert_summary=request.alert_summary,
        raw_alert=request.raw_alert,
    )
    _runs[run_id] = {"status": "running", "started_at": datetime.utcnow().isoformat()}
    background_tasks.add_task(_run_investigation, run_id, state)

    return InvestigationResponse(
        run_id=UUID(run_id),
        status="running",
        message="Investigation started",
    )


@router.get("/agent-runs/{run_id}")
async def get_investigation(run_id: str, principal: ScopedPrincipal):
    """Get the status and results of an investigation run."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    return run


class HuntRequest(BaseModel):
    """One natural-language hypothesis to hunt against tenant data."""

    tenant_id: UUID
    hypothesis: str


class HuntResponse(BaseModel):
    """What the hunt found, or why it could not look.

    `checked` and `unavailable_reason` are separate fields on purpose. A
    hunt that could not run is not a hunt that found nothing, and
    collapsing the two is how a console ends up showing a reassuring
    empty result for a search that never happened.
    """

    hypothesis: str
    checked: bool
    matches: list[dict[str, Any]] = []
    refusals: list[str] = []
    unavailable_reason: str | None = None


@router.post("/hunt", response_model=HuntResponse)
async def run_nl_hunt(request: HuntRequest, principal: ScopedPrincipal) -> HuntResponse:
    """Plan and run one natural-language hunt.

    This route is what takes `app/hunt/agent.py` off the unreachable
    list. The agent was complete and tested, and its only importer
    repo-wide was its own test — a passing test on a function nothing
    calls is indistinguishable from a working feature until someone
    traces the call graph.

    The model never writes a query. `plan_hunt` asks it for a *plan*,
    validates every attempt against the allowed shape, and records each
    refusal; `execute_plan` runs the validated plan. A refusal is
    returned rather than swallowed, because "the model proposed
    something I would not run" is information an analyst should see.
    """
    tenant_id = scoped_tenant_or_403(principal, request.tenant_id)
    hypothesis = request.hypothesis.strip()
    if not hypothesis:
        raise HTTPException(status_code=422, detail="hypothesis must not be empty")

    run_id = str(uuid4())
    model = make_chat_model("hunt", json_output=True)

    async def _invoke(messages: list[dict[str, str]]) -> Any:
        # Through `safe_ainvoke`, so the LLM input contract applies here
        # exactly as it does on every other call site in this service.
        return await safe_ainvoke(model, messages)

    # The real ledger module, not `None`. This passed no ledger at all, so
    # `_record` returned at its first line and **no hunt had ever written a
    # ledger row** -- while the agent's own suite asserted on ledger writes
    # against a double it supplied itself.
    result = await run_hunt(
        hypothesis,
        invoke=_invoke,
        run_id=run_id,
        tenant_id=str(tenant_id),
        ledger=ledger_module,
    )
    logger.info(
        "hunt.completed",
        extra={"tenant_id": str(tenant_id), "run_id": run_id, "checked": result.checked},
    )
    return HuntResponse(
        hypothesis=result.hypothesis,
        checked=result.checked,
        # `HuntAgentResult.findings`, not `matches`. This read `getattr(result,
        # "matches", [])`, and the attribute has never existed, so the default
        # swallowed it: every hunt that found rows answered `checked: true,
        # matches: []`, which reads as a clean result rather than as an answer
        # dropped on the way out.
        matches=list(result.findings or []),
        refusals=list(result.refusals or []),
        unavailable_reason=result.unavailable_reason,
    )


class ReportDraftRequest(BaseModel):
    """A published write-up to read indicators out of, for review."""

    tenant_id: UUID
    url: str


class ReportDraftResponse(BaseModel):
    """What a reviewer is shown. Deliberately not a hunt.

    This route drafts and stops. The indicators came out of a document
    somebody else published, so turning them straight into a query would
    let the author of a write-up choose what this tenant searches for.
    `clauses` is what *would* run if a human approves it, and `refusals`
    names every indicator that would not, because "the draft dropped
    something" is information a reviewer needs before approving the rest.
    """

    url: str
    byte_size: int
    content_sha256: str
    truncated: bool
    indicators: list[dict[str, Any]] = []
    techniques: list[str] = []
    skipped_indicators: int = 0
    clauses: list[dict[str, str]] = []
    refusals: list[str] = []
    #: The `hunt_source_reports` row this draft was recorded as, or None when
    #: it could not be. Reported rather than implied: a draft whose provenance
    #: was not stored is still usable, and six weeks later the difference
    #: between "no record" and "a record nobody told you about" is the whole
    #: question an analyst is asking.
    report_id: str | None = None
    #: NULL `approved_at` must never render as approved — migration 155 says
    #: so in the column's own comment — so a fresh draft says it outright.
    approved: bool = False


class ReportApprovalResponse(BaseModel):
    report_id: str
    approved: bool
    approved_at: str | None = None
    detail: str


@router.post("/hunt/from-report", response_model=ReportDraftResponse)
async def draft_hunt_from_report(request: ReportDraftRequest, principal: ScopedPrincipal) -> ReportDraftResponse:
    """Read a published report and draft the hunt it implies.

    This route is what takes `app/hunt/from_report.py` off the unreachable
    list, for the same reason `/hunt` above took `app/hunt/agent.py` off it:
    the module was complete and tested and its only importer repo-wide was
    its own test, which proves the code compiles rather than that it runs.

    Three properties the module owns and this route must not undo:

    * **Outbound fetching is off unless a tenant turned it on.** `enabled`
      is a required keyword on `fetch_report`, so a caller cannot acquire
      it by forgetting an argument. Here it comes from
      `AISOC_HUNT_REPORT_FETCH_ENABLED`, default off, because it is
      outbound traffic to a URL a caller chose.
    * **The URL goes through the SSRF guard and a hard size bound** inside
      `fetch_report`; the body is abandoned past the bound rather than
      trusted to a `Content-Length` the fetched server supplies.
    * **Nothing is hunted.** The draft is returned for a human to approve.
    """
    tenant_id = scoped_tenant_or_403(principal, request.tenant_id)
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="url must not be empty")

    enabled = os.environ.get("AISOC_HUNT_REPORT_FETCH_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        text, truncated = await from_report.fetch_report(url, enabled=enabled)
    except from_report.ReportDisabled as exc:
        # 403, not 503: the deployment answered, and the answer is "no".
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except from_report.ReportFetchError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    indicators, techniques, skipped = from_report.extract_indicators(text)
    clauses, refusals = from_report.draft_clauses(indicators, allowed_fields=frozenset(HUNT_FIELDS))
    draft = from_report.ReportDraft(
        url=url,
        byte_size=len(text.encode("utf-8")),
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        indicators=indicators,
        techniques=techniques,
        truncated=truncated,
        skipped_indicators=skipped,
    )
    logger.info(
        "hunt.report_drafted",
        extra={
            "tenant_id": str(tenant_id),
            "indicators": len(indicators),
            "refusals": len(refusals),
            "truncated": truncated,
        },
    )
    # Persist the provenance. This route used to compute exactly the columns
    # of `hunt_source_reports` and return them without writing a row, leaving
    # the table a pure orphan: `approved_at` had no writer and the migration's
    # stated property — nothing is hunted from a report until it is set — was
    # enforced by nobody. Fail-soft, because a provenance write must not cost
    # an analyst their draft; `report_id: null` says so rather than implying a
    # record exists.
    report_id = await source_report_store.record_report(
        tenant_id=str(tenant_id),
        url=url,
        fetched_by=str(getattr(principal, "user_id", "") or "") or None,
        byte_size=draft.byte_size,
        content_sha256=draft.content_sha256,
        truncated=truncated,
        indicator_count=len(indicators),
        technique_count=len(techniques),
    )
    payload = draft.as_dict()
    return ReportDraftResponse(**payload, clauses=clauses, refusals=refusals, report_id=report_id, approved=False)


@router.post("/hunt/from-report/{report_id}/approve", response_model=ReportApprovalResponse)
async def approve_hunt_report(report_id: str, principal: ScopedPrincipal) -> ReportApprovalResponse:
    """Record that a person reviewed this report's extracted indicators.

    Migration 155 states the property this writes: *"Nothing is hunted from a
    report until this is set, so NULL must never be rendered as approved."*
    Until this endpoint existed the column had no writer at all, so the
    sentence described an intention rather than a control.

    404 rather than 403 on another tenant's id, so the route is not an
    existence oracle over every tenant's report ids. A second approval is
    reported as already-approved rather than moving the timestamp: the review
    that counts is the one that happened.
    """
    tenant_id = scoped_tenant_or_403(principal, None)
    try:
        newly_approved = await source_report_store.approve_report(
            tenant_id=str(tenant_id),
            report_id=report_id,
            approved_by=str(getattr(principal, "user_id", "") or "") or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{report_id!r} is not a report id") from exc
    except Exception as exc:  # noqa: BLE001 — an unrecordable approval is not an approval
        logger.error("hunt.report_approval_failed", extra={"report_id": report_id, "error": str(exc)})
        raise HTTPException(status_code=503, detail="the approval could not be recorded, so nothing was approved") from exc

    stored = await source_report_store.get_report(tenant_id=str(tenant_id), report_id=report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="no such hunt source report")
    approved_at = stored.get("approved_at")
    return ReportApprovalResponse(
        report_id=report_id,
        approved=approved_at is not None,
        approved_at=approved_at.isoformat() if approved_at is not None else None,
        detail=("approved" if newly_approved else "already approved; the recorded review is the first one"),
    )


@router.get("/hunt/from-report", response_model=list[dict])
async def list_hunt_reports(principal: ScopedPrincipal) -> list[dict]:
    """Reports this tenant has drafted from, newest first, with their review state."""
    tenant_id = scoped_tenant_or_403(principal, None)
    rows = await source_report_store.list_reports(tenant_id=str(tenant_id))
    return [
        {
            **{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in row.items() if k != "approved_by"},
            "approved": row.get("approved_at") is not None,
            "approved_by": str(row["approved_by"]) if row.get("approved_by") else None,
        }
        for row in rows
    ]


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-agents"}
