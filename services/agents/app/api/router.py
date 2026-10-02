"""
Agent service REST API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from app.graph.runner import run_full_investigation
from app.hunt.agent import run_hunt
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

    result = await run_hunt(hypothesis, invoke=_invoke, run_id=run_id)
    logger.info(
        "hunt.completed",
        extra={"tenant_id": str(tenant_id), "run_id": run_id, "checked": result.checked},
    )
    return HuntResponse(
        hypothesis=result.hypothesis,
        checked=result.checked,
        matches=list(getattr(result, "matches", []) or []),
        refusals=list(result.refusals or []),
        unavailable_reason=result.unavailable_reason,
    )


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-agents"}
