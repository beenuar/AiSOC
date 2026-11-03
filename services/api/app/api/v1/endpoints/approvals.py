"""Agent approval endpoints for the mobile responder PWA.

Whenever an agent wants to take a high-risk action (isolate host,
disable user, run a destructive playbook step), it stops and emits an
approval request that lands here. The PWA polls and subscribes to push
notifications so the on-call analyst can approve or deny in one tap,
even from a phone.

That was the design, and for both of its halves it was only the design.
Nothing in the repository called ``POST /approvals``, so the queue had no
producer and the responder app's approvals screen was structurally empty; and
``decide`` flipped a row and notified the realtime service without ever
reaching ``services/actions``, so the queue had no executor either. Tapping
Approve recorded a decision and ran nothing, which is worse than a missing
feature: the operator is told the host was contained.

Both halves are closed in v9.0. ``services/agents`` posts here when triage
proposes an action that needs sign-off, and ``decide`` carries the decision
through to the actions service and records on the row whether it executed.

Endpoints
---------
* ``GET    /approvals``           List pending/decided approvals.
* ``GET    /approvals/{id}``      Approval detail (with action payload).
* ``POST   /approvals``           Create one (called by the agent service).
* ``POST   /approvals/{id}/decide`` Approve or deny.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select

from app.api.v1.deps import AuthUser, require_permission
from app.core.config import settings
from app.db.rls import TenantDBSession
from app.models.responder import AgentApproval
from app.services.actions_client import ActionsServiceError, decide_action, submit_action
from app.services.approval_delivery import deliver_approval
from app.services.branding.resolver import resolve_branding

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/approvals", tags=["responder", "approvals"])

_HTTP_TIMEOUT = 5.0
_VALID_STATUSES = {"pending", "approved", "denied", "expired"}


class ApprovalResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    run_id: uuid.UUID | None
    case_id: str | None
    alert_id: uuid.UUID | None
    requested_by: str
    required_user_id: uuid.UUID | None
    required_topic: str | None
    title: str
    summary: str
    risk_level: str
    action: dict
    status: str
    decided_by_id: uuid.UUID | None
    decided_at: datetime | None
    decision_comment: str | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ApprovalListResponse(BaseModel):
    items: list[ApprovalResponse]
    total: int
    page: int
    page_size: int
    pages: int


class ApprovalCreateRequest(BaseModel):
    run_id: uuid.UUID | None = None
    case_id: str | None = Field(default=None, max_length=200)
    alert_id: uuid.UUID | None = None
    requested_by: str = Field(default="agent", max_length=120)
    required_user_id: uuid.UUID | None = None
    required_topic: str | None = Field(default=None, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1)
    risk_level: Literal["low", "medium", "high", "critical"] = "medium"
    action: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approve", "deny"]
    comment: str | None = Field(default=None, max_length=2000)


#: Where the originating identity is kept on the approval row.
#:
#: Inside ``action`` rather than in a column of its own, following the two
#: server-written keys already there (``delivery``, ``dispatch``) and the
#: reasoning migration 055 gives for keeping the record whole: the shape is
#: owned by the thing that writes it, and a column per field makes every
#: contract change a migration.
#:
#: Always overwritten from the authenticated principal at create time and
#: never read out of the request body. ``requested_by`` beside it stays a
#: free-text label — it is caller-supplied, and separation of duties
#: evaluated against it would be forgeable from the body.
_REQUESTER_KEY = "requester_principal"

#: Dispatch states recorded on the approval row.
#:
#: ``dispatching`` is the one that did not exist. ``_dispatch_decision`` ran
#: before ``db.commit()``, so a crash in between left the approval ``pending``
#: against an action that had run — the row's own answer to "was this
#: executed" was silently wrong in the dangerous direction. The decision is
#: now committed first with the dispatch marked in flight, so an interrupted
#: decide is visible rather than invisible.
_DISPATCH_IN_FLIGHT = "dispatching"
#: The actions service was reached and answered.
_DISPATCH_EXECUTED = "executed"
#: Where the separation-of-duties verdict is recorded on the row.
#:
#: Mirrors ``services/actions/app/security/authz.py``, including its reasoning:
#: a control that cannot evaluate a request must say so in the record rather
#: than leave an omission, because afterwards "checked and passed" and "never
#: checked" are indistinguishable.
_SOD_KEY = "separation_of_duties"
_SOD_ENFORCED = "enforced"
_SOD_UNEVALUATED = "unevaluated"
_DISPATCH_DECLINED = "declined"
#: The actions service refused, with a reason.
_DISPATCH_FAILED = "failed"
#: We never heard back. Distinct from ``failed`` because the request may have
#: been processed, and "your action did not run" is a claim the evidence does
#: not support.
_DISPATCH_UNKNOWN = "unknown"
_DISPATCH_NOT_EXECUTABLE = "not_executable"

#: Dispatch states that mean the decision has not finished being carried out.
#: A repeat decide re-enters on these rather than reporting success: the
#: actions service claims an execution durably before contacting a vendor, so
#: a re-entry cannot double-execute — it is answered 409 — and the alternative
#: is an approval whose row says ``approved`` and whose action never ran.
_UNRESOLVED_DISPATCH = frozenset({_DISPATCH_IN_FLIGHT, _DISPATCH_UNKNOWN})


def _requester_principal(user: AuthUser) -> dict[str, Any]:
    """The identity that raised this approval, from authenticated context.

    For an agent-raised approval this is the agents service's own service
    principal; for one a human raised it is that human, which is what keeps
    separation of duties biting on the half where it must.
    """
    return {
        "user_id": str(user.user_id),
        "tenant_id": str(user.tenant_id),
        "email": getattr(user, "email", None),
        "roles": [user.role] if user.role else [],
        "permissions": user.effective_permissions(),
    }


def _dispatch_state(row: AgentApproval) -> str | None:
    dispatch = (row.action or {}).get("dispatch")
    return dispatch.get("state") if isinstance(dispatch, dict) else None


def _stamped_requester_id(row: AgentApproval) -> str | None:
    """The identity that raised this approval, or ``None`` for a legacy row.

    Read from ``action.requester_principal``, which :func:`create_approval`
    writes from authenticated context. Never from ``requested_by``, which is a
    free-text label the caller picks -- a separation-of-duties comparison
    against that would be forgeable from the request body, which is the exact
    defect the actions service was fixed for.
    """
    requester = (row.action or {}).get(_REQUESTER_KEY)
    if not isinstance(requester, dict):
        return None
    user_id = requester.get("user_id")
    return str(user_id) if user_id else None


def _authorize_decision(row: AgentApproval, user: AuthUser, *, approving: bool, enforce_window: bool) -> str:
    """Decide whether this principal may take this decision, now.

    ``require_permission("cases:write")`` on the route answers "may this
    person decide approvals at all". It cannot answer the three questions
    below, each of which is about *this* approval, and none of which was
    asked: GHSA-q388-w896-9jr2.

    One principle governs all three: **approving is the governed act, and
    denying executes nothing.** A denial dispatches a rejection, leaves the
    estate untouched, and is the safe default `approval_expiry` already names
    -- so every rule here narrows who may *approve*, and leaves denial open.
    The alternative was tried on paper and is worse: a requester who cannot
    withdraw their own mistaken request, and an approval routed to somebody on
    leave that nobody can clear, are both pressure to hand out wider
    permissions than the job needs.

    Returns the separation-of-duties state, for the caller to record.
    """
    requester_id = _stamped_requester_id(row)

    # F08. The requester may not approve their own request.
    if approving and requester_id is not None and requester_id == str(user.user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "The principal that requested this approval cannot approve it "
                "(separation of duties). Another holder of cases:write must decide it; "
                "you can still deny it."
            ),
        )

    # F09. An approval addressed to one person is answered by that person.
    #
    # `required_user_id` is written at create time and `list_approvals(mine=true)`
    # filters on it, so the console already presents these as routed. Reading the
    # column only in the list and never in the decision made the routing cosmetic.
    if approving and row.required_user_id is not None and row.required_user_id != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This approval is routed to a specific approver and only they can approve it. "
                "You can deny it, or have it re-raised to a different approver."
            ),
        )

    # F82. The window closes over approval.
    #
    # `enforce_window` is False when re-entering an already-decided row whose
    # dispatch never resolved: that decision *was* taken in time, and the
    # re-entry exists so an approval whose dispatch died is not stranded.
    if approving and enforce_window and row.expires_at is not None:
        deadline = row.expires_at if row.expires_at.tzinfo is not None else row.expires_at.replace(tzinfo=UTC)
        if deadline <= datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"This approval expired at {deadline.isoformat()} and can no longer be approved. "
                    "Nothing was dispatched. Deny it, or raise a new approval against current evidence."
                ),
            )

    if requester_id is None:
        # Pre-v9 rows carry no stamp. Refusing them would strand every approval
        # raised before the identity was recorded, during exactly the incident
        # somebody needs to clear them in -- so this is a recorded fact, not a
        # denial, and the row says afterwards which it was.
        logger.warning(
            "Approval decision: separation of duties could not be evaluated",
            extra={"approval_id": str(row.id), "reason": "the row carries no requester principal"},
        )
        return _SOD_UNEVALUATED
    return _SOD_ENFORCED


@router.get("", response_model=ApprovalListResponse)
async def list_approvals(
    user: AuthUser,
    db: TenantDBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    status_filter: str | None = Query(default="pending", alias="status"),
    mine: bool = Query(default=False),
    risk_level: str | None = Query(default=None),
) -> ApprovalListResponse:
    """List approvals for the current tenant.

    Defaults to ``status=pending`` so the PWA inbox view is fast.
    Set ``mine=true`` to only show approvals routed specifically to the
    current user.
    """
    filters = [AgentApproval.tenant_id == user.tenant_id]
    if status_filter:
        if status_filter not in _VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of {_VALID_STATUSES}",
            )
        filters.append(AgentApproval.status == status_filter)
    if mine:
        filters.append(AgentApproval.required_user_id == user.user_id)
    if risk_level:
        filters.append(AgentApproval.risk_level == risk_level)

    count_stmt = select(func.count()).select_from(AgentApproval).where(and_(*filters))
    total = (await db.execute(count_stmt)).scalar_one()

    stmt = (
        select(AgentApproval)
        .where(and_(*filters))
        .order_by(AgentApproval.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(stmt)).scalars().all()

    return ApprovalListResponse(
        items=[ApprovalResponse.model_validate(row) for row in rows],
        total=int(total),
        page=page,
        page_size=page_size,
        pages=max(1, (int(total) + page_size - 1) // page_size),
    )


@router.get("/{approval_id}", response_model=ApprovalResponse)
async def get_approval(
    approval_id: uuid.UUID,
    user: AuthUser,
    db: TenantDBSession,
) -> ApprovalResponse:
    row = (
        await db.execute(
            select(AgentApproval).where(
                AgentApproval.id == approval_id,
                AgentApproval.tenant_id == user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
    return ApprovalResponse.model_validate(row)


# `approvals:write` rather than `cases:write`, and the difference is the whole
# reason it exists. The agents service's playbook engine must open an approval
# when a step needs human sign-off, and it reaches this route on the shared
# service token — whose permission set is a deliberately short read-only list,
# because that one credential is valid on every route for every tenant. Adding
# `cases:write` to it to unblock one POST would also have handed it case
# authoring, case deletion and every other write on the case surface.
#
# Every role that held `cases:write` was granted `approvals:write` in the same
# commit, so no operator lost access; the only principal that gains anything is
# the service, and only this one verb. `/{id}/decide` deliberately still
# requires `cases:write`: a service that can raise an approval must not be able
# to answer it.
@router.post("", response_model=ApprovalResponse, status_code=status.HTTP_201_CREATED)
async def create_approval(
    body: ApprovalCreateRequest,
    user: Annotated[AuthUser, Depends(require_permission("approvals:write"))],
    db: TenantDBSession,
) -> ApprovalResponse:
    """Create a new approval request. Requires `approvals:write`.

    The agents service calls this when it hits a high-risk step that
    requires human sign-off. We persist it, then fan-out a Web Push
    notification via the realtime service so the PWA buzzes the right
    on-call analyst.
    """
    row = AgentApproval(
        tenant_id=user.tenant_id,
        run_id=body.run_id,
        case_id=body.case_id,
        alert_id=body.alert_id,
        requested_by=body.requested_by,
        required_user_id=body.required_user_id,
        required_topic=body.required_topic,
        title=body.title,
        summary=body.summary,
        risk_level=body.risk_level,
        action={**(body.action or {}), _REQUESTER_KEY: _requester_principal(user)},
        expires_at=body.expires_at,
        status="pending",
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    # Best-effort push notification — failure must not block the agent run.
    await _notify_realtime(row, event="approval_request")

    # Depth 5.2. Push was the only channel that ever fired. The email
    # sender, the Slack card route and the Teams card builder all existed
    # and were reached by nothing, so an approval raised by an agent waited
    # for somebody to open the console and notice it. The fan-out never
    # raises: the row is already durable, and a channel that is down must
    # leave a record saying so rather than take the approval with it.
    # Resolved here because this is the only layer holding both the session
    # and the authenticated tenant. The fan-out took no branding at all when
    # the three channels were unified, so every approval mail rendered the
    # platform palette no matter what the operator had configured --
    # `send_approval_email` has accepted a `branding` argument throughout and
    # nothing passed one.
    delivery = await deliver_approval(row, await resolve_branding(db, user.tenant_id))
    row.action = {**(row.action or {}), "delivery": delivery.as_dict()}
    await db.commit()
    await db.refresh(row)

    return ApprovalResponse.model_validate(row)


@router.post("/{approval_id}/decide", response_model=ApprovalResponse)
async def decide_approval(
    approval_id: uuid.UUID,
    body: ApprovalDecisionRequest,
    user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: TenantDBSession,
) -> ApprovalResponse:
    """Approve or deny a pending approval.

    Idempotent only on the same decision: re-approving an already
    approved request returns the row unchanged; trying to flip an
    approved row to denied (or vice versa) is a 409.

    Separation of duties, the named approver and the approval window are each
    enforced; a requester cannot approve their own request, and an elapsed
    approval can be denied but not approved.
    """
    # The paragraph above is a *published* description -- this docstring is
    # exported into `docs/openapi.yaml`, so it says what a caller must know
    # and does not name internals. The mechanism is `_authorize_decision`:
    # `cases:write` on the dependency answers "may this person decide
    # approvals at all" and nothing more, and the three questions about
    # *this* approval are asked there.
    row = (
        await db.execute(
            select(AgentApproval).where(
                AgentApproval.id == approval_id,
                AgentApproval.tenant_id == user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")

    new_status = "approved" if body.decision == "approve" else "denied"
    unresolved = _dispatch_state(row) in _UNRESOLVED_DISPATCH

    if row.status == new_status and not unresolved:
        return ApprovalResponse.model_validate(row)
    if row.status not in {"pending", "expired"} and row.status != new_status:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval already {row.status}; cannot change to {new_status}",
        )

    # Everything from here writes a decision, so this is where it is authorized.
    # Placed after the idempotent return above and before the first mutation,
    # so re-entering a stalled dispatch is governed too -- re-driving a
    # containment is an act, even when the row already records the verdict.
    sod = _authorize_decision(
        row,
        user,
        approving=body.decision == "approve",
        # The window governs a *new* decision. A row already carrying a verdict
        # had that verdict taken in time; re-entry is finishing the dispatch.
        enforce_window=row.status not in {"approved", "denied"},
    )

    row.status = new_status
    row.decided_by_id = user.user_id
    row.decided_at = datetime.now(UTC)
    row.decision_comment = body.comment

    # Commit the decision with the dispatch marked in flight, *then* dispatch.
    #
    # The order used to be the other way round, with a comment explaining that
    # dispatching first stopped a refused action leaving a row reading
    # "approved". It did, and it opened a worse hole: the dispatch ran at one
    # line and `db.commit()` at the next, so a crash in between left the
    # approval `pending` against an action that had already contained a host.
    # Nothing in the row said a dispatch had been attempted, so the recovery
    # was to approve it again.
    #
    # Writing the attempt first costs the thing the old comment protected —
    # the window where the row says approved and the action has not run yet —
    # and that window is now *visible*, which is the property that matters:
    # `dispatch.state` says `dispatching`, a repeat decide re-enters, and the
    # actions service's durable claim is what stops a re-entry from executing
    # twice.
    row.action = {
        **(row.action or {}),
        _SOD_KEY: sod,
        "dispatch": {"state": _DISPATCH_IN_FLIGHT, "started_at": datetime.now(UTC).isoformat()},
    }
    await db.commit()

    dispatch = await _dispatch_decision(row, user, approve=body.decision == "approve")
    row.action = {**(row.action or {}), "dispatch": dispatch}

    await db.commit()
    await db.refresh(row)

    # Notify the agents service (and any other listener) so the run can
    # resume — fire-and-forget pattern matches the rest of the surface.
    await _notify_realtime(row, event="approval_decided")

    if dispatch.get("state") == _DISPATCH_FAILED:
        # The decision is durable and the operator is told the truth: their
        # choice was recorded, the execution behind it was not accepted.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Decision recorded, but the action service refused it: {dispatch.get('detail')}. "
                "The approval row reflects your decision; the action did not run."
            ),
        )
    if dispatch.get("state") == _DISPATCH_UNKNOWN:
        # Deliberately not phrased as a failure. The action service may have
        # executed this; it claims an execution durably before touching a
        # vendor, so the answer exists and nobody should act on a guess.
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=(
                f"Decision recorded, but the action service did not answer: {dispatch.get('detail')}. "
                "Whether the action ran is not yet known — check the action's status before deciding again."
            ),
        )

    return ApprovalResponse.model_validate(row)


async def _dispatch_decision(
    row: AgentApproval,
    user: AuthUser,
    *,
    approve: bool,
) -> dict[str, Any]:
    """Carry a decision through to ``services/actions``.

    Returns a provenance record that is stored on the approval, so "was this
    actually executed" is answerable from the row rather than by correlating
    two services' logs. The four states are deliberately distinct:

    ``not_executable``  the approval names no action type, so there is
                        nothing to run. Common and fine: an approval can
                        gate a human step.
    ``declined``        the decision was to deny; the action was rejected
                        upstream so it cannot later be approved by replay.
    ``executed``        the actions service accepted and ran it.
    ``failed``          the actions service refused, with a reason.
    ``unknown``         we never heard back. The request may have been
                        processed; the actions service claims an execution
                        durably before contacting a vendor, so the answer
                        exists upstream and must be read rather than guessed.
    """
    action = row.action or {}
    action_type = action.get("action_type") or action.get("type")
    target = action.get("target")
    if not isinstance(action_type, str) or not action_type.strip():
        return {"state": _DISPATCH_NOT_EXECUTABLE, "reason": "approval carries no action_type"}
    if not isinstance(target, str) or not target.strip():
        return {"state": _DISPATCH_NOT_EXECUTABLE, "reason": "approval carries no target"}

    # The approval id is reused as the action id so the two systems share one
    # identifier. Without that, "which action did this approval authorise"
    # requires a join nobody wrote.
    action_id = str(row.id)
    # `CurrentUser` has `role` (singular), `scopes` and `resolved_permissions`.
    # This used to read `user.roles` and `user.permissions` through
    # `getattr(..., [])`, and since neither attribute exists both defaults
    # fired silently -- so the actions service received an empty permission
    # list, `has_action_permission` denied unconditionally, and *every*
    # approval came back 502 with the decision already recorded.
    #
    # Resolved by the principal rather than here on purpose: a route deciding
    # its own permissions is what `check_one_permission_model` refuses, and
    # `effective_permissions()` uses the same scopes -> resolved -> role order
    # as `require_permission`, so one principal cannot be allowed to approve
    # something it would be refused for elsewhere.
    permissions = user.effective_permissions()
    principal = {
        "user_id": str(user.user_id),
        "tenant_id": str(user.tenant_id),
        "email": getattr(user, "email", None),
        # Singular on this class; sent as a list because that is the shape
        # `services/actions` reads.
        "roles": [user.role] if user.role else [],
        "permissions": permissions,
    }

    # Who originally asked, stamped onto the row from authenticated context
    # when the approval was created. Sent as `requester`, a separate field
    # from `principal`, because the actions service records the requester for
    # separation of duties: sending the deciding user as `principal` made
    # them the requester too, so every approval was refused upstream as its
    # own request and surfaced here as a 502.
    #
    # Falls back to this caller only when the approval predates the stamp, in
    # which case separation of duties has nothing to compare and the actions
    # service records that rather than claiming it passed.
    requester = action.get(_REQUESTER_KEY)
    if not isinstance(requester, dict) or not requester.get("user_id"):
        requester = None

    try:
        await submit_action(
            action_id=action_id,
            action_type=action_type.strip(),
            target=target.strip(),
            tenant_id=str(row.tenant_id),
            incident_id=str(row.run_id or row.id),
            rationale=row.summary or row.title,
            parameters=action.get("parameters") or {},
            # A label, not an identity. The authorization basis is `requester`.
            requested_by=row.requested_by or "agent",
            # Identifies the caller to the gate. Omitting it was harmless only
            # while `AISOC_ACTIONS_REQUIRE_PRINCIPAL` defaults false; turning
            # that on would have broken the submit leg exactly as the decide
            # leg was broken.
            principal=principal,
            requester=requester,
        )
    except ActionsServiceError as exc:
        logger.warning(
            "Approval dispatch: submit refused",
            extra={"approval_id": action_id, "status": exc.status_code, "detail": str(exc)},
        )
        # A submit that was never acknowledged has still not authorized
        # anything: the actions service gates before it executes, and the
        # decide leg below is what would have released it.
        state = _DISPATCH_UNKNOWN if exc.indeterminate else _DISPATCH_FAILED
        return {"state": state, "stage": "submit", "detail": str(exc)}

    try:
        result = await decide_action(action_id=action_id, approve=approve, approver=principal)
    except ActionsServiceError as exc:
        logger.warning(
            "Approval dispatch: decision not confirmed",
            extra={"approval_id": action_id, "status": exc.status_code, "detail": str(exc), "indeterminate": exc.indeterminate},
        )
        state = _DISPATCH_UNKNOWN if exc.indeterminate else _DISPATCH_FAILED
        return {"state": state, "stage": "decide", "action_id": action_id, "detail": str(exc)}

    return {
        "state": _DISPATCH_EXECUTED if approve else _DISPATCH_DECLINED,
        "action_id": action_id,
        "action_status": result.get("status"),
        "blast_radius": result.get("blast_radius"),
    }


async def _notify_realtime(row: AgentApproval, *, event: str) -> None:
    """Fan out an agent event to the realtime service.

    Both the websocket layer (for desktop) and the Web Push layer (for
    mobile) listen on this internal endpoint. We translate the SQL row
    into the existing ``agent.event`` shape so we don't have to teach
    the realtime service a new contract.
    """
    base = settings.REALTIME_BASE_URL.rstrip("/") if settings.REALTIME_BASE_URL else None
    if not base:
        return

    headers: dict[str, str] = {"Accept": "application/json"}
    if settings.REALTIME_INTERNAL_TOKEN:
        # Match the lower-cased header the realtime service checks.
        headers["x-internal-token"] = settings.REALTIME_INTERNAL_TOKEN

    payload: dict[str, Any] = {
        "tenant_id": str(row.tenant_id),
        "run_id": str(row.run_id) if row.run_id else str(row.id),
        "kind": "APPROVAL_REQUEST" if event == "approval_request" else "APPROVAL_DECISION",
        "agent": row.requested_by or "agent",
        "summary": row.title,
        "data": {
            "approval_id": str(row.id),
            "case_id": row.case_id,
            "alert_id": str(row.alert_id) if row.alert_id else None,
            "risk_level": row.risk_level,
            "status": row.status,
            "decision_comment": row.decision_comment,
            "notify_user_ids": ([str(row.required_user_id)] if row.required_user_id else None),
        },
    }

    url = f"{base}/internal/agent-event"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        # The approval has already been persisted; failing to notify is
        # a degraded experience, not a data loss event.
        logger.warning(
            "Failed to fan-out approval event to realtime: %s",
            exc,
            extra={"approval_id": str(row.id), "event": event},
        )
