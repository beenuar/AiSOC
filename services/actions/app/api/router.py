"""
Action Execution Service REST API.
"""

from __future__ import annotations

import os
import socket
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.models.action import (
    ACTION_BLAST_RADIUS,
    ActionPrincipal,
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    BlastRadius,
    ChatOpsApprover,
)
from app.security.authz import (
    SOD_UNEVALUATED,
    ActionAuthzError,
    authorize_action,
    authorize_approver,
    require_service_auth,
)
from app.security.chatops_identity import resolve_approver
from app.security.chatops_token import ChatOpsTokenError, verify_token
from app.services import action_store
from app.services.action_store import ActionIntentConflict, ActionStoreUnavailable, ClaimOutcome
from app.services.approval_gate import apply_matrix
from app.services.blast_radius import BlastRadiusGate
from app.services.executor_registry import EXECUTOR_REGISTRY
from app.services.timeline_client import TimelineClientError, post_timeline_event
from app.services.verification import PostActionVerifier, VerificationOutcome

logger = structlog.get_logger()
router = APIRouter()
gate = BlastRadiusGate()

#: Which replica claimed an execution. A hostname and a pid: enough for an
#: operator holding a stuck `running` record to find the container that took
#: it, and nothing a caller supplies.
_WORKER_ID = f"{socket.gethostname()}/{os.getpid()}"

#: The header a service-to-service caller declares its tenant on.
#:
#: Read off the raw request rather than declared as a `Header(...)` parameter:
#: one such parameter on a route rewrites the published OpenAPI document with
#: a parameter and a 422 response, and a tenant that services exchange between
#: themselves does not belong in the public contract.
_TENANT_HEADER = "X-Tenant-ID"

#: Below this, an unverifiable failure is recorded as a failure.
#:
#: The rule above it is "unknown until the vendor says so", which is right for
#: anything that changes an estate. Applied to a Slack message or a ticket it
#: would fill the reconciliation queue with items whose duplicate costs
#: nothing — and a queue an operator learns to ignore is not a control. So
#: MINIMAL and LOW keep the executor's own verdict, and MEDIUM upward do not.
_UNKNOWN_OUTCOME_FLOOR: frozenset[BlastRadius] = frozenset({BlastRadius.MEDIUM, BlastRadius.HIGH, BlastRadius.CRITICAL})

# The module-global `_actions` dict that used to live here is gone; storage is
# `app.services.action_store`, which persists to Postgres when a DSN is
# configured. A restart used to lose every action awaiting approval, so an
# analyst tapping Approve on a Slack card got "Action not found" for an
# incident that was still live. Tests reset state with `action_store.clear()`.

# Replay-protection set: action IDs that have already received a response.
# Single-use enforcement is layered on top of HMAC + expiry. Anything more
# durable belongs in Redis once we move off the in-memory action store.
_chatops_replied: set[str] = set()


def _requester_id(request: ActionRequest) -> str | None:
    """Who asked for this action, for separation of duties.

    The explicit originator when the caller supplied one, otherwise the
    invoking principal — which is what this has always recorded, and is still
    right for a caller that submits on its own behalf.

    Never ``request.requested_by``: that is a free-text label a caller picks,
    and a separation-of-duties comparison against it would be forgeable from
    the request body.
    """
    if request.requester is not None:
        return request.requester.user_id
    if request.principal is not None:
        return request.principal.user_id
    return None


async def _verify_effect(request: ActionRequest) -> tuple[VerificationOutcome, dict[str, Any]]:
    """Ask the vendor whether the action's effect is actually present.

    ``PostActionVerifier`` already re-queries the vendor with the same clients
    the forward action uses, and already refuses to invent a ``VERIFIED`` it
    did not earn. It is used here rather than classifying the exception,
    because an exception type answers "did the client raise" and the question
    is "did the estate change" — and for the case that matters, a vendor that
    accepted a containment and then dropped the response, those two answers
    disagree.
    """
    verdict = await PostActionVerifier().verify(request.action_type, request.target, dict(request.parameters or {}))
    return verdict.outcome, {
        "outcome": verdict.outcome.value,
        "reason": verdict.reason,
        "vendor": verdict.vendor,
        "checked_at": datetime.now(UTC).isoformat(),
    }


async def _apply_outcome(
    record: dict[str, Any],
    request: ActionRequest,
    result: ActionResult | None,
    error: str | None,
) -> None:
    """Turn a dispatch into a status the record can be trusted on.

    A clean success is a success. Anything else is unknown until the vendor is
    read back: the executors catch their own vendor errors and return
    ``ActionResult(status=FAILED, error=str(exc))``, so a containment the EDR
    had accepted was recorded as ``failed`` — the reading whose obvious remedy
    is to run it again.
    """
    if result is not None and result.status == ActionStatus.COMPLETED:
        record["status"] = ActionStatus.COMPLETED
        record["output"] = result.output
        record["rollback_data"] = result.rollback_data
        record.pop("error", None)
        return

    reported = error or (result.error if result is not None else None) or "the executor reported no outcome"
    if result is not None and result.output:
        record["output"] = result.output

    blast = ACTION_BLAST_RADIUS.get(request.action_type, BlastRadius.HIGH)
    if blast not in _UNKNOWN_OUTCOME_FLOOR:
        record["status"] = ActionStatus.FAILED
        record["error"] = reported
        return

    outcome, verification = await _verify_effect(request)
    record["verification"] = verification
    if outcome is VerificationOutcome.VERIFIED:
        # The dispatch reported a problem and the effect is in force anyway:
        # the response was lost, not the action.
        record["status"] = ActionStatus.COMPLETED
        record["dispatch_error"] = reported
        record.pop("error", None)
        return
    if outcome is VerificationOutcome.FAILED:
        record["status"] = ActionStatus.FAILED
        record["error"] = reported
        return
    record["status"] = ActionStatus.RECONCILIATION_REQUIRED
    record["error"] = reported


async def _dispatch_claimed(record: dict[str, Any], request: ActionRequest) -> dict[str, Any]:
    """Run an action whose execution this process has already claimed.

    The claim is the durable authorization for the vendor call, so by the time
    control reaches here the record says ``running`` in Postgres and no other
    replica, retry or approval can start the same action. What is left is to
    run it and write down what happened — including when "what happened" is
    that nobody knows.
    """
    executor = EXECUTOR_REGISTRY.get(request.action_type)
    if executor is None:
        record["status"] = ActionStatus.FAILED
        record["error"] = f"No executor found for action type: {request.action_type}"
    else:
        try:
            result = await executor.execute(request)
            await _apply_outcome(record, request, result, None)
        except Exception as exc:  # noqa: BLE001 — never leave a claimed action without an outcome
            # The message is logged in full and never echoed: it can carry
            # internal hostnames and stack detail.
            logger.error("Action execution failed", action_id=str(request.id), error=str(exc), exc_info=True)
            await _apply_outcome(record, request, None, f"execution failed ({type(exc).__name__})")

    dispatch = dict(record.get("dispatch") or {})
    dispatch["state"] = "resolved"
    dispatch["resolved_at"] = datetime.now(UTC).isoformat()
    record["dispatch"] = dispatch

    try:
        await action_store.save(record)
    except ActionIntentConflict:  # pragma: no cover - the intent cannot change under a claim
        logger.error("action_store.outcome_write_refused", action_id=str(request.id))
    return record


@router.post("/actions", response_model=dict)
async def submit_action(request: ActionRequest, _auth: None = Depends(require_service_auth)):
    """Submit an action for execution (may require approval)."""
    # W4.2 — least-privilege: the invoking principal must hold the permission
    # this action's blast radius demands before it is gated or executed.
    try:
        authorize_action(request)
    except ActionAuthzError as exc:
        logger.warning("Action authorization denied", action_type=request.action_type, reason=str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    status, blast_radius, reason = gate.evaluate(request)
    # Second axis: confidence against the action's declared impact, under the
    # tenant's autonomy tier. The matrix that implements this was written,
    # tested, and called by nothing — so the gate the docs described was not
    # the gate that ran. It can only raise a requirement, never lower one.
    status, reason, approval_tier = await apply_matrix(request, status, blast_radius, reason)

    record = {
        "id": str(request.id),
        "action_type": request.action_type,
        "target": request.target,
        "status": status,
        "blast_radius": blast_radius,
        "gate_reason": reason,
        # The tier both gates composed to. Persisted because it is the only
        # record of whether this ran unattended: `status` moves on as the
        # action executes, so a completed row cannot say afterwards whether
        # a human had to approve it.
        "approval_tier": approval_tier,
        "incident_id": str(request.incident_id),
        "tenant_id": str(request.tenant_id),
        "rationale": request.rationale,
        # W4.4 — remember who requested it so an approver can't approve their
        # own action (separation of duties). The originator when the caller
        # distinguishes one, because a relaying service sending its own
        # principal here makes the requester and the approver the same person.
        "requested_by_user_id": _requester_id(request),
        # Kept so approve can rebuild the request faithfully. Without this the
        # approve path reconstructed an ActionRequest with an empty
        # `parameters`, so an action that was gated *because* of what it
        # targets executed against defaults — and reported COMPLETED. An
        # approval that silently changes what it approved is not an approval.
        "parameters": dict(request.parameters or {}),
    }
    try:
        await action_store.save(record)
    except ActionIntentConflict as exc:
        # A second submission of an id that is already awaiting a decision, with
        # a different target or parameters. Refused rather than applied: an
        # approval card showing one host while the record names another is an
        # approval of something nobody read.
        raise HTTPException(
            status_code=409,
            detail=("this action id is already awaiting a decision on a different target or parameters; submit a new action id"),
        ) from exc

    # Auto-execute if approved
    if status == ActionStatus.APPROVED:
        claim = await action_store.claim_for_execution(
            str(request.id),
            tenant_id=str(request.tenant_id),
            expected_status=ActionStatus.APPROVED.value,
            claimed_by=_WORKER_ID,
        )
        if claim.ok and claim.record is not None:
            record = await _dispatch_claimed(claim.record, request)
        elif claim.outcome is ClaimOutcome.STORE_UNAVAILABLE:
            # The gate said this may run unattended and the store cannot record
            # that it did. Refuse: an external effect nobody can prove was
            # authorized is worse than an action an operator can resubmit.
            raise HTTPException(
                status_code=503,
                detail="the action store is unavailable, so execution was not authorized; retry when it is reachable",
            )
        else:
            # Another replica took it, or it is no longer in a state that can
            # run. Report what the store holds rather than executing.
            record = claim.record or record

    logger.info(
        "Action submitted",
        action_id=str(request.id),
        action_type=request.action_type,
        status=record["status"],
        blast_radius=blast_radius,
    )
    return record


def _bind_approver(
    record: dict[str, Any],
    action_id: str,
    approver: ActionPrincipal | None,
    assertion: ChatOpsApprover | None,
    *,
    require: bool,
) -> ActionPrincipal | None:
    """Resolve and authorize the identity behind an approve/reject call.

    Returns the bound principal, or ``None`` when no identity was supplied and
    ``require`` is false. Raises ``HTTPException`` on denial.

    A ChatOps assertion carries identity only — never permissions — because a
    bot that asserted its own permissions could grant itself anything. The
    mapping from a verified platform user to a principal is operator
    configuration; an unmapped user is refused rather than admitted with an
    empty permission set.

    ``require`` is true for approve and false for reject. The asymmetry is
    deliberate: an approval with no identity cannot be evaluated against
    separation of duties, while a rejection causes no vendor effect and has no
    human at all when it comes from the approval-timeout scheduler — requiring
    one would leave expired requests stuck in ``awaiting_approval`` forever.
    """
    approver = _resolve_identity(action_id, approver, assertion, require=require)
    if approver is None:
        return None

    try:
        record["separation_of_duties"] = authorize_approver(record, approver)
    except ActionAuthzError as exc:
        logger.warning("Approval denied", action_id=action_id, reason=str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return approver


def _resolve_identity(
    action_id: str,
    approver: ActionPrincipal | None,
    assertion: ChatOpsApprover | None,
    *,
    require: bool,
) -> ActionPrincipal | None:
    """The identity half of :func:`_bind_approver`, with no record in hand.

    Split out so the route can learn the deciding principal's tenant *before*
    it reads the action, and narrow the read by it. Fetching globally and
    comparing afterwards leaves the lookup itself unscoped, which on a table
    whose row-level policy is inert on this service's connections means the id
    is the only control.
    """
    if approver is None and assertion is not None:
        approver = resolve_approver(assertion.platform, assertion.platform_user_id)
        if approver is None:
            logger.warning(
                "approval_denied_unmapped_identity",
                action_id=action_id,
                platform=assertion.platform,
            )
            detail = f"{assertion.platform} user is not mapped to an AiSOC approver. Add them to AISOC_CHATOPS_APPROVERS."
            raise HTTPException(status_code=403, detail=detail)

    if approver is None:
        settings = get_settings()
        if require and (settings.AISOC_ACTIONS_REQUIRE_APPROVER or settings.AISOC_ACTIONS_REQUIRE_PRINCIPAL):
            raise HTTPException(status_code=403, detail="an approver identity is required")
        return None
    return approver


def _tenant_of(principal: ActionPrincipal | None) -> str | None:
    """The tenant to narrow a read by, or None when the identity carries none.

    A ChatOps approver comes from operator configuration and may legitimately
    have no tenant; the narrowing is then skipped and
    :func:`authorize_approver` is the control. The tenant is never taken from
    the request body.
    """
    if principal is None or principal.tenant_id is None:
        return None
    return str(principal.tenant_id)


async def _load_for_decision(action_id: str, tenant_id: str | None) -> dict[str, Any]:
    """Read the record a decision will act on, from the database.

    ``authoritative`` because the process-local cache is what let an approve
    on the submitting replica resurrect an action another replica had already
    executed, and because a store that is configured and unreachable must not
    be reported as "no such action".
    """
    try:
        record = await action_store.get(action_id, tenant_id=tenant_id, authoritative=True)
    except ActionStoreUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="the action store is unavailable; the decision was not recorded and nothing was executed",
        ) from exc
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    return record


@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: str,
    approver: ActionPrincipal | None = None,
    chatops_approver: ChatOpsApprover | None = None,
    _auth: None = Depends(require_service_auth),
):
    """Approve a pending action (human-in-the-loop gate).

    W4.4 — the approver is bound to the decision: they must hold the action's
    required permission and must not be the requester. T3.6 — an approval with
    no resolvable identity is refused by default
    (``AISOC_ACTIONS_REQUIRE_APPROVER``), because separation of duties cannot
    be evaluated against nobody. ChatOps callers send ``chatops_approver``
    (verified platform identity) and the mapping supplies the permissions.

    Phase 2 — the order below is the control. Identity, then a tenant-narrowed
    authoritative read, then authorization, then an **atomic claim in durable
    storage**, and only then the vendor. This used to be a read, a status
    comparison in Python, the vendor call, and a save afterwards: two replicas
    both read ``awaiting_approval`` and both contained the host, and if the
    process died in between there was no record that either had tried.
    """
    bound = _resolve_identity(action_id, approver, chatops_approver, require=True)
    record = await _load_for_decision(action_id, _tenant_of(bound))

    if bound is not None:
        _bind_approver(record, action_id, bound, None, require=True)
        record["approved_by_user_id"] = bound.user_id
        record["approved_at"] = datetime.now(UTC).isoformat()
    else:
        record["separation_of_duties"] = SOD_UNEVALUATED

    if record["status"] != ActionStatus.AWAITING_APPROVAL:
        raise HTTPException(status_code=400, detail=f"Action is not awaiting approval (current: {record['status']})")

    claim = await action_store.claim_for_execution(
        action_id,
        tenant_id=str(record["tenant_id"]),
        expected_status=ActionStatus.AWAITING_APPROVAL.value,
        claimed_by=_WORKER_ID,
    )
    if not claim.ok:
        raise _claim_refusal(action_id, claim)

    # The claimed record, read back from the store, carries the approval
    # stamps above only if they were written before the claim — they were not,
    # so re-apply them to the authoritative copy rather than to the one this
    # process happened to read.
    claimed = claim.record or record
    claimed["approved_by_user_id"] = record.get("approved_by_user_id")
    claimed["approved_at"] = record.get("approved_at")
    claimed["separation_of_duties"] = record.get("separation_of_duties", SOD_UNEVALUATED)

    # Reconstruct the request as submitted, parameters included. Dropping
    # them turned an approved action into a different action that still
    # reported success.
    request = ActionRequest(
        id=UUID(action_id),
        incident_id=UUID(claimed["incident_id"]),
        tenant_id=UUID(claimed["tenant_id"]),
        action_type=ActionType(claimed["action_type"]),
        target=claimed["target"],
        rationale=claimed.get("rationale") or "",
        parameters=dict(claimed.get("parameters") or {}),
        # The bound approver, not the original requester: the executor's
        # authorization has to evaluate the identity that authorised this run.
        principal=bound,
    )

    record = await _dispatch_claimed(claimed, request)
    logger.info(
        "Action approved and executed",
        action_id=action_id,
        status=record["status"],
        approved_by=bound.user_id if bound else None,
    )
    return record


def _claim_refusal(action_id: str, claim: action_store.Claim) -> HTTPException:
    """The refusal a losing or blocked claimant gets, by reason.

    Three different operator actions hide behind "the claim did not take", so
    they are three different answers: another worker has it (wait), the action
    is in a state no approval can move (reconcile or resubmit), or the store
    cannot be written (retry).
    """
    if claim.outcome is ClaimOutcome.STORE_UNAVAILABLE:
        logger.error("approval_refused_store_unavailable", action_id=action_id)
        return HTTPException(
            status_code=503,
            detail="the action store is unavailable, so execution was not authorized; nothing was sent to the vendor",
        )
    if claim.outcome is ClaimOutcome.NOT_FOUND:
        return HTTPException(status_code=404, detail="Action not found")

    current = claim.current_status or "unknown"
    if current == ActionStatus.RUNNING.value:
        detail = "this action is already being executed by another worker"
    elif current == ActionStatus.RECONCILIATION_REQUIRED.value:
        detail = (
            "this action's outcome is unknown and it will not be run again; "
            f"reconcile it with POST /api/v1/actions/{action_id}/reconcile before deciding anything further"
        )
    else:
        detail = f"Action is not awaiting approval (current: {current})"
    logger.info("approval_refused", action_id=action_id, current_status=current)
    return HTTPException(status_code=409, detail=detail)


@router.post("/actions/{action_id}/reject")
async def reject_action(
    action_id: str,
    approver: ActionPrincipal | None = None,
    chatops_approver: ChatOpsApprover | None = None,
    _auth: None = Depends(require_service_auth),
):
    """Reject a pending action.

    Binds the deciding identity on the same terms as approve. A rejection used
    to take no identity and record none, so "who declined to contain this
    host, and were they entitled to" had no answer — which matters as much as
    the approve side during an incident review.

    A rejection is a state transition like any other, so it is claimed rather
    than written over whatever is there: rejecting an action a worker is in
    the middle of executing would record a decision that did not happen.
    """
    bound = _resolve_identity(action_id, approver, chatops_approver, require=False)
    record = await _load_for_decision(action_id, _tenant_of(bound))

    if bound is not None:
        _bind_approver(record, action_id, bound, None, require=False)
        record["rejected_by_user_id"] = bound.user_id

    if record["status"] == ActionStatus.REJECTED:
        return record

    claim = await action_store.claim_for_execution(
        action_id,
        tenant_id=str(record["tenant_id"]),
        expected_status=ActionStatus.AWAITING_APPROVAL.value,
        claimed_by=_WORKER_ID,
        running_status=ActionStatus.REJECTED.value,
    )
    if not claim.ok:
        raise _claim_refusal(action_id, claim)

    rejected = claim.record or record
    rejected["status"] = ActionStatus.REJECTED
    rejected["rejected_by_user_id"] = record.get("rejected_by_user_id")
    rejected["rejected_at"] = datetime.now(UTC).isoformat()
    try:
        await action_store.save(rejected)
    except ActionIntentConflict:  # pragma: no cover - the intent is unchanged here
        logger.error("action_store.rejection_write_refused", action_id=action_id)
    logger.info(
        "Action rejected",
        action_id=action_id,
        rejected_by=bound.user_id if bound else None,
    )
    return rejected


#: What an unscoped read is allowed to see.
#:
#: A caller that does not declare a tenant still gets a usable status poll,
#: and does not get the host or account the action was aimed at, the
#: parameters it ran with, or the identities around it.
_UNSCOPED_READ_FIELDS: tuple[str, ...] = (
    "id",
    "status",
    "action_type",
    "blast_radius",
    "approval_tier",
    "tenant_id",
)


@router.get("/actions/{action_id}")
async def get_action(action_id: str, request: Request, _auth: None = Depends(require_service_auth)):
    """Get action status and result.

    Behind the service guard: an action record names the host or account an
    action was aimed at and the parameters it ran with, and ``GET`` by id was
    reachable with no credential at all.

    The service token is shared, and ``aisoc_action_records``' row-level
    policy is inert on this service's connections — it reads a GUC nothing
    here sets — so inside the trust boundary an id was still a capability over
    every tenant's response history. A caller that declares its tenant on
    ``X-Tenant-ID`` gets the record when it owns it and a 404 when it does
    not; never a 403, which would make the route an existence oracle over
    every tenant's action ids. A caller that declares none keeps working and
    is answered with status only.
    """
    tenant_id = (request.headers.get(_TENANT_HEADER) or "").strip() or None
    try:
        record = await action_store.get(action_id, tenant_id=tenant_id, authoritative=True)
    except ActionStoreUnavailable as exc:
        raise HTTPException(status_code=503, detail="the action store is unavailable") from exc
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    if tenant_id is None:
        logger.info("action_read_unscoped", action_id=action_id)
        return {key: record.get(key) for key in _UNSCOPED_READ_FIELDS if key in record}
    return record


class ReconcileRequest(BaseModel):
    """Credentials for the read-back, supplied per call.

    Not taken from the stored record alone on purpose: an operator reconciling
    days later should be able to present a current credential rather than
    depend on whatever was captured at submit time.
    """

    parameters: dict[str, Any] = Field(default_factory=dict)


@router.post("/actions/{action_id}/reconcile")
async def reconcile_action(
    action_id: str,
    request: Request,
    body: ReconcileRequest | None = None,
    _auth: None = Depends(require_service_auth),
):
    """Resolve an action whose outcome was never established, by asking the vendor.

    The recovery path for the two states a dispatch can strand in: ``running``,
    where the worker that claimed it died before writing an outcome, and
    ``reconciliation_required``, where it finished and could not tell what had
    happened.

    It never re-executes. The reason those states exist is that the vendor may
    already have acted, and running the action again is the one response that
    turns an unknown into a real duplicate. What it does is the read-back
    probe: present means it completed, absent means it genuinely failed,
    unreadable means it stays unknown and a human has to look.
    """
    tenant_id = (request.headers.get(_TENANT_HEADER) or "").strip() or None
    try:
        record = await action_store.get(action_id, tenant_id=tenant_id, authoritative=True)
    except ActionStoreUnavailable as exc:
        raise HTTPException(status_code=503, detail="the action store is unavailable") from exc
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")

    current = str(getattr(record.get("status"), "value", record.get("status")))
    if current not in (ActionStatus.RUNNING.value, ActionStatus.RECONCILIATION_REQUIRED.value):
        raise HTTPException(
            status_code=409,
            detail=f"only a claimed or unresolved action can be reconciled (current: {current})",
        )

    parameters = {**(record.get("parameters") or {}), **((body.parameters if body else None) or {})}
    probe_request = ActionRequest(
        id=UUID(action_id),
        incident_id=UUID(record["incident_id"]),
        tenant_id=UUID(record["tenant_id"]),
        action_type=ActionType(record["action_type"]),
        target=record["target"],
        rationale=record.get("rationale") or "",
        parameters=parameters,
    )

    outcome, verification = await _verify_effect(probe_request)
    record["verification"] = verification
    record["reconciled_at"] = datetime.now(UTC).isoformat()
    if outcome is VerificationOutcome.VERIFIED:
        record["status"] = ActionStatus.COMPLETED
        record.pop("error", None)
    elif outcome is VerificationOutcome.FAILED:
        record["status"] = ActionStatus.FAILED
        record.setdefault("error", "the effect was not present when the vendor was read back")
    else:
        record["status"] = ActionStatus.RECONCILIATION_REQUIRED

    try:
        await action_store.save(record)
    except ActionIntentConflict:  # pragma: no cover - reconciliation changes no intent
        logger.error("action_store.reconcile_write_refused", action_id=action_id)
    logger.info("action_reconciled", action_id=action_id, status=record["status"], outcome=outcome.value)
    return record


_CHOICE_COPY: dict[str, dict[str, str]] = {
    "acknowledge": {
        "headline": "Thanks — recorded as acknowledged.",
        "body": "We've logged that you confirmed this activity. You can close this tab.",
    },
    "deny": {
        "headline": "Thanks — recorded as denied.",
        "body": (
            "We've flagged this as suspicious. A security analyst will follow up shortly. "
            "If you didn't expect this prompt, please contact your security team."
        ),
    },
    "escalate": {
        "headline": "Thanks — escalated to security.",
        "body": "We've routed this to your security team for review.",
    },
}


def _chatops_response_html(headline: str, body: str, *, ok: bool = True) -> str:
    """Tiny self-contained response page rendered to the user's browser.

    Slack/Teams open the callback URL in a normal browser tab, so we can't
    redirect into the AiSOC console (the user may not have one). A static
    HTML acknowledgement is the smallest UX that confirms the click landed
    without leaking incident details into a URL the user might forward.
    """
    color = "#0a7" if ok else "#a33"
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>AiSOC verification</title>"
        "<style>"
        "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;"
        "background:#0b1220;color:#e6edf3;margin:0;padding:0;display:flex;min-height:100vh;"
        "align-items:center;justify-content:center}"
        ".card{max-width:480px;background:#111827;border:1px solid #1f2937;border-radius:12px;"
        "padding:32px;box-shadow:0 8px 24px rgba(0,0,0,.4)}"
        f".dot{{width:12px;height:12px;border-radius:50%;background:{color};display:inline-block;margin-right:8px}}"
        "h1{margin:0 0 12px 0;font-size:18px;display:flex;align-items:center}"
        "p{margin:0;color:#9ca3af;line-height:1.5}"
        "</style></head><body>"
        f'<div class="card"><h1><span class="dot"></span>{headline}</h1><p>{body}</p></div>'
        "</body></html>"
    )


@router.get("/chatops/callback", response_class=HTMLResponse)
async def chatops_callback(token: str = Query(..., min_length=8)):
    """Receive a user's response to a ChatOps verification prompt.

    The token is the HMAC-signed payload minted by
    :class:`app.executors.chatops.ChatOpsVerifyExecutor`. We re-verify
    the signature + expiry, dedupe against ``_chatops_replied``, write a
    ``chatops.verify.responded`` event onto the case timeline, and update
    the in-memory action record so ``GET /actions/{id}`` reflects the
    final status.

    Returns an HTML acknowledgement page so the click lands cleanly in
    Slack/Teams' default browser tab.
    """
    settings = get_settings()
    secret = settings.AISOC_CHATOPS_RESPONSE_SECRET

    try:
        claims = verify_token(token, secret)
    except ChatOpsTokenError as exc:
        reason = str(exc)
        logger.info("ChatOps callback rejected", reason=reason)
        message = {
            "expired": ("This verification link has expired. If you still need to respond, contact your security team."),
            "invalid_signature": "This verification link is invalid.",
        }.get(reason, "This verification link is invalid.")
        return HTMLResponse(
            content=_chatops_response_html("Couldn't record your response", message, ok=False),
            status_code=400,
        )

    action_id_str = str(claims.action_id)
    if action_id_str in _chatops_replied:
        return HTMLResponse(
            content=_chatops_response_html(
                "Response already recorded",
                "We've already logged a response for this prompt. No further action is needed.",
            ),
            status_code=200,
        )

    record = await action_store.get(action_id_str)
    # We still record on the timeline even if the record is gone entirely
    # (no database configured, and this replica did not handle the submit).
    # The case timeline is durable either way — losing the local record
    # must not lose the user's reply.

    timeline_warning: str | None = None
    try:
        await post_timeline_event(
            case_id=claims.case_id,
            event_type="chatops.verify.responded",
            content=(f"User {claims.user_ref or 'unknown'} responded '{claims.choice}' to the ChatOps verification prompt."),
            metadata={
                "action_id": action_id_str,
                "tenant_id": str(claims.tenant_id),
                "choice": claims.choice,
                "user_ref": claims.user_ref,
                "issued_at": claims.issued_at,
                "responded_at": int(datetime.now(UTC).timestamp()),
            },
        )
    except TimelineClientError as exc:
        timeline_warning = str(exc)
        logger.warning(
            "ChatOps response timeline write failed",
            action_id=action_id_str,
            case_id=str(claims.case_id),
            error=timeline_warning,
        )

    _chatops_replied.add(action_id_str)

    if record is not None:
        record["status"] = ActionStatus.COMPLETED
        record.setdefault("output", {})
        record["output"].update(
            {
                "user_choice": claims.choice,
                "user_ref": claims.user_ref,
                "responded_at": datetime.now(UTC).isoformat(),
            }
        )
        if timeline_warning:
            record["output"]["timeline_warning"] = timeline_warning

    logger.info(
        "ChatOps response recorded",
        action_id=action_id_str,
        case_id=str(claims.case_id),
        choice=claims.choice,
    )

    copy = _CHOICE_COPY.get(claims.choice, _CHOICE_COPY["acknowledge"])
    return HTMLResponse(
        content=_chatops_response_html(copy["headline"], copy["body"]),
        status_code=200,
    )


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-actions"}
