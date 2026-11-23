"""The console's door to reversing a completed response action.

Every destructive executor captures ``rollback_data`` and its contract names
a ``reverse_capability``, but no production surface could dispatch a
reversal. This route is the missing door, shaped like the forward one: it
authenticates a person, resolves the tenant's stored integration server-side,
and hands the governed decision to ``services/actions``, which grades the
reverse capability's contract and claims the reversal durably before any
vendor is contacted.

**The request carries no credentials, by construction.** The body refuses
unknown fields outright, so there is no key to put a token in — the vault and
the tenant's connector row are the only credential source, which is the same
property the playbook-step dispatch holds and the reason both live behind
this service.

**An undo the grading queues follows the forward approval flow.** It lands in
the approvals inbox as a pending row naming what would be reversed; deciding
it re-drives the reversal with the deciding identity bound as approver, and
the requester cannot approve their own undo.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, require_permission
from app.api.v1.endpoints.approvals import create_undo_approval
from app.db.rls import TenantDBSession
from app.services import action_undo
from app.services.audit import emit_audit

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/actions", tags=["actions"])


class ActionUndoRequest(BaseModel):
    """What a caller may say about an undo: how sure they are, and nothing else.

    ``extra="forbid"`` is the control, not a nicety. The reversal's
    credentials come from the tenant's stored integration through the vault,
    and the vendor comes from the action record itself — a body that could
    carry either would let a caller steer a reversal somewhere it was never
    aimed, so a request naming any other field is refused outright.
    """

    model_config = {"extra": "forbid"}

    #: How good the reason for reversing is, 0..1. An input to the reverse
    #: capability's approval grading, exactly as forward dispatch takes it;
    #: omitted means the lowest band, never a free pass.
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


@router.post("/{action_id}/undo", summary="Reverse a completed response action")
async def undo_action(
    action_id: uuid.UUID,
    body: ActionUndoRequest | None,
    user: Annotated[AuthUser, Depends(require_permission("actions:execute"))],
    db: TenantDBSession,
    request: Request,
) -> dict[str, Any]:
    """Reverse one completed action through its executor's own rollback.

    The reversal is graded against the reverse capability's contract before
    anything runs. The answer is always 200 with a status naming what
    happened — ``rolled_back``, ``undo_failed`` (the vendor refused; the
    action is still in force), ``pending_approval`` (queued in the approvals
    inbox, ``approval_id`` included) or ``refused`` (the contract prohibits
    the reversal). 4xx is reserved for requests that cannot be served at
    all: an action that never executed or was already rolled back (409), a
    verb the platform cannot reverse or a missing integration (422), an
    action this tenant does not own (404).
    """
    principal = {
        "user_id": str(user.user_id),
        "tenant_id": str(user.tenant_id),
        "email": getattr(user, "email", None),
        "roles": [user.role] if user.role else [],
        "permissions": user.effective_permissions(),
    }
    requested_by = f"user:{user.email}" if getattr(user, "email", None) else f"user:{user.user_id}"
    confidence = body.confidence if body else None

    try:
        report = await action_undo.drive_undo(
            db,
            tenant_id=user.tenant_id,
            action_id=str(action_id),
            principal=principal,
            requested_by=requested_by,
            confidence=confidence,
        )
    except action_undo.UndoNotPossible as refusal:
        raise HTTPException(status_code=refusal.status_code, detail=refusal.detail) from refusal

    payload = report.as_dict()
    if report.status == "pending_approval":
        approval = await create_undo_approval(
            db,
            user,
            undo_of=str(action_id),
            action_type=report.action_type,
            target=report.target,
            vendor_id=report.vendor_id,
            confidence=confidence,
            requirement=report.requirement,
            reason=report.reason,
            requested_by=requested_by,
        )
        payload["approval_id"] = str(approval.id)

    await emit_audit(
        db=db,
        tenant_id=user.tenant_id,
        actor_id=user.user_id,
        actor_email=getattr(user, "email", None),
        action="actions:undo",
        resource="action",
        resource_id=str(action_id),
        changes={
            "status": report.status,
            "reversed": report.reversed_,
            "vendor_id": report.vendor_id,
            "action_type": report.action_type,
            "target": report.target,
            "requirement": report.requirement,
            "error": report.error or None,
            "approval_id": payload.get("approval_id"),
        },
        request=request,
    )
    return payload
